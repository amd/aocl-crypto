/*
 * Copyright (C) 2026, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Allocation-failure tests for the RSA C API.
 */

#include <vector>

#include <gtest/gtest.h>

#include "alcp/rsa.h"

#include "oom_inject.hh"
#include "rsa/rsa_keys.hh"

namespace {

using alcp::testing::oom::MaxProbes;
using alcp::testing::oom::probe_request;
using alcp::testing::oom::under_oom;

constexpr Uint64 Sha256Len = 32;

// A handle whose context lives for as long as the test needs it.
class Session
{
  public:
    Session()
        : m_context(alcp_rsa_context_size())
    {
        m_handle.context = static_cast<alc_rsa_context_p>(m_context.data());
    }

    ~Session() { alcp_rsa_finish(&m_handle); }

    alc_rsa_handle_p get() { return &m_handle; }

    alc_error_t withKeys()
    {
        alc_error_t err = alcp_rsa_set_publickey(&m_handle,
                                                 pub_key_exp,
                                                 PubKey_Modulus_1024,
                                                 sizeof(PubKey_Modulus_1024));
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        return alcp_rsa_set_privatekey(&m_handle,
                                       PvtKey_DP_EXP_1024,
                                       PvtKey_DQ_EXP_1024,
                                       PvtKey_P_Modulus_1024,
                                       PvtKey_Q_Modulus_1024,
                                       PvtKey_Q_ModulusINV_1024,
                                       PvtKey_Modulus_1024,
                                       sizeof(PvtKey_P_Modulus_1024));
    }

  private:
    std::vector<Uint8> m_context;
    alc_rsa_handle_t   m_handle{};
};

// Signs and verifies one message, which is what exercises the digest and the
// mask generation function the session currently holds.
alc_error_t
signAndVerifyPss(Session& session)
{
    Uint8       text[] = { 'm', 'e', 's', 's', 'a', 'g', 'e' };
    Uint8       salt[Sha256Len]{ 0x01 };
    Uint8       signature[sizeof(PubKey_Modulus_1024)]{};
    alc_error_t err = alcp_rsa_privatekey_sign_pss(
        session.get(), true, text, sizeof(text), salt, sizeof(salt), signature);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    return alcp_rsa_publickey_verify_pss(
        session.get(), text, sizeof(text), signature, sizeof(signature));
}

TEST(RsaOom, RequestReportsFailure)
{
    alc_rsa_handle_t handle{};
    probe_request(
        alcp_rsa_context_size(),
        [&](void* context) {
            handle.context = static_cast<alc_rsa_context_p>(context);
            return alcp_rsa_request(&handle);
        },
        [&](void*) { alcp_rsa_finish(&handle); });
}

// The digest of the new mode is the first allocation of these calls, and it
// used to be attempted only after the old digest had been freed, so a failure
// left the context holding a pointer its finish would free a second time.
TEST(RsaOom, AFailedFetchLeavesTheOldDigestInPlace)
{
    for (bool mgf : { false, true }) {
        SCOPED_TRACE(mgf ? "add_mgf" : "add_digest");
        Session session;
        ASSERT_EQ(alcp_rsa_request(session.get()), ALC_ERROR_NONE);
        ASSERT_EQ(session.withKeys(), ALC_ERROR_NONE);
        ASSERT_EQ(alcp_rsa_add_digest(session.get(), ALC_SHA2_256),
                  ALC_ERROR_NONE);
        ASSERT_EQ(alcp_rsa_add_mgf(session.get(), ALC_SHA2_256),
                  ALC_ERROR_NONE);

        auto out = under_oom(0, [&] {
            return mgf ? alcp_rsa_add_mgf(session.get(), ALC_SHA2_384)
                       : alcp_rsa_add_digest(session.get(), ALC_SHA2_384);
        });

        ASSERT_TRUE(out.fired) << "nothing was allocated, nothing tested";
        ASSERT_FALSE(out.threw) << "an exception escaped the entry point";
        EXPECT_EQ(out.err, ALC_ERROR_NO_MEMORY);

        // the digest that was already there has to still be usable, and the
        // session's finish must not free it twice
        EXPECT_EQ(signAndVerifyPss(session), ALC_ERROR_NONE);
    }
}

// A copy that fails must not leave the destination holding the source's
// objects, because the caller then finishes both and frees them twice.
TEST(RsaOom, ContextCopyDoesNotAliasTheSource)
{
    bool failure_reported = false;
    long nth              = 0;

    for (; nth < MaxProbes; nth++) {
        SCOPED_TRACE(nth);
        Session src;
        Session dest;
        ASSERT_EQ(alcp_rsa_request(src.get()), ALC_ERROR_NONE);
        ASSERT_EQ(src.withKeys(), ALC_ERROR_NONE);
        ASSERT_EQ(alcp_rsa_add_digest(src.get(), ALC_SHA2_256), ALC_ERROR_NONE);
        ASSERT_EQ(alcp_rsa_add_mgf(src.get(), ALC_SHA2_256), ALC_ERROR_NONE);

        auto out = under_oom(
            nth, [&] { return alcp_rsa_context_copy(src.get(), dest.get()); });

        // Both sessions are finished when they go out of scope, so an alias
        // here is a second free of the same object.
        ASSERT_FALSE(out.threw) << "an exception escaped alcp_rsa_context_copy";
        if (out.err != ALC_ERROR_NONE) {
            failure_reported = true;
            EXPECT_EQ(out.err, ALC_ERROR_NO_MEMORY);
        }
        if (!out.fired) {
            break;
        }
    }

    EXPECT_LT(nth, MaxProbes) << "the sweep ran out of probes";
    EXPECT_TRUE(failure_reported) << "no failure was reported, nothing tested";
}

} // namespace
