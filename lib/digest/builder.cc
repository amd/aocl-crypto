/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "capi/digest/builder.hh"
#include "capi/digest/ctx.hh"

#include "digest.hh"

namespace alcp::digest {

using Context = alcp::digest::Context;

template<typename DIGESTTYPE>
static alc_error_t
__sha_update_wrapper(void* pDigest, const uint8_t* pSrc, uint64_t len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<DIGESTTYPE*>(pDigest);
    e       = ap->update(pSrc, len);

    return e;
}

template<typename DIGESTTYPE>
static alc_error_t
__sha_finalize_wrapper(void* pDigest, const uint8_t* pBuf, uint64_t len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<DIGESTTYPE*>(pDigest);
    e       = ap->finalize(pBuf, len);

    return e;
}

template<typename DIGESTTYPE>
static alc_error_t
__sha_copy_wrapper(const void* pDigest, uint8_t* pBuf, uint64_t len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<const DIGESTTYPE*>(pDigest);
    e       = ap->copyHash(pBuf, len);

    return e;
}

#if 0
template<typename DIGESTTYPE,
         alc_error_t (DIGESTTYPE::*func)(void*, const uint8_t*, uint64_t)>
static alc_error_t
__digest_func_wrapper(void* pDigest, const uint8_t* pBuf, uint64_t len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<DIGESTTYPE*>(pDigest);
    e       = ap->func(pBuf, len);

    return e;
}
#endif

template<typename DIGESTTYPE>
static alc_error_t
__sha_dtor(const void* pDigest)
{
    alc_error_t e  = ALC_ERROR_NONE;
    auto        ap = static_cast<const DIGESTTYPE*>(pDigest);
    delete ap;
    return e;
}

template<typename ALGONAME>
static alc_error_t
__build_sha(const alc_digest_info_t& sha2Info, Context& ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    /* if (!Sha256::isSupported(sha2Info)) */
    /*     err = ALC_ERROR_NOT_SUPPORTED; */

    if (!Error::isError(err)) {
        auto algo    = new ALGONAME(sha2Info);
        ctx.m_digest = static_cast<void*>(algo);
        ctx.update   = __sha_update_wrapper<ALGONAME>;
        ctx.copy     = __sha_copy_wrapper<ALGONAME>;
        ctx.finalize = __sha_finalize_wrapper<ALGONAME>;
        //   ctx.finalize = __digest_func_wrapper<ALGONAME,
        //   &ALGONAME::finalize>;
        ctx.finish = __sha_dtor<ALGONAME>;
    }

    return err;
}

class Sha2Builder
{
  public:
    static alc_error_t Build(const alc_digest_info_t& rDigestInfo,
                             Context&                 rCtx)
    {
        alc_error_t err = ALC_ERROR_NONE;

        switch (rDigestInfo.dt_len) {
            case ALC_DIGEST_LEN_256:
                __build_sha<Sha256>(rDigestInfo, rCtx);
                break;

            default:
                Error::setGeneric(err, ALC_ERROR_NOT_SUPPORTED);
                break;
        }

        return err;
    }
};

alc_error_t
DigestBuilder::Build(const alc_digest_info_t& rDigestInfo, Context& rCtx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (rDigestInfo.dt_type) {
        case ALC_DIGEST_TYPE_SHA2:
            err = Sha2Builder::Build(rDigestInfo, rCtx);
            break;

        default:
            Error::setGeneric(err, ALC_ERROR_NOT_SUPPORTED);
            break;
    }

    return err;
}

} // namespace alcp::digest
