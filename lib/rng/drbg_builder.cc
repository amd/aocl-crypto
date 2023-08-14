/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"
#include "alcp/capi/drbg/builder.hh"
#include "alcp/capi/rng/builder.hh"
#include "alcp/interface/Irng.hh"
#include "alcp/rng/ctrdrbg_build.hh"
#include "alcp/rng/hmacdrbg_build.hh"
#include "hardware_rng.hh"
#include "system_rng.hh"

namespace alcp::drbg {
class CustomRng : public IRng
{

  private:
    std::vector<Uint8> m_entropy;
    std::vector<Uint8> m_nonce;

    Uint64 m_call_count;

  public:
    CustomRng() = default;

    Status readRandom(Uint8* pBuf, Uint64 size) override { return StatusOk(); }

    Status randomize(Uint8 output[], size_t length) override
    {
        Status s = StatusOk();
        if (m_call_count == 0) {
            utils::CopyBytes(output, &m_entropy[0], length);
            m_call_count++;
        } else if (m_call_count == 1) {
            utils::CopyBytes(output, &m_nonce[0], length);
            m_call_count++;
        } else {
            printf("Not Allowed\n");
        }

        return s;
    }

    std::string name() const override { return "Dummy DRBG"; }

    bool isSeeded() const override { return true; }

    size_t reseed() override { return 0; }

    Status setPredictionResistance(bool value) override
    {
        Status s = StatusOk();
        return s;
    }

    void setEntropy(std::vector<Uint8> entropy) { m_entropy = entropy; }
    void setNonce(std::vector<Uint8> nonce) { m_nonce = nonce; }

    void reset()
    {
        m_call_count = 0;
        m_entropy.clear();
        m_nonce.clear();
    }
};

static Status
__drbg_wrapperinitialize(void*        m_drbg,
                         int          cSecurityStrength,
                         const Uint8* buff,
                         Uint64       size)
{
    std::vector<Uint8> temp_personalization_string;
    if (buff != nullptr && size != 0) {
        temp_personalization_string = std::vector<Uint8>(buff, buff + size);
    }
    alcp::rng::Drbg* p_drbg = static_cast<alcp::rng::Drbg*>(m_drbg);
    return p_drbg->initialize(cSecurityStrength, temp_personalization_string);
}

static Status
__drbg_wrapperrandomize(void*        m_drbg,
                        Uint8        p_Output[],
                        const size_t cOutputLength,
                        int          cSecurityStrength,
                        const Uint8  cAdditionalInput[],
                        const size_t cAdditionalInputLength)
{
    alcp::rng::Drbg* p_drbg = static_cast<alcp::rng::Drbg*>(m_drbg);
    return p_drbg->randomize(p_Output,
                             cOutputLength,
                             cSecurityStrength,
                             cAdditionalInput,
                             cAdditionalInputLength);
}

static Status
__drbg_wrapperFinish(void* m_drbg)
{
    Status status = StatusOk();

    alcp::rng::IDrbg* p_drbg = static_cast<alcp::rng::IDrbg*>(m_drbg);
    p_drbg->~IDrbg();

    return status;
}

Status
DrbgBuilder::build(const alc_drbg_info_t& drbgInfo, Context& ctx)
{
    using namespace status;
    Status status = StatusOk();
    switch (drbgInfo.di_type) {
        case ALC_DRBG_HMAC:
            status = HmacDrbgBuilder::build(drbgInfo, ctx);
            break;
        case ALC_DRBG_CTR:
            status = CtrDrbgBuilder::build(drbgInfo, ctx);
            if (!status.ok()) {
                return status;
            }
            break;
        default:
            status.update(InvalidArgument("Unknown MAC Type"));
            break;
    }
    const alc_rngsource_info_t* rng_source_info = &(drbgInfo.di_rng_sourceinfo);
    alcp::rng::IDrbg* p_drbg = static_cast<alcp::rng::Drbg*>(ctx.m_drbg);
    if (rng_source_info->custom_rng == false) {
        std::shared_ptr<IRng> irng;
        switch (rng_source_info->di_sourceinfo.rng_info.ri_source) {
            case ALC_RNG_SOURCE_OS: {
                irng = std::make_shared<alcp::rng::SystemRng>();
                break;
            }
            case ALC_RNG_SOURCE_ARCH: {
                irng = std::make_shared<alcp::rng::HardwareRng>();
                break;
            }
            default:
                status.update(alcp::rng::status::NotPermitted(
                    "RNG type specified is unknown"));
                break;
        }
        status = p_drbg->setRng(irng);
        if (!status.ok()) {
            return status;
        }
    } else {
        auto* entropy = rng_source_info->di_sourceinfo.custom_rng_info.entropy;
        auto  entropylen =
            rng_source_info->di_sourceinfo.custom_rng_info.entropylen;

        auto nonce    = rng_source_info->di_sourceinfo.custom_rng_info.nonce;
        auto noncelen = rng_source_info->di_sourceinfo.custom_rng_info.noncelen;

        auto entropy_vect = std::vector<Uint8>(entropy, entropy + entropylen);
        auto nonce_vect   = std::vector<Uint8>(nonce, nonce + noncelen);

        if (noncelen != drbgInfo.max_nonce_len
            && entropylen != drbgInfo.max_entropy_len) {
            return InternalError(
                "For Testing Purposes Max Entropy,Nonce Length should match "
                "given Entropy,Nonce Lengths");
        }

        auto custom_rng = std::make_shared<alcp::drbg::CustomRng>();
        custom_rng->setEntropy(entropy_vect);
        custom_rng->setNonce(nonce_vect);

        status = p_drbg->setRng(custom_rng);
        if (!status.ok()) {
            return status;
        }
    }

    p_drbg->setEntropyLen(drbgInfo.max_entropy_len);
    p_drbg->setNonceLen(drbgInfo.max_nonce_len);

    ctx.initialize = __drbg_wrapperinitialize;
    ctx.randomize  = __drbg_wrapperrandomize;
    ctx.finish     = __drbg_wrapperFinish;

    return StatusOk();
}

Uint64
DrbgBuilder::getSize(const alc_drbg_info_t& drbgInfo)
{
    Uint64 size = 0;
    switch (drbgInfo.di_type) {
        case ALC_DRBG_HMAC:
            size = sizeof(alcp::rng::drbg::HmacDrbg);
            break;
        case ALC_DRBG_CTR:
            size = sizeof(alcp::rng::drbg::CtrDrbg);
            break;
        default:
            size = 0;
    }
    return size;
}

Status
DrbgBuilder::isSupported(const alc_drbg_info_t& drbgInfo)
{
    Status s{ StatusOk() };
    s = alcp::rng::RngBuilder::isSupported(
        drbgInfo.di_rng_sourceinfo.di_sourceinfo.rng_info);
    if (!s.ok()) {
        return s;
    }
    switch (drbgInfo.di_type) {
        case ALC_DRBG_CTR:
            return CtrDrbgBuilder::isSupported(drbgInfo);
            break;
        case ALC_DRBG_HMAC:
            return HmacDrbgBuilder::isSupported(drbgInfo);
            break;
    }
    return s;
}

} // namespace alcp::drbg