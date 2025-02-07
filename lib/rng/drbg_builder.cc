/*
 * Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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
#include "alcp/utils/cpuid.hh"
#include "hardware_rng.hh"
#include "system_rng.hh"
namespace alcp::drbg {
class CustomRng : public IRng
{

  private:
    std::vector<Uint8> m_entropy;
    std::vector<Uint8> m_nonce;

    Uint64 m_call_count = {};

  public:
    CustomRng() = default;

    alc_error_t readRandom(Uint8* pBuf, Uint64 size) override
    {
        return ALC_ERROR_NONE;
    }

    alc_error_t randomize(Uint8 output[], size_t length) override
    {
        alc_error_t err = ALC_ERROR_NONE;
        if (m_call_count == 0) {
            utils::CopyBytes(output, &m_entropy[0], length);
            m_call_count++;
        } else if (m_call_count == 1) {
            utils::CopyBytes(output, &m_nonce[0], length);
            m_call_count++;
        } else {
            printf("Not Allowed\n");
        }

        return err;
    }

    std::string name() const override { return "Dummy DRBG"; }

    bool isSeeded() const override { return true; }

    size_t reseed() override { return 0; }

    alc_error_t setPredictionResistance(bool value) override
    {
        return ALC_ERROR_NONE;
    }

    void setEntropy(std::vector<Uint8> entropy)
    {
        m_entropy = std::move(entropy);
    }
    void setNonce(std::vector<Uint8> nonce) { m_nonce = std::move(nonce); }

    void reset()
    {
        m_call_count = 0;
        m_entropy.clear();
        m_nonce.clear();
    }
};

static alc_error_t
__drbg_wrapperinitialize(void*        m_drbg,
                         int          cSecurityStrength,
                         const Uint8* buff,
                         Uint64       size)
{
    std::vector<Uint8> temp_personalization_string;
    temp_personalization_string.reserve(1);
    if (buff != nullptr && size != 0) {
        temp_personalization_string = std::vector<Uint8>(buff, buff + size);
    }
    alcp::rng::Drbg* p_drbg = static_cast<alcp::rng::Drbg*>(m_drbg);
    return p_drbg->initialize(cSecurityStrength, temp_personalization_string);
}

static alc_error_t
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

static void
__drbg_wrapperFinish(void* m_drbg)
{

    alcp::rng::IDrbg* p_drbg = static_cast<alcp::rng::IDrbg*>(m_drbg);
    p_drbg->~IDrbg();
}

alc_error_t
DrbgBuilder::build(const alc_drbg_info_t& drbgInfo, Context& ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    const alc_rng_source_info_t* rng_source_info =
        &(drbgInfo.di_rng_sourceinfo);
    std::shared_ptr<IRng> irng;
    if (rng_source_info->custom_rng == false) {
        switch (rng_source_info->di_sourceinfo.rng_info.ri_source) {
            case ALC_RNG_SOURCE_OS: {
                irng = std::make_shared<alcp::rng::SystemRng>();
                break;
            }
            case ALC_RNG_SOURCE_ARCH: {
                if (alcp::utils::CpuId::cpuHasRdRand()) {
                    irng = std::make_shared<alcp::rng::HardwareRng>();
                } else {
                    return ALC_ERROR_NOT_SUPPORTED;
                }
                break;
            }
            default:
                // RNG type specified is unknown
                return ALC_ERROR_NOT_PERMITTED;
                break;
        }

    } else {
        auto* entropy = rng_source_info->di_sourceinfo.custom_rng_info.entropy;
        if (entropy == nullptr) {
            // Entropy cant be null
            return ALC_ERROR_INVALID_ARG;
        }
        auto entropylen =
            rng_source_info->di_sourceinfo.custom_rng_info.entropylen;

        auto nonce    = rng_source_info->di_sourceinfo.custom_rng_info.nonce;
        auto noncelen = rng_source_info->di_sourceinfo.custom_rng_info.noncelen;

        auto entropy_vect = std::vector<Uint8>(entropy, entropy + entropylen);
        auto nonce_vect   = std::vector<Uint8>(nonce, nonce + noncelen);

        if (noncelen != drbgInfo.max_nonce_len
            && entropylen != drbgInfo.max_entropy_len) {
            // For Testing Purposes Max Entropy,Nonce Length should match given
            // Entropy,Nonce Lengths
            return ALC_ERROR_INVALID_ARG;
        }

        auto customRng = std::make_shared<alcp::drbg::CustomRng>();
        customRng->setEntropy(std::move(entropy_vect));
        customRng->setNonce(std::move(nonce_vect));
        irng = customRng;
    }

    switch (drbgInfo.di_type) {
        case ALC_DRBG_HMAC:
            err = HmacDrbgBuilder::build(drbgInfo, ctx);
            break;
        case ALC_DRBG_CTR:
            err = CtrDrbgBuilder::build(drbgInfo, ctx);
            break;
        default:
            // Unknown MAC Type
            err = ALC_ERROR_INVALID_ARG;
            break;
    }
    if (alcp_is_error(err)) {
        return err;
    }

    alcp::rng::IDrbg* p_drbg = static_cast<alcp::rng::Drbg*>(ctx.m_drbg);

    err = p_drbg->setRng(std::move(irng));
    if (alcp_is_error(err)) {
        return err;
    }

    p_drbg->setEntropyLen(drbgInfo.max_entropy_len);
    p_drbg->setNonceLen(drbgInfo.max_nonce_len);

    ctx.initialize = __drbg_wrapperinitialize;
    ctx.randomize  = __drbg_wrapperrandomize;
    ctx.finish     = __drbg_wrapperFinish;

    return ALC_ERROR_NONE;
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

// ToDO: Check if the isSupported is required
alc_error_t
DrbgBuilder::isSupported(const alc_drbg_info_t& drbgInfo)
{
    alc_error_t err{ ALC_ERROR_NONE };
    if (drbgInfo.di_rng_sourceinfo.custom_rng == false) {
        err = alcp::rng::RngBuilder::isSupported(
            drbgInfo.di_rng_sourceinfo.di_sourceinfo.rng_info);
        if (alcp_is_error(err)) {
            return err;
        }
    }
    switch (drbgInfo.di_type) {
        case ALC_DRBG_CTR:
            return CtrDrbgBuilder::isSupported(drbgInfo);
            break;
        case ALC_DRBG_HMAC:
            return err;
            break;
    }
    return err;
}

} // namespace alcp::drbg