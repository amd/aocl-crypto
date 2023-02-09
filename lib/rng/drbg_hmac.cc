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

#include "rng/drbg_hmac.hh"
#include "iostream"
#include "utils/copy.hh"

namespace alcp::rng::drbg {

using alcp::digest::Digest;
using alcp::digest::Sha256;
using alcp::mac::Hmac;

/**
 * @brief Print Value in a vector given vector, file and line where its
 * called and message.
 *
 * @param in      - Vector to be print
 * @param message - Debug message to print
 * @param file    - Which file called this
 * @param line    - Which line in source code is this
 */
#ifdef DEBUG_MODE
void
DebugPrint(const std::vector<Uint8>& in,
           std::string               message,
           std::string               file,
           int                       line)
{
    std::cout << "Debug Location " << file << ":" << line << std::endl;
    std::cout << message << "=" << std::endl;
    BIO_dump_fp(stdout, &in[0], in.size());
    std::cout << std::endl;
}
#else
void
DebugPrint(const std::vector<Uint8>& in,
           std::string               message,
           std::string               file,
           int                       line)
{}
#endif

void
HmacDrbg::IHmacDrbg::concat(concat_type_t<Uint8>& in, std::vector<Uint8>& out)
{
    int   pos   = 0;
    auto* p_out = &out[0];
    for (Uint64 i = 0; i < in.size(); i++) {
        auto current = *(in.at(i));
        utils::CopyBytes(p_out + pos, &(current[0]), current.size());
        pos += current.size();
    }
}

void
HmacDrbg::IHmacDrbg::HMAC_Wrapper(const Uint8* cIn1,
                                  const Uint64 cIn1Len,
                                  const Uint8* in2,
                                  const Uint64 cIn2Len,
                                  const Uint8* in3,
                                  const Uint64 cIn3Len,
                                  Uint8*       out,
                                  const Uint64 cOutLen)
{
    alc_digest_info_t hmac_digest = {
        ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_256, {}, ALC_SHA2_256, {}
    };
    alc_hmac_info_t hmac_info = { hmac_digest };
    alc_key_info_t  key_info  = { ALC_KEY_TYPE_SYMMETRIC,
                                ALC_KEY_FMT_RAW,
                                ALC_KEY_ALG_MAC,
                                {},
                                static_cast<Uint32>(m_key.size()),
                                &m_key[0] };
    alc_mac_info_t  mac_info  = { ALC_MAC_HMAC, hmac_info, key_info };
    // FIXME: Static is not a good idea, just doing for easy optimal
    // implementation
    Hmac hmac_obj = Hmac(mac_info, m_digest.get());
    hmac_obj.update(cIn1, cIn1Len);
    if (in2 != nullptr && cIn2Len != 0)
        hmac_obj.update(in2, cIn2Len);
    if (in3 != nullptr && cIn3Len != 0)
        hmac_obj.update(in3, cIn3Len);
    hmac_obj.finalize(nullptr, 0);

    // Assert that we have enough memory to write the output into
    assert(cOutLen >= m_digest->getHashSize());

    hmac_obj.copyHash(out, m_digest->getHashSize());

    // FIXME: Might need a hard reset in hmac_obj
    // hmac_obj.reset();
    m_digest->reset();
}

void
HmacDrbg::IHmacDrbg::HMAC_Wrapper(const Uint8* cIn,
                                  const Uint64 cInLen,
                                  const Uint8* cIn1,
                                  const Uint64 cIn1Len,
                                  Uint8*       out,
                                  const Uint64 cOutLen)
{
    HmacDrbg::IHmacDrbg::HMAC_Wrapper(cIn,
                                      cInLen,
                                      cIn1,
                                      cIn1Len,
                                      nullptr,
                                      static_cast<Uint64>(0),
                                      out,
                                      cOutLen);
}

void
HmacDrbg::IHmacDrbg::HMAC_Wrapper(const Uint8* cIn,
                                  const Uint64 cInLen,
                                  Uint8*       out,
                                  const Uint64 cOutLen)
{
    HmacDrbg::IHmacDrbg::HMAC_Wrapper(cIn,
                                      cInLen,
                                      nullptr,
                                      static_cast<Uint64>(0),
                                      nullptr,
                                      static_cast<Uint64>(0),
                                      out,
                                      cOutLen);
}

void
HmacDrbg::IHmacDrbg::HMAC_Wrapper(const std::vector<Uint8>& cIn,
                                  std::vector<Uint8>&       out)
{
    // Call the real implementation
    HMAC_Wrapper(&cIn[0], cIn.size(), &out[0], out.size());
}

/*
    NIST SP 800-90A Rev 1 Page 44
    Section 10.1.2.2
*/
void
HmacDrbg::IHmacDrbg::Update(const Uint8* p_provided_data,
                            const Uint64 cProvidedDataLen)
{
    const std::vector<Uint8> cZeroVect = std::vector<Uint8>{ 0x00 };
    const std::vector<Uint8> cOneVect  = std::vector<Uint8>{ 0x01 };

    HMAC_Wrapper(&m_v[0],
                 m_v.size(),
                 &cZeroVect[0],
                 cZeroVect.size(),
                 p_provided_data,
                 cProvidedDataLen,
                 &m_key[0],
                 m_key.size());

    DebugPrint(m_key, "Update K", __FILE__, __LINE__);

    // V = HMAC(K,V)
    HMAC_Wrapper(m_v, m_v);

    DebugPrint(m_v, "Update V", __FILE__, __LINE__);

    if (cProvidedDataLen == 0) {
        return;
    }

    // K = HMAC(K,V || 0x01 || provided_data)
    HMAC_Wrapper(&m_v[0],
                 m_v.size(),
                 &cOneVect[0],
                 cOneVect.size(),
                 p_provided_data,
                 cProvidedDataLen,
                 &m_key[0],
                 m_key.size());

    // V = HMAC(K,V)
    HMAC_Wrapper(m_v, m_v);
}

void
HmacDrbg::IHmacDrbg::Update(const std::vector<Uint8>& p_provided_data)
{
    Update(&p_provided_data[0], p_provided_data.size());
}

/*
    NIST SP 800-90A Rev 1 Page 45
    Section 10.1.2.3
*/
void
HmacDrbg::IHmacDrbg::instantiate(const Uint8* cEntropyInput,
                                 const Uint64 cEntropyInputLen,
                                 const Uint8* cNonce,
                                 const Uint64 cNonceLen,
                                 const Uint8* cPersonalizationString,
                                 const Uint64 cPersonalizationStringLen)
{
    std::vector<Uint8> seed_material(cEntropyInputLen + cNonceLen
                                     + cPersonalizationStringLen);

    Uint8* p_seed_material_buff = &seed_material[0];

    // Copy can't be avoided
    utils::CopyBytes(p_seed_material_buff, cEntropyInput, cEntropyInputLen);
    utils::CopyBytes(
        p_seed_material_buff + cEntropyInputLen, cNonce, cNonceLen);
    utils::CopyBytes(p_seed_material_buff + cEntropyInputLen + cNonceLen,
                     cPersonalizationString,
                     cPersonalizationStringLen);
    // concat(concatVect, seed_material);

    // Initialize key with 0x00
    std::fill(m_key.begin(), m_key.end(), 0);
    // Initialize v with 0x01
    std::fill(m_v.begin(), m_v.end(), 1);

    DebugPrint(m_key, "K", __FILE__, __LINE__);
    DebugPrint(m_v, "V", __FILE__, __LINE__);

    // (Key,V) = HMAC_DRBG_Update(seed_material,Key,V)
    Update(p_seed_material_buff, seed_material.size());

    DebugPrint(m_key, "K", __FILE__, __LINE__);
    DebugPrint(m_v, "V", __FILE__, __LINE__);

    // FIXME: Currently no reseed counter is there
    // reseed_counter = 1
}

void
HmacDrbg::IHmacDrbg::instantiate(
    const std::vector<Uint8>& cEntropyInput,
    const std::vector<Uint8>& cNonce,
    const std::vector<Uint8>& cPersonalizationString)
{
    instantiate(&cEntropyInput[0],
                cEntropyInput.size(),
                &cNonce[0],
                cNonce.size(),
                &cPersonalizationString[0],
                cPersonalizationString.size());
}

/*
    NIST SP 800-90A Rev 1 Page 46
    Section 10.1.2.5
*/
void
HmacDrbg::IHmacDrbg::generate(const Uint8* cAdditionalInput,
                              const Uint64 cAdditionalInputLen,
                              Uint8*       output,
                              const Uint64 cOutputLen)
{
    // FIXME: Implement below
    // if (reseed_counter > reseed_interval) {
    //     return reseed_required
    // }
    if (cAdditionalInputLen != 0) {
        Update(cAdditionalInput, cAdditionalInputLen);
    }

    // Treating size of m_v as digest size;
    Uint64 blocks = cOutputLen / m_v.size();

    for (Uint64 i = 0; i < blocks; i++) {
        HMAC_Wrapper(m_v, m_v);

        DebugPrint(m_v, "generate: m_v", __FILE__, __LINE__);

        utils::CopyBlock(output + i * m_v.size(), &m_v[0], m_v.size());
    }

    if ((cOutputLen - (blocks * m_v.size())) != 0) {
        HMAC_Wrapper(m_v, m_v);
        utils::CopyBlock(output + blocks * m_v.size(),
                         &m_v[0],
                         (cOutputLen - (blocks * m_v.size())));
    }

    Update(cAdditionalInput, cAdditionalInputLen);
    // FIXME: Reseed counter not implemented
    // reseed_counter += 1;
}

void
HmacDrbg::IHmacDrbg::generate(const std::vector<Uint8>& cAdditionalInput,
                              std::vector<Uint8>&       output)
{
    generate(&cAdditionalInput[0],
             cAdditionalInput.size(),
             &output[0],
             output.size());
}

/*
    NIST SP 800-90A Rev 1 Page 46
    Section 10.1.2.4
*/
void
HmacDrbg::IHmacDrbg::internalReseed(const Uint8* cEntropyInput,
                                    const Uint64 cEntropyInputLen,
                                    const Uint8* cAdditionalInput,
                                    const Uint64 cAdditionalInputLen)
{
    std::vector<Uint8> seed_material(cEntropyInputLen + cAdditionalInputLen);
    Uint8*             p_seed_material = &seed_material[0];

    utils::CopyBytes(p_seed_material, cEntropyInput, cEntropyInputLen);
    utils::CopyBytes(p_seed_material + cEntropyInputLen,
                     cAdditionalInput,
                     cAdditionalInputLen);

    Update(seed_material);

    // FIXME: Reseed counter not implemented yet
    // reseed_counter = 1
}

void
HmacDrbg::IHmacDrbg::internalReseed(const std::vector<Uint8>& cEntropyInput,
                                    const std::vector<Uint8>& cAdditionalInput)
{
    internalReseed(&cEntropyInput[0],
                   cEntropyInput.size(),
                   &cAdditionalInput[0],
                   cAdditionalInput.size());
}

HmacDrbg::IHmacDrbg::IHmacDrbg(int                     digestSize,
                               std::shared_ptr<Digest> digest_obj)
    : m_digest{ digest_obj }
    , m_v{ std::vector<Uint8>(digestSize) }
    , m_key{ std::vector<Uint8>(digestSize) }
{}
} // namespace alcp::rng::drbg