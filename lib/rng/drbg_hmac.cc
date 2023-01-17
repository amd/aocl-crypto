/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

namespace alcp::random_number { namespace drbg {
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
    void DebugPrint(const std::vector<Uint8>& in,
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
    void DebugPrint(const std::vector<Uint8>& in,
                    std::string               message,
                    std::string               file,
                    int                       line)
    {}
#endif

    void HmacDrbg::IHmacDrbg::concat(concat_type_t<Uint8>& in,
                                     std::vector<Uint8>&   out)
    {
        int   pos  = 0;
        auto* pOut = &out[0];
        for (Uint64 i = 0; i < in.size(); i++) {
            auto current = *(in.at(i));
            utils::CopyBytes(pOut + pos, &(current[0]), current.size());
            pos += current.size();
        }
    }

    void HmacDrbg::IHmacDrbg::HMAC_Wrapper(const std::vector<Uint8>& key,
                                           const std::vector<Uint8>& in,
                                           std::vector<Uint8>&       out,
                                           Digest*                   sha_obj)
    {
        alc_digest_info_t hmac_digest = {
            ALC_DIGEST_TYPE_SHA2, ALC_DIGEST_LEN_256, {}, ALC_SHA2_256, {}
        };
        alc_hmac_info_t hmac_info = { hmac_digest };
        alc_key_info_t  key_info  = { ALC_KEY_TYPE_SYMMETRIC,
                                    ALC_KEY_FMT_RAW,
                                    ALC_KEY_ALG_MAC,
                                    {},
                                    static_cast<Uint32>(key.size()),
                                    &key[0] };
        alc_mac_info_t  mac_info  = { ALC_MAC_HMAC, hmac_info, key_info };
        // FIXME: Static is not a good idea, just doing for easy optimal
        // implementation
        // Digest* sha_obj  = new Sha256();
        Hmac hmac_obj = Hmac(mac_info, sha_obj);
        hmac_obj.update(&in[0], in.size());
        hmac_obj.finalize(nullptr, 0);
        hmac_obj.copyHash(&out[0], sha_obj->getHashSize());
        // hmac_obj.reset();
        sha_obj->reset();
        // delete static_cast<Sha256*>(sha_obj);
        // hmac_obj.finish();
    }

    /*
        NIST SP 800-90A Rev 1 Page 44
        Section 10.1.2.2
    */
    void HmacDrbg::IHmacDrbg::Update(const std::vector<Uint8>& p_provided_data)
    {
        int buffer_length           = m_v.size() + 1 + p_provided_data.size();
        std::vector<Uint8> zeroVect = std::vector<Uint8>{ 0x00 };
        std::vector<Uint8> oneVect  = std::vector<Uint8>{ 0x01 };
        std::vector<Uint8> buff(buffer_length);
        std::vector<const std::vector<Uint8>*> concatVect(3);

        // K = HMAC(K, V || 0x00 || provided_data)
        concatVect.at(0) = &m_v;
        concatVect.at(1) = &zeroVect;
        concatVect.at(2) = &p_provided_data;
        concat(concatVect, buff);

        DebugPrint(buff, "Update buff", __FILE__, __LINE__);

        HMAC_Wrapper(m_key, buff, m_key, m_digest);

        DebugPrint(m_key, "Update K", __FILE__, __LINE__);

        // buff.clear();

        // V = HMAC(K,V)
        HMAC_Wrapper(m_key, m_v, m_v, m_digest);

        DebugPrint(m_v, "Update V", __FILE__, __LINE__);

        if (p_provided_data.size() == 0) {
            return;
        }

        // K = HMAC(K,V || 0x01 || provided_data)
        concatVect.at(0) = &m_v;
        concatVect.at(1) = &oneVect;
        concatVect.at(2) = &p_provided_data;
        concat(concatVect, buff);
        DebugPrint(buff, "Update buff", __FILE__, __LINE__);

        HMAC_Wrapper(m_key, buff, m_key, m_digest);
        buff.clear();

        // V = HMAC(K,V)
        HMAC_Wrapper(m_key, m_v, m_v, m_digest);
    }

    /*
        NIST SP 800-90A Rev 1 Page 45
        Section 10.1.2.3
    */
    void HmacDrbg::IHmacDrbg::Instantiate(
        const std::vector<Uint8>& entropy_input,
        const std::vector<Uint8>& nonce,
        const std::vector<Uint8>& personalization_string)
    {
        // Concat Vector for seed material
        concat_type_t<Uint8> concatVect(3);
        concatVect.at(0) = &entropy_input;
        concatVect.at(1) = &nonce;
        concatVect.at(2) = &personalization_string;

        // seed_material = entropy_input || nonce || personalization_string
        std::vector<Uint8> seed_material(entropy_input.size() + nonce.size()
                                         + personalization_string.size());
        concat(concatVect, seed_material);

        // Initialize key with 0x00
        std::fill(m_key.begin(), m_key.end(), 0);
        // Initialize v with 0x01
        std::fill(m_v.begin(), m_v.end(), 1);

        DebugPrint(m_key, "K", __FILE__, __LINE__);
        DebugPrint(m_v, "V", __FILE__, __LINE__);

        DebugPrint(seed_material, "SeedMat", __FILE__, __LINE__);

        // (Key,V) = HMAC_DRBG_Update(seed_material,Key,V)
        Update(seed_material);

        DebugPrint(m_key, "K", __FILE__, __LINE__);
        DebugPrint(m_v, "V", __FILE__, __LINE__);

        // FIXME: Currently no reseed counter is there
        // reseed_counter = 1
    }

    /*
        NIST SP 800-90A Rev 1 Page 46
        Section 10.1.2.5
    */
    void HmacDrbg::IHmacDrbg::Generate(
        const std::vector<Uint8>& additional_input, std::vector<Uint8>& output)
    {
        // FIXME: Implement below
        // if (reseed_counter > reseed_interval) {
        //     return reseed_required
        // }
        if (additional_input.size() != 0) {
            Update(additional_input);
        }

        // Treating size of m_v as digest size;
        Uint64 blocks = output.size() / m_v.size();

        for (Uint64 i = 0; i < blocks; i++) {
            HMAC_Wrapper(m_key, m_v, m_v, m_digest);

            DebugPrint(m_v, "Generate: m_v", __FILE__, __LINE__);

            utils::CopyBlock(
                (&output[0]) + i * m_v.size(), &m_v[0], m_v.size());
        }

        if ((output.size() - (blocks * m_v.size())) != 0) {
            HMAC_Wrapper(m_key, m_v, m_v, m_digest);
            utils::CopyBlock((&output[0]) + blocks * m_v.size(),
                             &m_v[0],
                             (output.size() - (blocks * m_v.size())));
        }

        Update(additional_input);
        // FIXME: Reseed counter not implemented
        // reseed_counter += 1;
    }

    /*
        NIST SP 800-90A Rev 1 Page 46
        Section 10.1.2.4
    */
    void HmacDrbg::IHmacDrbg::Reseed(const std::vector<Uint8>& entropy_input,
                                     const std::vector<Uint8>& additional_input)
    {
        // seed_material = entropy_input || additional_input
        concat_type_t<Uint8> concatVect(2);
        std::vector<Uint8>   seed_material(entropy_input.size()
                                         + additional_input.size());
        concatVect.at(0) = &entropy_input;
        concatVect.at(1) = &additional_input;
        concat(concatVect, seed_material);

        // (Key,V) = HMAC_DRBG_Update(seed_material,Key,V);
        Update(seed_material);

        // FIXME: Reseed counter not implemented yet
        // reseed_counter = 1
    }

    HmacDrbg::IHmacDrbg::IHmacDrbg(int digestSize, Digest* digest_obj)
        : m_digest{ digest_obj }
    {
        m_v   = std::vector<Uint8>(digestSize);
        m_key = std::vector<Uint8>(digestSize);
    }

}} // namespace alcp::random_number::drbg