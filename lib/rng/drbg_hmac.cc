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

namespace alcp::rng { namespace drbg {
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

    void HmacDrbg::IHmacDrbg::HMAC_Wrapper(const Uint8* in1,
                                           const Uint64 in1_len,
                                           const Uint8* in2,
                                           const Uint64 in2_len,
                                           const Uint8* in3,
                                           const Uint64 in3_len,
                                           Uint8*       out,
                                           const Uint64 out_len)
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
        hmac_obj.update(in1, in1_len);
        if (in2 != nullptr && in2_len != 0)
            hmac_obj.update(in2, in2_len);
        if (in3 != nullptr && in3_len != 0)
            hmac_obj.update(in3, in3_len);
        hmac_obj.finalize(nullptr, 0);

        // Assert that we have enough memory to write the output into
        assert(out_len >= m_digest->getHashSize());

        hmac_obj.copyHash(out, m_digest->getHashSize());

        // FIXME: Might need a hard reset in hmac_obj
        // hmac_obj.reset();
        m_digest->reset();
    }

    void HmacDrbg::IHmacDrbg::HMAC_Wrapper(const Uint8* in,
                                           const Uint64 in_len,
                                           const Uint8* in1,
                                           const Uint64 in1_len,
                                           Uint8*       out,
                                           const Uint64 out_len)
    {
        HmacDrbg::IHmacDrbg::HMAC_Wrapper(in,
                                          in_len,
                                          in1,
                                          in1_len,
                                          nullptr,
                                          static_cast<Uint64>(0),
                                          out,
                                          out_len);
    }

    void HmacDrbg::IHmacDrbg::HMAC_Wrapper(const Uint8* in,
                                           const Uint64 in_len,
                                           Uint8*       out,
                                           const Uint64 out_len)
    {
        HmacDrbg::IHmacDrbg::HMAC_Wrapper(in,
                                          in_len,
                                          nullptr,
                                          static_cast<Uint64>(0),
                                          nullptr,
                                          static_cast<Uint64>(0),
                                          out,
                                          out_len);
    }

    void HmacDrbg::IHmacDrbg::HMAC_Wrapper(const std::vector<Uint8>& in,
                                           std::vector<Uint8>&       out)
    {
        // Call the real implementation
        HMAC_Wrapper(&in[0], in.size(), &out[0], out.size());
    }

    /*
        NIST SP 800-90A Rev 1 Page 44
        Section 10.1.2.2
    */
    void HmacDrbg::IHmacDrbg::Update(const Uint8* p_provided_data,
                                     const Uint64 provided_data_len)
    {
        const std::vector<Uint8> zeroVect = std::vector<Uint8>{ 0x00 };
        const std::vector<Uint8> oneVect  = std::vector<Uint8>{ 0x01 };

        HMAC_Wrapper(&m_v[0],
                     m_v.size(),
                     &zeroVect[0],
                     zeroVect.size(),
                     p_provided_data,
                     provided_data_len,
                     &m_key[0],
                     m_key.size());

        DebugPrint(m_key, "Update K", __FILE__, __LINE__);

        // V = HMAC(K,V)
        HMAC_Wrapper(m_v, m_v);

        DebugPrint(m_v, "Update V", __FILE__, __LINE__);

        if (provided_data_len == 0) {
            return;
        }

        // K = HMAC(K,V || 0x01 || provided_data)
        HMAC_Wrapper(&m_v[0],
                     m_v.size(),
                     &oneVect[0],
                     oneVect.size(),
                     p_provided_data,
                     provided_data_len,
                     &m_key[0],
                     m_key.size());

        // V = HMAC(K,V)
        HMAC_Wrapper(m_v, m_v);
    }

    void HmacDrbg::IHmacDrbg::Update(const std::vector<Uint8>& p_provided_data)
    {
        Update(&p_provided_data[0], p_provided_data.size());
    }

    /*
        NIST SP 800-90A Rev 1 Page 45
        Section 10.1.2.3
    */
    void HmacDrbg::IHmacDrbg::Instantiate(
        const Uint8* entropy_input,
        const Uint64 entropy_input_len,
        const Uint8* nonce,
        const Uint64 nonce_len,
        const Uint8* personalization_string,
        const Uint64 personalization_string_len)
    {
        std::vector<Uint8> seed_material(entropy_input_len + nonce_len
                                         + personalization_string_len);

        Uint8* seed_material_buff_p = &seed_material[0];

        // Copy can't be avoided
        utils::CopyBytes(
            seed_material_buff_p, entropy_input, entropy_input_len);
        utils::CopyBytes(
            seed_material_buff_p + entropy_input_len, nonce, nonce_len);
        utils::CopyBytes(seed_material_buff_p + entropy_input_len + nonce_len,
                         personalization_string,
                         personalization_string_len);
        // concat(concatVect, seed_material);

        // Initialize key with 0x00
        std::fill(m_key.begin(), m_key.end(), 0);
        // Initialize v with 0x01
        std::fill(m_v.begin(), m_v.end(), 1);

        DebugPrint(m_key, "K", __FILE__, __LINE__);
        DebugPrint(m_v, "V", __FILE__, __LINE__);

        // (Key,V) = HMAC_DRBG_Update(seed_material,Key,V)
        Update(seed_material_buff_p, seed_material.size());

        DebugPrint(m_key, "K", __FILE__, __LINE__);
        DebugPrint(m_v, "V", __FILE__, __LINE__);

        // FIXME: Currently no reseed counter is there
        // reseed_counter = 1
    }

    void HmacDrbg::IHmacDrbg::Instantiate(
        const std::vector<Uint8>& entropy_input,
        const std::vector<Uint8>& nonce,
        const std::vector<Uint8>& personalization_string)
    {
        Instantiate(&entropy_input[0],
                    entropy_input.size(),
                    &nonce[0],
                    nonce.size(),
                    &personalization_string[0],
                    personalization_string.size());
    }

    /*
        NIST SP 800-90A Rev 1 Page 46
        Section 10.1.2.5
    */
    void HmacDrbg::IHmacDrbg::Generate(const Uint8* additional_input,
                                       const Uint64 additional_input_len,
                                       Uint8*       output,
                                       const Uint64 output_len)
    {
        // FIXME: Implement below
        // if (reseed_counter > reseed_interval) {
        //     return reseed_required
        // }
        if (additional_input_len != 0) {
            Update(additional_input, additional_input_len);
        }

        // Treating size of m_v as digest size;
        Uint64 blocks = output_len / m_v.size();

        for (Uint64 i = 0; i < blocks; i++) {
            HMAC_Wrapper(m_v, m_v);

            DebugPrint(m_v, "Generate: m_v", __FILE__, __LINE__);

            utils::CopyBlock(output + i * m_v.size(), &m_v[0], m_v.size());
        }

        if ((output_len - (blocks * m_v.size())) != 0) {
            HMAC_Wrapper(m_v, m_v);
            utils::CopyBlock(output + blocks * m_v.size(),
                             &m_v[0],
                             (output_len - (blocks * m_v.size())));
        }

        Update(additional_input, additional_input_len);
        // FIXME: Reseed counter not implemented
        // reseed_counter += 1;
    }

    void HmacDrbg::IHmacDrbg::Generate(
        const std::vector<Uint8>& additional_input, std::vector<Uint8>& output)
    {
        Generate(&additional_input[0],
                 additional_input.size(),
                 &output[0],
                 output.size());
    }

    /*
        NIST SP 800-90A Rev 1 Page 46
        Section 10.1.2.4
    */
    void HmacDrbg::IHmacDrbg::Reseed(const Uint8* entropy_input,
                                     const Uint64 entropy_input_len,
                                     const Uint8* additional_input,
                                     const Uint64 additional_input_len)
    {
        std::vector<Uint8> seed_material(entropy_input_len
                                         + additional_input_len);
        Uint8*             seed_material_p = &seed_material[0];

        utils::CopyBytes(seed_material_p, entropy_input, entropy_input_len);
        utils::CopyBytes(seed_material_p + entropy_input_len,
                         additional_input,
                         additional_input_len);

        Update(seed_material);

        // FIXME: Reseed counter not implemented yet
        // reseed_counter = 1
    }

    void HmacDrbg::IHmacDrbg::Reseed(const std::vector<Uint8>& entropy_input,
                                     const std::vector<Uint8>& additional_input)
    {
        Reseed(&entropy_input[0],
               entropy_input.size(),
               &additional_input[0],
               additional_input.size());
    }

    HmacDrbg::IHmacDrbg::IHmacDrbg(int                     digestSize,
                                   std::shared_ptr<Digest> digest_obj)
        : m_digest{ digest_obj }
        , m_v{ std::vector<Uint8>(digestSize) }
        , m_key{ std::vector<Uint8>(digestSize) }
    {}
}} // namespace alcp::rng::drbg