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
#include "openssl/bio.h"
// FIXME: Remove after debugging
#include "iostream"

namespace alcp::random_number { namespace drbg {
    using alcp::digest::Sha256;
    using alcp::mac::Hmac;
    /*
    Scrapped implementation

    // void
    // HMAC_wrapper(Uint8* key, Uint8* message, std::vector<Uint8> output)
    // {
    //     static auto hmac_obj = new HMAC(bla, blue);
    //     create_HMAC_object(key);
    //     update_HMAC_object(message);
    //     finalize_HMAC_object();
    //     copy_hash_HMAC_object(&output[0],output.size());
    //     reset_HMAC_object();
    //     return mac
    // }
    */

    // void
    // HMAC_wrapper(Uint8* key, Uint8* message)
    // {
    //     create_HMAC_object(key);
    //     update_HMAC_object(message);
    //     mac = finalize_HMAC_object();
    //     return mac
    // }

    void HmacDrbg::concat(concat_type_t<Uint8>& in, std::vector<Uint8>& out)
    {
        int   pos  = 0;
        auto* pOut = &out[0];
        for (Uint64 i = 0; i < in.size(); i++) {
            auto current = *(in.at(i));
            utils::CopyBytes(pOut + pos, &(current[0]), current.size());
            pos += current.size();
        }
    }

    void HmacDrbg::HMAC_Wrapper(const std::vector<Uint8>& key,
                                const std::vector<Uint8>& in,
                                std::vector<Uint8>&       out)
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
        Sha256 sha_obj  = Sha256();
        Hmac   hmac_obj = Hmac(mac_info, &sha_obj);
        hmac_obj.update(&in[0], in.size());
        hmac_obj.finalize(nullptr, 0);
        hmac_obj.copyHash(&out[0], sha_obj.getHashSize());
        // hmac_obj.finish();
    }

    /*
        NIST SP 800-90A Rev 1 Page 44
        Section 10.1.2.2
    */
    void HmacDrbg::Update(const std::vector<Uint8>& p_provided_data,
                          std::vector<Uint8>&       p_K,
                          std::vector<Uint8>&       p_V)
    {
        int buffer_length           = p_V.size() + 1 + p_provided_data.size();
        std::vector<Uint8> zeroVect = std::vector<Uint8>{ 0x00 };
        std::vector<Uint8> oneVect  = std::vector<Uint8>{ 0x01 };
        std::vector<Uint8> buff(buffer_length);
        std::vector<const std::vector<Uint8>*> concatVect(3);

        // K = HMAC(K, V || 0x00 || provided_data)
        concatVect.at(0) = &p_V;
        concatVect.at(1) = &zeroVect;
        concatVect.at(2) = &p_provided_data;
        concat(concatVect, buff);

        std::cout << "Update buff=" << std::endl;
        BIO_dump_fp(stdout, &buff[0], buff.size());
        std::cout << std::endl;

        HMAC_Wrapper(p_K, buff, p_K);

        std::cout << "Update K=" << std::endl;
        BIO_dump_fp(stdout, &p_K[0], p_K.size());
        std::cout << std::endl;

        // buff.clear();

        // V = HMAC(K,V)
        HMAC_Wrapper(p_K, p_V, p_V);

        std::cout << "Update V=" << std::endl;
        BIO_dump_fp(stdout, &p_V[0], p_V.size());
        std::cout << std::endl;

        if (p_provided_data.size() == 0) {
            return;
        }

        // K = HMAC(K,V || 0x01 || provided_data)
        concatVect.at(0) = &p_V;
        concatVect.at(1) = &oneVect;
        concatVect.at(2) = &p_provided_data;
        concat(concatVect, buff);
        std::cout << "Update buff=" << std::endl;
        BIO_dump_fp(stdout, &buff[0], buff.size());
        std::cout << std::endl;
        HMAC_Wrapper(p_K, buff, p_K);
        buff.clear();

        // V = HMAC(K,V)
        HMAC_Wrapper(p_K, p_V, p_V);
    }

    /*
        NIST SP 800-90A Rev 1 Page 45
        Section 10.1.2.3
    */
    void HmacDrbg::Instantiate(const std::vector<Uint8>& entropy_input,
                               const std::vector<Uint8>& nonce,
                               const std::vector<Uint8>& personalization_string,
                               std::vector<Uint8>&       p_K,
                               std::vector<Uint8>&       p_V)
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
        std::fill(p_K.begin(), p_K.end(), 0);
        // Initialize v with 0x01
        std::fill(p_V.begin(), p_V.end(), 1);

        std::cout << "K=" << std::endl;
        BIO_dump_fp(stdout, &p_K[0], p_K.size());
        std::cout << std::endl;
        std::cout << "V=" << std::endl;
        BIO_dump_fp(stdout, &p_V[0], p_V.size());
        std::cout << std::endl;

        std::cout << "SeedMat=" << std::endl;
        BIO_dump_fp(stdout, &seed_material[0], seed_material.size());
        std::cout << std::endl;

        // (Key,V) = HMAC_DRBG_Update(seed_material,Key,V)
        Update(seed_material, p_K, p_V);

        std::cout << "K=" << std::endl;
        BIO_dump_fp(stdout, &p_K[0], p_K.size());
        std::cout << std::endl;
        std::cout << "V=" << std::endl;
        BIO_dump_fp(stdout, &p_V[0], p_V.size());
        std::cout << std::endl;

        // FIXME: Currently no reseed counter is there
        // reseed_counter = 1
    }

    /*
        NIST SP 800-90A Rev 1 Page 46
        Section 10.1.2.5
    */
    void HmacDrbg::Generate(const std::vector<Uint8>& additional_input,
                            std::vector<Uint8>&       output,
                            std::vector<Uint8>&       p_K,
                            std::vector<Uint8>&       p_V)
    {
        // FIXME: Implement below
        // if (reseed_counter > reseed_interval) {
        //     return reseed_required
        // }
        if (additional_input.size() != 0) {
            Update(additional_input, p_K, p_V);
        }

        // Treating size of p_V as digest size;
        Uint64 blocks = output.size() / p_V.size();

        for (Uint64 i = 0; i < blocks; i++) {
            HMAC_Wrapper(p_K, p_V, p_V);

            std::cout << "Generate: p_V=" << std::endl;
            BIO_dump_fp(stdout, &p_V[0], p_V.size());
            std::cout << std::endl;

            utils::CopyBlock(
                (&output[0]) + i * p_V.size(), &p_V[0], p_V.size());
        }

        if ((output.size() - (blocks * p_V.size())) != 0) {
            HMAC_Wrapper(p_K, p_V, p_V);
            utils::CopyBlock((&output[0]) + blocks * p_V.size(),
                             &p_V[0],
                             (output.size() - (blocks * p_V.size())));
        }

        Update(additional_input, p_K, p_V);
        // FIXME: Reseed counter not implemented
        // reseed_counter += 1;
    }

}} // namespace alcp::random_number::drbg