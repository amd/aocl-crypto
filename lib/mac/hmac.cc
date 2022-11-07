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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "mac/hmac.hh"
#include "utils/copy.hh"
#include <immintrin.h>

namespace alcp::mac {
class Hmac::Impl
{

  private:
    std::vector<Uint8>    key;
    Uint32                keylen;
    std::vector<Uint8>    k0, opad, ipad;
    Uint32                output_hash_size{};
    std::vector<Uint8>    output_mac;
    Uint32                input_block_length{};
    alcp::digest::Digest* p_digest;
    hmac_state_t          state = INVALID;

    std::vector<Uint8> k0_xor_opad, k0_xor_ipad;

  public:
    Impl(const alc_mac_info_t mac_info, alcp::digest::Digest* p_digest)
        : p_digest{ p_digest }
    {
        alc_error_t    err;
        alc_key_info_t kinfo = mac_info.mi_keyinfo;
        input_block_length   = p_digest->getInputBlockSize();

        if (input_block_length == 0) {
            // throw std::length_error(
            //     "ERROR: Block Length of the hash function cannot be 0");
            state = INVALID;
        }
        output_hash_size = p_digest->getHashSize();

        if (output_hash_size == 0) {
            // throw std::length_error("ERROR: Digest Hash Size cannot be 0");
            state = INVALID;
        }

        output_mac.assign(output_hash_size, 0);
        err = validate_keys(kinfo);
        if (err) {
            state = INVALID;
            return;
        }
        opad = std::vector<Uint8>(input_block_length, 0x5c);
        ipad = std::vector<Uint8>(input_block_length, 0x36);
        k0   = get_k0(input_block_length);
        get_k0_xor_pad(k0_xor_ipad, k0_xor_opad);
        // start the hash calculation
        err = calculate_hash(p_digest, k0_xor_ipad);
        if (err) {
        } else {
            state = VALID;
        }
    }

  public:
    Uint64 getHashSize()
    {
        if (state == VALID)
            return output_hash_size;
        else
            return 0;
    }
    hmac_state_t getState() const { return state; };
    alc_error_t  update(std::vector<Uint8> buff)
    {
        alc_error_t err = ALC_ERROR_NONE;
        if (getState() == VALID)
            err = calculate_hash(p_digest, buff);
        else {
            err = ALC_ERROR_BAD_STATE;
        }
        return err;
    }

    alc_error_t update(const Uint8* buff, Uint64 size)
    {
        alc_error_t err = ALC_ERROR_NONE;
        if (getState() == VALID)
            err = calculate_hash(p_digest, buff, size, nullptr);
        else
            err = ALC_ERROR_BAD_STATE;

        return err;
    }
    alc_error_t finalize(const Uint8* buff, Uint64 size)
    {
        if (getState() == VALID) {
            if (sizeof(buff) != 0 && size != 0)
                calculate_hash(p_digest, buff, size, nullptr);
            p_digest->finalize(nullptr, 0);

            std::vector<Uint8> h1(output_hash_size, 0);
            p_digest->copyHash(&(h1.at(0)), h1.size());
            p_digest->reset();
            std::vector<Uint8> k0_xor_opad_ct_h1;
            k0_xor_opad_ct_h1.insert(k0_xor_opad_ct_h1.end(),
                                     k0_xor_opad.begin(),
                                     k0_xor_opad.end());
            k0_xor_opad_ct_h1.insert(
                k0_xor_opad_ct_h1.end(), h1.begin(), h1.end());
            calculate_hash(p_digest, k0_xor_opad_ct_h1);

            p_digest->finalize(nullptr, 0);
            p_digest->copyHash(&(output_mac.at(0)), output_mac.size());
            p_digest->reset();
        }
        return ALC_ERROR_NONE;
    }

    alc_error_t copyHash(Uint8* buff, Uint64 size) const
    {
        alc_error_t err = ALC_ERROR_NONE;
        if (getState() == VALID)
            alcp::utils::CopyBytes(buff, &output_mac.at(0), size);
        else
            err = ALC_ERROR_BAD_STATE;
        return err;
    }

  private:
    alc_error_t validate_keys(const alc_key_info_t& rKeyInfo)
    {
        // For RAW assignments
        switch (rKeyInfo.fmt) {

            case ALC_KEY_FMT_RAW:
                keylen = rKeyInfo.len;
                if (keylen == 0) {
                    // std::cout << "ERROR:Key Length Cannot be Zero" <<
                    // std::endl;
                    return ALC_ERROR_INVALID_SIZE;
                }
                if (rKeyInfo.key) {
                    key =
                        std::vector<Uint8>(rKeyInfo.key, rKeyInfo.key + keylen);
                } else {
                    // std::cout << "ERROR:Key Cannot be NULL" << std::endl;
                    return ALC_ERROR_NOT_PERMITTED;
                }
                break;
            case ALC_KEY_FMT_BASE64:
                // TODO: For base64 conversions
                return ALC_ERROR_NOT_SUPPORTED; // remove this return when
                                                // above todo is resolved.
                break;
            // TODO: Subsequest switch cases for other formats
            default:
                return ALC_ERROR_NOT_SUPPORTED;
        }
        return ALC_ERROR_NONE;
    }
    void get_k0_xor_pad(std::vector<Uint8>& k0_xor_ipad,
                        std::vector<Uint8>& k0_xor_opad)
    {
        const int register_size = 128,
                  no_of_xor_operations =
                      (input_block_length * 8) / (2 * register_size),
                  xor_operations_left =
                      (input_block_length * 8) % (2 * register_size);

        Uint8* temp_k0_xor_ipad = new Uint8[input_block_length];
        Uint8* temp_k0_xor_opad = new Uint8[input_block_length];
        Uint8 *p_opad = &(opad.at(0)), *p_ipad = &(ipad.at(0)),
              *p_k0 = &(k0.at(0));

        Uint8* current_temp_k0_xor_ipad = temp_k0_xor_ipad; //
        Uint8* current_temp_k0_xor_opad = temp_k0_xor_opad;

        Uint8*        temp_ipad_xor_concat = new Uint8[input_block_length];
        constexpr int incrementer          = 2 * (128 / 8);
        Uint8*        current_temp_ipad_xor_concat = temp_ipad_xor_concat;
        for (int i = 0; i < no_of_xor_operations; i += 1) {
            __m128i reg_opad_1 =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(p_opad));
            __m128i reg_ipad_1 =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(p_ipad));
            __m128i reg_k0_1 =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(p_k0));
            __m128i reg_k0_xor_ipad_1 = _mm_xor_si128(reg_k0_1, reg_ipad_1);
            __m128i reg_k0_xor_opad_1 = _mm_xor_si128(reg_k0_1, reg_opad_1);
            _mm_storeu_si128(
                reinterpret_cast<__m128i*>(current_temp_k0_xor_ipad),
                reg_k0_xor_ipad_1); //
            _mm_storeu_si128(
                reinterpret_cast<__m128i*>(current_temp_ipad_xor_concat),
                reg_k0_xor_ipad_1);
            _mm_storeu_si128(
                reinterpret_cast<__m128i*>(current_temp_k0_xor_opad),
                reg_k0_xor_opad_1);

            __m128i reg_opad_2 = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(p_opad + register_size / 8));
            __m128i reg_ipad_2 = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(p_ipad + register_size / 8));
            __m128i reg_k0_2 = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(p_k0 + register_size / 8));
            __m128i reg_k0_xor_ipad_2 = _mm_xor_si128(reg_k0_2, reg_ipad_2);
            __m128i reg_k0_xor_opad_2 = _mm_xor_si128(reg_k0_2, reg_opad_2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(current_temp_k0_xor_ipad
                                                        + register_size / 8),
                             reg_k0_xor_ipad_2); //
            _mm_storeu_si128(
                reinterpret_cast<__m128i*>(current_temp_ipad_xor_concat
                                           + register_size / 8),
                reg_k0_xor_ipad_2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(current_temp_k0_xor_opad
                                                        + register_size / 8),
                             reg_k0_xor_opad_2);

            p_k0 += incrementer;
            current_temp_k0_xor_ipad += incrementer;
            current_temp_k0_xor_opad += incrementer;
            current_temp_ipad_xor_concat += incrementer;
            p_opad += incrementer;
            p_ipad += incrementer;
        }

        for (int i = 0; i < xor_operations_left; i++) {
            *current_temp_ipad_xor_concat = *p_k0 ^ *p_ipad;
            current_temp_ipad_xor_concat++;
            p_k0++;
            p_ipad++;
        }

        k0_xor_ipad = std::vector<Uint8>(temp_k0_xor_ipad,
                                         temp_k0_xor_ipad + input_block_length);
        k0_xor_opad = std::vector<Uint8>(temp_k0_xor_opad,
                                         temp_k0_xor_opad + input_block_length);

        delete[] temp_k0_xor_ipad;
        delete[] temp_k0_xor_opad;
        delete[] temp_ipad_xor_concat;
    }

    std::vector<Uint8> get_k0(Uint32 block_len)
    {
        std::vector<Uint8> k0;
        if (block_len == keylen) {
            k0 = key;
        } else if (keylen < block_len) {
            int L                       = block_len - keylen;
            k0                          = key;
            std::vector<Uint8> zerovect = std::vector<Uint8>(L, 0);
            k0.insert(k0.end(), zerovect.begin(), zerovect.end());
        } else if (keylen > block_len) {
            // Optimization: Reusing p_digest for calculating this sha
            p_digest->reset();
            std::vector<Uint8> hash = std::vector<Uint8>(output_hash_size, 0);
            p_digest->update(&(key.at(0)), key.size());
            p_digest->finalize(nullptr, 0);
            p_digest->copyHash(&(hash.at(0)), output_hash_size);
            p_digest->reset();

            int L = block_len - output_hash_size;

            std::vector<Uint8> zerovect = std::vector<Uint8>(L, 0);
            hash.insert(hash.end(), zerovect.begin(), zerovect.end());
            k0 = hash;
        }
        return k0;
    }

    alc_error_t calculate_hash(alcp::digest::Digest* p_digest,
                               std::vector<Uint8>    input)
    {
        return calculate_hash(p_digest, &(input.at(0)), input.size(), nullptr);
    }

    alc_error_t calculate_hash(alcp::digest::Digest* p_digest,
                               const Uint8*          input,
                               Uint64                len,
                               Uint8*                output)
    {
        alc_error_t err;
        err = p_digest->update(input, len);
        p_digest->copyHash(output, output_hash_size);
        return err;
    }
};

Hmac::Hmac(const alc_mac_info_t mac_info, alcp::digest::Digest* p_digest)
    : p_digest{ p_digest }
    , m_pimpl{ std::make_unique<Hmac::Impl>(mac_info, p_digest) }
{}
Hmac::~Hmac() {}

alc_error_t
Hmac::update(std::vector<Uint8> buff)
{
    return m_pimpl->update(buff);
}

alc_error_t
Hmac::update(const Uint8* buff, Uint64 size)
{
    return m_pimpl->update(buff, size);
}

alc_error_t
Hmac::finalize(const Uint8* buff, Uint64 size)
{

    return m_pimpl->finalize(buff, size);
}

alc_error_t
Hmac::copyHash(Uint8* buff, Uint64 size) const
{
    return m_pimpl->copyHash(buff, size);
}

Uint64
Hmac::getHashSize()
{
    return m_pimpl->getHashSize();
}

hmac_state_t
Hmac::getState() const
{
    return m_pimpl->getState();
}
} // namespace alcp::mac