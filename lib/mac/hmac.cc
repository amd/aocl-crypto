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
    /** Single Memory Block to hold h1,
     * m_k0_xor_ipad,m_k0_xor_opad, m_k0 */
    Uint8* memory_block;
    // Input Key to HMAC
    const Uint8* m_key;
    // Length of the input key must be >0 to be valid
    Uint32 m_keylen;
    Uint32 m_k0_length;
    // Input Block Length / B of the digest used by HMAC
    Uint32 m_input_block_length{};

    Uint8* h1;

    /**
     * Processed Key to match the input block length input_block_length
     * get_k0 function performs the preprocessing
     * */
    Uint8* m_k0;
    // Size of the message digest
    Uint32 m_output_hash_size{};
    // Placeholder variable to hold the mac value after finalize has been called
    Uint8* m_output_mac;

    // TODO: Consider Shared pointer for this implementation
    /**
     * Pointer to the Base class Digest, holds the address of the derived class
     * object of Digest which supports HMAC
     *
     */
    alcp::digest::Digest* m_pDigest;

    /**
     * holds the state of HMAC Class at any point can be accessed via public
     * getState()
     * */
    hmac_state_t m_state = INVALID;

    Uint8* m_k0_xor_opad;
    Uint8* m_k0_xor_ipad;

  public:
    Impl(const alc_mac_info_t& mac_info, alcp::digest::Digest* p_digest)
        : m_pDigest{ p_digest }
    {
        alc_error_t    err;
        alc_key_info_t kinfo = mac_info.mi_keyinfo;
        m_input_block_length = p_digest->getInputBlockSize();

        if (m_input_block_length == 0) {
            // throw std::length_error(
            //     "ERROR: Block Length of the hash function cannot be 0");
            m_state = INVALID;
        }
        m_output_hash_size = p_digest->getHashSize();

        if (m_output_hash_size == 0) {
            // throw std::length_error("ERROR: Digest Hash Size cannot be 0");
            m_state = INVALID;
        }
        err = validate_keys(kinfo);
        if (err) {
            m_state = INVALID;
            return;
        }
        m_k0_length = m_input_block_length;

        // TODO: Investigate Pool Allocator for this optimization
        /*Optimization: Requesting single block of memory takes less time than
         * requesting individually*/
        memory_block = new Uint8[m_output_hash_size + 3 * m_k0_length];
        m_output_mac = new Uint8[m_output_hash_size];

        h1 = memory_block;

        // Allocate k0_xor_ipad and k0_xor_opad with same length as k0. But
        // value will be junk
        m_k0_xor_ipad = h1 + m_output_hash_size;
        m_k0_xor_opad = m_k0_xor_ipad + m_k0_length;
        m_k0          = m_k0_xor_opad + m_k0_length;

        get_k0();

        // obtain k0_xor_ipad and k0_xor_opad
        get_k0_xor_pad();

        // start the hash calculation
        err = calculate_hash(p_digest, m_k0_xor_ipad, m_input_block_length);
        if (err) {
        } else {
            m_state = VALID;
        }
    }

  public:
    Uint64 getHashSize()
    {
        if (m_state == VALID)
            return m_output_hash_size;
        else
            return 0;
    }
    hmac_state_t getState() const { return m_state; };

    alc_error_t update(const Uint8* buff, Uint64 size)
    {
        alc_error_t err = ALC_ERROR_NONE;
        if (buff != nullptr && size != 0) {
            if (getState() == VALID)
                err = calculate_hash(m_pDigest, buff, size);
            else
                err = ALC_ERROR_BAD_STATE;
        }
        return err;
    }
    alc_error_t finalize(const Uint8* buff, Uint64 size)
    {
        if (getState() == VALID) {
            if (sizeof(buff) != 0 && size != 0) {
                m_pDigest->finalize(buff, size);
            } else {
                m_pDigest->finalize(nullptr, 0);
            }
            m_pDigest->copyHash(h1, m_output_hash_size);
            m_pDigest->reset();

            calculate_hash(m_pDigest, m_k0_xor_opad, m_k0_length);
            m_pDigest->finalize(h1, m_output_hash_size);

            m_pDigest->copyHash(m_output_mac, m_output_hash_size);
            m_pDigest->reset();
            delete[] memory_block;
        }
        return ALC_ERROR_NONE;
    }

    alc_error_t copyHash(Uint8* buff, Uint64 size)
    {
        alc_error_t err = ALC_ERROR_NONE;
        if (getState() == VALID) {
            alcp::utils::CopyBytes(buff, m_output_mac, size);
        } else {
            err = ALC_ERROR_BAD_STATE;
        }
        m_state = INVALID;
        // Since m_output_mac is cleared here. CopyHash can only be called once.
        delete[] m_output_mac;
        return err;
    }

  private:
    // TODO: This method should be outside the class and a common validation
    // utility for keys
    alc_error_t validate_keys(const alc_key_info_t& rKeyInfo)
    {
        // For RAW assignments
        switch (rKeyInfo.fmt) {

            case ALC_KEY_FMT_RAW:
                m_keylen = rKeyInfo.len;
                if (m_keylen == 0) {
                    // std::cout << "ERROR:Key Length Cannot be Zero" <<
                    // std::endl;
                    return ALC_ERROR_INVALID_SIZE;
                }
                if (rKeyInfo.key) {
                    m_key = rKeyInfo.key;
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
    void get_k0_xor_pad()
    {
        constexpr int register_size = 128, // sizeof(__m128i)*8
            no_optimized_xor        = 2;
        constexpr Uint64 opad_value = 0x5c5c, ipad_value = 0x3636;

        const int input_block_length_bits = m_input_block_length * 8;

        // No of optimized xor output bits that will result from each iteration
        // in the loop
        const int optimized_bits_per_xor = no_optimized_xor * register_size;
        const int no_of_xor_operations =
            input_block_length_bits / optimized_bits_per_xor;

        __m128i* pi_k0          = reinterpret_cast<__m128i*>(m_k0);
        __m128i* pi_k0_xor_ipad = reinterpret_cast<__m128i*>(m_k0_xor_ipad);
        __m128i* pi_k0_xor_opad = reinterpret_cast<__m128i*>(m_k0_xor_opad);
        __m128i  reg_k0_1;
        __m128i  reg_k0_xor_ipad_1;
        __m128i  reg_k0_xor_opad_1;
        __m128i  reg_k0_2;
        __m128i  reg_k0_xor_ipad_2;
        __m128i  reg_k0_xor_opad_2;

        const __m128i reg_opad = _mm_set_epi16(opad_value,
                                               opad_value,
                                               opad_value,
                                               opad_value,
                                               opad_value,
                                               opad_value,
                                               opad_value,
                                               opad_value);
        const __m128i reg_ipad = _mm_set_epi16(ipad_value,
                                               ipad_value,
                                               ipad_value,
                                               ipad_value,
                                               ipad_value,
                                               ipad_value,
                                               ipad_value,
                                               ipad_value);

        /** TODO: Consider adding more optimized XOR Operations and reducing the
        register usage */
        for (int i = 0; i < no_of_xor_operations; i += 1) {
            // Load 128 bit key
            reg_k0_1 = _mm_loadu_si128(pi_k0);
            // Load the next 128 bit key
            reg_k0_2 = _mm_loadu_si128(pi_k0 + 1);

            // Perform XOR
            reg_k0_xor_ipad_1 = _mm_xor_si128(reg_k0_1, reg_ipad);
            reg_k0_xor_opad_1 = _mm_xor_si128(reg_k0_1, reg_opad);
            reg_k0_xor_ipad_2 = _mm_xor_si128(reg_k0_2, reg_ipad);
            reg_k0_xor_opad_2 = _mm_xor_si128(reg_k0_2, reg_opad);

            // Store the XOR Result
            _mm_storeu_si128(pi_k0_xor_ipad, reg_k0_xor_ipad_1);
            _mm_storeu_si128(pi_k0_xor_opad, reg_k0_xor_opad_1);
            _mm_storeu_si128((pi_k0_xor_ipad + 1), reg_k0_xor_ipad_2);
            _mm_storeu_si128(pi_k0_xor_opad + 1, reg_k0_xor_opad_2);

            // Increment for the next 256 bits
            pi_k0_xor_ipad += no_optimized_xor;
            pi_k0_xor_opad += no_optimized_xor;
            pi_k0 += no_optimized_xor;
        }

        /**
         *  Obtain Uint8* pointers from the register pointers for remaining
         * unoptimized xor
         */
        Uint8* current_temp_k0_xor_ipad =
            reinterpret_cast<Uint8*>(pi_k0_xor_ipad);
        Uint8* current_temp_k0_xor_opad =
            reinterpret_cast<Uint8*>(pi_k0_xor_opad);
        auto            p_k0 = reinterpret_cast<Uint8*>(pi_k0);
        constexpr Uint8 ipad = 0x36;
        constexpr Uint8 opad = 0x5c;

        // Calculating unoptimized xor_operations based on completed optimized
        // xor operation
        const int xor_operations_left =
            input_block_length_bits
            - no_of_xor_operations * (optimized_bits_per_xor);

        // Unoptimized XOR operation
        for (int i = 0; i < xor_operations_left; i++) {
            *current_temp_k0_xor_ipad = *p_k0 ^ ipad;
            *current_temp_k0_xor_opad = *p_k0 ^ opad;
            p_k0++;
        }
    }

    alc_error_t get_k0()
    {
        if (m_input_block_length == m_keylen) {
            utils::CopyBytes(m_k0, m_key, m_keylen);
        } else if (m_keylen < m_input_block_length) {
            utils::CopyBytes(m_k0, m_key, m_keylen);
            memset(m_k0 + m_keylen, 0x0, m_input_block_length - m_keylen);
        } else if (m_keylen > m_input_block_length) {
            // Optimization: Reusing p_digest for calculating
            m_pDigest->reset();
            m_pDigest->finalize(m_key, m_keylen);
            m_pDigest->copyHash(m_k0, m_output_hash_size);
            m_pDigest->reset();
            memset(m_k0 + m_output_hash_size,
                   0x0,
                   m_input_block_length - m_output_hash_size);
        }
        return ALC_ERROR_NONE;
    }

    alc_error_t calculate_hash(alcp::digest::Digest* p_digest,
                               const Uint8*          input,
                               Uint64                len)
    {
        alc_error_t err;
        err = p_digest->update(input, len);
        return err;
    }
};

Hmac::Hmac(const alc_mac_info_t mac_info, alcp::digest::Digest* p_digest)
    : m_pDigest{ p_digest }
    , m_pImpl{ std::make_unique<Hmac::Impl>(mac_info, p_digest) }
{}
Hmac::~Hmac() {}

alc_error_t
Hmac::update(const Uint8* buff, Uint64 size)
{
    return m_pImpl->update(buff, size);
}

alc_error_t
Hmac::finalize(const Uint8* buff, Uint64 size)
{

    return m_pImpl->finalize(buff, size);
}

alc_error_t
Hmac::copyHash(Uint8* buff, Uint64 size) const
{
    return m_pImpl->copyHash(buff, size);
}

Uint64
Hmac::getHashSize()
{
    return m_pImpl->getHashSize();
}

hmac_state_t
Hmac::getState() const
{
    return m_pImpl->getState();
}
} // namespace alcp::mac