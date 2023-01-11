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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/utils/cpuid.hh"
#include "mac/hmac.hh"
#include "utils/copy.hh"
#include <cstring> // for std::memset
#include <immintrin.h>

using alcp::utils::CpuId;
namespace alcp::mac {
using Status = alcp::base::Status;
class Hmac::Impl
{
  private:
    // Input Key to HMAC
    const Uint8* m_pKey;
    // Length of the input key must be >0 to be valid
    Uint32 m_keylen;
    // Length of the preprocessed Key
    Uint32 m_k0_length;
    // Input Block Length or B of the digest used by HMAC
    Uint32 m_input_block_length{};
    // Size of the message digest
    Uint32 m_output_hash_size{};
    // Placeholder variable to hold intermediate hash and the the mac value
    // after finalize has been called
    // Optimization: Max Size of 1024 bits for any SHA
    Uint8 m_pTempHash[64];

    // TODO: Consider Shared pointer for this implementation
    /**
     * Pointer to the Base class Digest, holds the address of the derived class
     * object of Digest which supports HMAC
     *
     */
    alcp::digest::Digest* m_pDigest;

    // Single Memory Block to hold  m_pK0_xor_ipad,m_pK0_xor_opad,m_pK0.
    // 3*input_block_length (with SHA input block length max size 144 bytes for
    // SHA3-224)
    alignas(16) Uint8 m_pMemory_block[432];
    Uint8* m_pK0_xor_opad = m_pMemory_block;
    Uint8* m_pK0_xor_ipad = m_pMemory_block + 144;

    /**
     * Preprocessed Key to match the input block length input_block_length
     * get_k0 function performs the preprocessing
     * */
    Uint8* m_pK0 = m_pMemory_block + 288;

  public:
    Impl(const alc_mac_info_t& mac_info, alcp::digest::Digest* p_digest)
        : m_pDigest{ p_digest }
    {
        // Constructor argument validations
        m_input_block_length = p_digest->getInputBlockSize();
        m_output_hash_size   = p_digest->getHashSize();
        m_pKey               = mac_info.mi_keyinfo.key;
        m_keylen             = mac_info.mi_keyinfo.len;

        // For HMAC, we require k0 to be same length as input block length of
        // the used hash
        m_k0_length = m_input_block_length;

        // Preprocess key to obtain K0
        get_k0();

        // obtain k0_xor_ipad and k0_xor_opad
        get_k0_xor_pad();

        // start the hash calculation
        calculate_hash(p_digest, m_pK0_xor_ipad, m_input_block_length);
    }

  public:
    /// @brief Get hash size in bytes of the digest used for HMAC
    /// @return hash size in bytes of the HMAC digest
    Uint64 getHashSize() { return m_output_hash_size; }

    /// @brief Update HMAC with the given buffer chunk
    /// @param buff The chunk of the message to be updated
    /// @param size size of buff in bytes
    /// @return ALC_ERROR_NONE if no errors otherwise appropriate error
    Status update(const Uint8* buff, Uint64 size)
    {
        Status status = Status();
        if (buff != nullptr && size != 0) {
            status = calculate_hash(m_pDigest, buff, size);
        }
        return status;
    }

    /// @brief Last method to be called with any remaining chunks of the
    /// message to calculate HMAC
    /// @param buff final chunk of the message. Can be nullptr
    /// @param size size of buff in bytes
    /// @return ALC_ERROR_NONE if no errors otherwise appropriate error
    Status finalize(const Uint8* buff, Uint64 size)
    {
        Status status;
        // TODO: For all the following calls to digest return the proper error
        // and assign
        if (sizeof(buff) != 0 && size != 0) {
            m_pDigest->finalize(buff, size);
        } else {
            m_pDigest->finalize(nullptr, 0);
        }
        m_pDigest->copyHash(m_pTempHash, m_output_hash_size);
        m_pDigest->reset();

        calculate_hash(m_pDigest, m_pK0_xor_opad, m_k0_length);
        m_pDigest->finalize(m_pTempHash, m_output_hash_size);

        m_pDigest->copyHash(m_pTempHash, m_output_hash_size);
        m_pDigest->reset();

        return status;
    }

    /// @brief copy the result of HMAC to buff. Should be Called only after
    /// Finalize
    /// @param buff Output Buffer where HMAC result should be copied to
    /// @param size Size of buff in bytes
    /// @return ALC_ERROR_NONE if no errors otherwise appropriate error
    Status copyHash(Uint8* buff, Uint64 size)
    {
        Status status;
        alcp::utils::CopyBytes(buff, m_pTempHash, size);
        // TODO: Update status with proper error code.
        return status;
    }

    void finish() {}

    Status reset()
    {
        Status status;
        m_pDigest->reset();
        status =
            calculate_hash(m_pDigest, m_pK0_xor_ipad, m_input_block_length);
        return status;
    }

  private:
    void get_k0_xor_pad()
    {
        if (CpuId::cpuHasAvx2()) {
            avx2::get_k0_xor_opad(
                m_input_block_length, m_pK0, m_pK0_xor_ipad, m_pK0_xor_opad);
            return;
        }
        constexpr int register_size = 128, // sizeof(__m128i)*8
            no_optimized_xor =
                2; // No. of XORs performed inside the for loop below

        // Fixed values from the specification
        constexpr Uint64 opad_value = 0x5c5c, ipad_value = 0x3636;

        const int input_block_length_bits = m_input_block_length * 8;

        // No of optimized xor output bits that will result from each
        // iteration in the loop
        const int optimized_bits_per_xor = no_optimized_xor * register_size;
        const int no_of_xor_operations =
            input_block_length_bits / optimized_bits_per_xor;

        __m128i* pi_k0          = reinterpret_cast<__m128i*>(m_pK0);
        __m128i* pi_k0_xor_ipad = reinterpret_cast<__m128i*>(m_pK0_xor_ipad);
        __m128i* pi_k0_xor_opad = reinterpret_cast<__m128i*>(m_pK0_xor_opad);
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

        /** TODO: Consider adding more optimized XOR Operations and reducing
        the register usage */
        for (int i = 0; i < no_of_xor_operations; i += 1) {
            // Load 128 bit key
            reg_k0_1 = _mm_load_si128(pi_k0);
            // Load the next 128 bit key
            reg_k0_2 = _mm_load_si128(pi_k0 + 1);

            // Perform XOR
            reg_k0_xor_ipad_1 = _mm_xor_si128(reg_k0_1, reg_ipad);
            reg_k0_xor_opad_1 = _mm_xor_si128(reg_k0_1, reg_opad);
            reg_k0_xor_ipad_2 = _mm_xor_si128(reg_k0_2, reg_ipad);
            reg_k0_xor_opad_2 = _mm_xor_si128(reg_k0_2, reg_opad);

            // Store the XOR Result
            _mm_store_si128(pi_k0_xor_ipad, reg_k0_xor_ipad_1);
            _mm_store_si128(pi_k0_xor_opad, reg_k0_xor_opad_1);
            _mm_store_si128((pi_k0_xor_ipad + 1), reg_k0_xor_ipad_2);
            _mm_store_si128(pi_k0_xor_opad + 1, reg_k0_xor_opad_2);

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

        // Calculating unoptimized xor_operations based on completed
        // optimized xor operation
        const int xor_operations_left =
            (input_block_length_bits
             - no_of_xor_operations * (optimized_bits_per_xor))
            / 8;

        // Unoptimized XOR operation
        for (int i = 0; i < xor_operations_left; i++) {
            *current_temp_k0_xor_ipad = *p_k0 ^ ipad;
            *current_temp_k0_xor_opad = *p_k0 ^ opad;
            p_k0++;
            current_temp_k0_xor_ipad++;
            current_temp_k0_xor_opad++;
        }
    }
    void copyData(Uint8* destination, const Uint8* source, int len)
    {
        if (CpuId::cpuHasAvx2()) {

            avx2::copyData(destination, source, len);
        } else {

            alcp::utils::CopyBytes(destination, source, len);
        }
    }

    Status get_k0()
    {
        Status status;
        if (m_input_block_length == m_keylen) {
            copyData(m_pK0, m_pKey, m_keylen);
        } else if (m_keylen < m_input_block_length) {
            copyData(m_pK0, m_pKey, m_keylen);
            std::memset(m_pK0 + m_keylen, 0x0, m_input_block_length - m_keylen);
        } else if (m_keylen > m_input_block_length) {
            // Optimization: Reusing p_digest for calculating
            // TODO: For all the following digest calls check and update proper
            // error status
            m_pDigest->reset();
            m_pDigest->finalize(m_pKey, m_keylen);
            m_pDigest->copyHash(m_pK0, m_output_hash_size);
            m_pDigest->reset();
            std::memset(m_pK0 + m_output_hash_size,
                        0x0,
                        m_input_block_length - m_output_hash_size);
        }
        return status;
    }

    Status calculate_hash(alcp::digest::Digest* p_digest,
                          const Uint8*          input,
                          Uint64                len)
    {
        Status status;
        p_digest->update(input, len);
        // TODO: Based on the output from update call update status code
        return status;
    }
};

Hmac::Hmac(const alc_mac_info_t mac_info, alcp::digest::Digest* p_digest)
    : m_pDigest{ p_digest }
    , m_pImpl{ std::make_unique<Hmac::Impl>(mac_info, p_digest) }
{}
Hmac::~Hmac() {}

Status
Hmac::update(const Uint8* buff, Uint64 size)
{
    return m_pImpl->update(buff, size);
}

Status
Hmac::finalize(const Uint8* buff, Uint64 size)
{

    return m_pImpl->finalize(buff, size);
}

Status
Hmac::copyHash(Uint8* buff, Uint64 size) const
{
    return m_pImpl->copyHash(buff, size);
}

Uint64
Hmac::getHashSize()
{
    return m_pImpl->getHashSize();
}

void
Hmac::finish()
{
    m_pImpl->finish();
}

Status
Hmac::reset()
{
    return m_pImpl->reset();
}
} // namespace alcp::mac
