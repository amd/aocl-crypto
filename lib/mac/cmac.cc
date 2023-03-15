/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "mac/cmac.hh"
#include "alcp/utils/cpuid.hh"
#include "cipher/aes.hh"
#include "cipher/common.hh"
#include "utils/copy.hh"

// TODO: Currently CMAC is AES-CMAC, Once IEncrypter is complete, revisit the
// class design
namespace alcp::mac {
using utils::CpuId;
using namespace status;
class Cmac::Impl : public cipher::Aes
{
    // Implementation as per NIST Special Publication 800-38B: The CMAC Mode for
    // Authentication
  private:
    static constexpr int cAESBlockSize = 16;
    alignas(16) Uint8 m_k1[cAESBlockSize]{};
    alignas(16) Uint8 m_k2[cAESBlockSize]{};

    // Pointer to user supplied key
    const Uint8* m_key    = nullptr;
    Uint32       m_keylen = 0;

    // Pointer to expanded keys
    const Uint8* m_encrypt_keys = nullptr;

    // Temporary Storage Buffer to keep the plaintext data for processing
    alignas(16) Uint8 m_storage_buffer[cAESBlockSize]{};
    int m_storage_buffer_offset = 0;

    // Temporary Buffer to storage Encryption Result
    alignas(16) Uint32 m_temp_enc_result_32[cAESBlockSize / 4]{};
    Uint8* m_temp_enc_result_8 = reinterpret_cast<Uint8*>(m_temp_enc_result_32);

    bool m_finalized = false;

  public:
    Impl()
        : Aes()
    {
        setMode(ALC_AES_MODE_NONE);
    }

    Status setKey(const Uint8 key[], Uint64 len)
    {
        this->m_key    = key;
        this->m_keylen = len;
        Status s{ StatusOk() };
        s = Aes::setKey(key, m_keylen);
        if (!s.ok()) {
            return s;
        }
        m_encrypt_keys = getEncryptKeys();
        getSubkeys();
        s = reset();
        return s;
    }

    void finish()
    {
        m_key          = nullptr;
        this->m_keylen = 0;
        m_encrypt_keys = nullptr;
        reset();
    }
    Status reset()
    {
        memset(m_temp_enc_result_8, 0, cAESBlockSize);
        memset(m_storage_buffer, 0, cAESBlockSize);
        m_storage_buffer_offset = 0;
        m_finalized             = false;
        return StatusOk();
    };

    Status update(const Uint8 plaintext[], int plaintext_size)
    {
        static bool has_avx2_aesni =
            CpuId::cpuHasAvx2() && CpuId::cpuHasAesni();

        Status status{ StatusOk() };
        if (m_key == nullptr || m_keylen == 0) {
            return InvalidArgument("Key is Empty");
        }
        // No need to Process anything for empty block
        if (plaintext_size == 0) {
            return StatusOk();
        }
        if (has_avx2_aesni) {
            avx2::update(plaintext,
                         plaintext_size,
                         m_storage_buffer,
                         m_storage_buffer_offset,
                         m_encrypt_keys,
                         m_temp_enc_result_8,
                         getRounds(),
                         cAESBlockSize);
            return status;
        }

        // Reference Algorithm for AES CMAC

        /* Internal Storage buffer and Plaintext combined should be greater than
        block size to process it. Otherwise copy plaintext also to internal
        buffer for later processing */
        if ((m_storage_buffer_offset + plaintext_size) <= cAESBlockSize) {
            utils::CopyBlock<Uint64>(m_storage_buffer + m_storage_buffer_offset,
                                     plaintext,
                                     plaintext_size);
            m_storage_buffer_offset += plaintext_size;
            return status;
        }

        int n_blocks = 0;
        // Variable to keep track of the number of bytes not processed in this
        // update which needs to be copied to the internal buffer
        int bytes_to_copy = 0;
        /* For processing, it is assumed storage buffer is always complete. So
        copy data from plaintext buffer to internal storage buffer until it
        is complete */
        if (m_storage_buffer_offset <= cAESBlockSize) {
            int b = cAESBlockSize - (m_storage_buffer_offset);
            utils::CopyBlock<Uint64>(
                m_storage_buffer + m_storage_buffer_offset, plaintext, b);
            m_storage_buffer_offset = cAESBlockSize;
            plaintext += b;

            /* Calculations to check if internal storage buffer and plaintext
            bytes combined is divisible by Cipher block size or not. If
            bytes_to_copy is zero it is divisible*/
            int ptxt_bytes_rem = plaintext_size - b;
            n_blocks           = ((ptxt_bytes_rem) / cAESBlockSize);
            bytes_to_copy      = ((ptxt_bytes_rem)-cAESBlockSize * (n_blocks));

            if (bytes_to_copy == 0) {
                // If the total number of blocks are a multiple of Cipher Block
                // Size then don't process the last block size
                n_blocks = n_blocks - 1;
                // Assigning this will cause one unprocessed block to be copied
                // back to the buffer after update is complete
                bytes_to_copy = cAESBlockSize;
            }
        }

        alcp::cipher::xor_a_b(m_temp_enc_result_8,
                              m_storage_buffer,
                              m_temp_enc_result_8,
                              cAESBlockSize);
        encryptBlock(m_temp_enc_result_32, m_encrypt_keys, getRounds());
        for (int i = 0; i < n_blocks; i++) {
            alcp::cipher::xor_a_b(m_temp_enc_result_8,
                                  plaintext,
                                  m_temp_enc_result_8,
                                  cAESBlockSize);
            encryptBlock(m_temp_enc_result_32, m_encrypt_keys, getRounds());
            plaintext += 16;
        }
        // Copy the unprocessed plaintext bytes to the internal buffer
        utils::CopyBlock<Uint64>(m_storage_buffer, plaintext, bytes_to_copy);
        m_storage_buffer_offset = bytes_to_copy;
        return StatusOk();
    }

    Status finalize(const Uint8 plaintext[], int plaintext_size)
    {

        if (m_key == nullptr || m_keylen == 0) {
            return InvalidArgument("Key is Empty");
        }
        if (plaintext_size != 0) {
            update(plaintext, plaintext_size);
        }
        assert(m_storage_buffer_offset <= cAESBlockSize);
        reg_128 xor_result;

        // Check if storage_buffer is complete ie, 128 bits
        if (m_storage_buffer_offset == cAESBlockSize) {
            // Since the final block was complete, ie 128 bit len, xor storage
            // buffer with k1 before final block processing
            xor_result.reg =
                _mm_xor_si128(_mm_loadu_si128((__m128i*)&m_k1[0]),
                              _mm_loadu_si128((__m128i*)m_storage_buffer));

            _mm_storeu_si128((__m128i*)this->m_storage_buffer, xor_result.reg);
        }
        // else: storage buffer is not complete. Pad it with 100000... to make
        // it complete
        else {
            /**
             * Set the first bit of the first byte of the unfilled bytes in
             * storage buffer as 1 and the remaining as zero
             */
            memset(m_storage_buffer + m_storage_buffer_offset, 0x80, 1);
            m_storage_buffer_offset += 1;
            memset(m_storage_buffer + m_storage_buffer_offset,
                   0x00,
                   cAESBlockSize - m_storage_buffer_offset);

            // Storage Buffer is filled with all 16 bytes
            m_storage_buffer_offset = cAESBlockSize;
            // Since the Final Block was Incomplete xor the already padded
            // storage buffer with k2 before final block processing.
            xor_result.reg =
                _mm_xor_si128(_mm_loadu_si128((__m128i*)&m_k2[0]),
                              _mm_loadu_si128((__m128i*)m_storage_buffer));
            _mm_storeu_si128((__m128i*)this->m_storage_buffer, xor_result.reg);
        }
        // Process the Final Block
        processChunk();
        m_finalized = true;
        return StatusOk();
    }

    Status copy(Uint8 buff[], Uint32 size)
    {
        if (!m_finalized) {
            return InternalError("Cannot Copy CMAC without finalizing");
        } else {
            utils::CopyBytes(buff, m_temp_enc_result_8, size);
        }
        return StatusOk();
    }

  private:
    bool isSupported(const alc_cipher_info_t& cipherInfo) { return true; }
    void getSubkeys()
    {
        if (CpuId::cpuHasAvx2()) {
            avx2::get_subkeys(m_k1, m_k2, m_encrypt_keys, getRounds());
            return;
        }

        Uint32 temp[4]{};
        encryptBlock(temp, m_encrypt_keys, getRounds());
        Uint8 rb[16]{};
        rb[15] = 0x87;

        Uint8* p_temp_8 = reinterpret_cast<Uint8*>(temp);
        cipher::dbl(p_temp_8, rb, m_k1);
        cipher::dbl(m_k1, rb, m_k2);
    }

    void processChunk()
    {
        //  Act like storage buffer is filled with 16 bytes and Perform
        //  operation
        assert(m_storage_buffer_offset == cAESBlockSize);

        if (CpuId::cpuHasAvx2()) {
            avx2::processChunk(m_temp_enc_result_8,
                               m_storage_buffer,
                               m_encrypt_keys,
                               getRounds());
            m_storage_buffer_offset = 0;
            return;
        }
    }
};

Cmac::Cmac()
    : m_pImpl{ std::make_unique<Cmac::Impl>() }
{
}

Status
Cmac::update(const Uint8 pMsgBuf[], Uint64 size)
{
    return m_pImpl->update(pMsgBuf, size);
}

void
Cmac::finish()
{
    m_pImpl->finish();
}

Status
Cmac::reset()
{
    return m_pImpl->reset();
}

Status
Cmac::finalize(const Uint8 pMsgBuf[], Uint64 size)
{
    return m_pImpl->finalize(pMsgBuf, size);
}

Status
Cmac::copy(Uint8 buff[], Uint32 size)
{
    return m_pImpl->copy(buff, size);
}

Status
Cmac::setKey(const Uint8 key[], Uint64 len)
{
    return m_pImpl->setKey(key, len);
}

Cmac::~Cmac(){};
} // namespace alcp::mac