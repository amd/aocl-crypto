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
#include "utils/copy.hh"

using alcp::base::Status;
using alcp::utils::CpuId;

// TODO: Currently CMAC is AES-CMAC, Once IEncrypter is complete, revisit the
// class design
namespace alcp::mac {
class Cmac::Impl : public alcp::cipher::Aes
{
    // Implementation as per NIST Special Publication 800-38B: The CMAC Mode for
    // Authentication
  public:
    std::vector<Uint8> k1 = std::vector<Uint8>(16);
    std::vector<Uint8> k2 = std::vector<Uint8>(16);

    // Pointer to user supplied key
    const Uint8* key    = nullptr;
    Uint32       keylen = 0;

    // Pointer to expanded keys
    const Uint8* encrypt_keys = nullptr;

    // Temporary Storage Buffer to keep the plaintext data for processing
    Uint8 storage_buffer[16]{};
    int   storage_buffer_offset = 0;

    // Temporary Buffer to storage Encryption Result
    Uint8 temp_enc_result[16]{};

    bool m_finalized = false;

    Impl()
        : Aes()
    {
        setMode(ALC_AES_MODE_NONE);
    }

    Status setKey(const Uint8* key, Uint64 len)
    {
        this->key    = key;
        this->keylen = len;
        Aes::setKey(key, keylen);
        encrypt_keys = getEncryptKeys();
        get_subkeys();
        reset();
        return StatusOk();
    }
    void finish()
    {
        key          = nullptr;
        this->keylen = 0;
        encrypt_keys = nullptr;
        reset();
    }
    Status reset()
    {
        memset(temp_enc_result, 0, 16);
        memset(storage_buffer, 0, 16);
        storage_buffer_offset = 0;
        m_finalized           = false;
        return StatusOk();
    };

    bool isSupported(const alc_cipher_info_t& cipherInfo) { return true; }

    alcp::base::Status update(const Uint8* plaintext, int plaintext_size)
    {
        Status status{ StatusOk() };
        if (key == nullptr || keylen == 0) {
            return InvalidArgumentError("Key is Empty");
        }
        // No need to Process anything for empty block
        if (plaintext_size == 0) {
            return StatusOk();
        }

        /*Combined Bytes to be Processed including any data remainining in
         * storage buffer and data user has provided in the current update
         * function call */
        int total_bytes_to_be_processed =
            storage_buffer_offset + plaintext_size;

        /* To keep track of the total processed bytes combining data from
         * storage buffer and current update function call */
        int total_bytes_processed_so_far = 0;

        // To keep track of the remaining number of total bytes to be
        // processed combining storage buffer and plaintext buffer
        int bytes_left_to_process =
            total_bytes_to_be_processed - total_bytes_processed_so_far;

        // To keep track of only the plaintext bytes processed so far
        int plaintext_bytes_processed_so_far = 0;

        /* Buffer contains data only for single processing. This block is copied
           to temporary storage buffer so it can be processed either in finalize
           or subsequent updates
         */
        if (total_bytes_to_be_processed <= 16) {
            assert(plaintext_size <= 16);
            alcp::utils::CopyBytes(storage_buffer + storage_buffer_offset,
                                   plaintext,
                                   plaintext_size);
            storage_buffer_offset = storage_buffer_offset + plaintext_size;
            return StatusOk();
        } else {
            // If total remaining bytes to be processed is less than or equal to
            // 128 bits, break and copy the remaining data into temporary
            // storage buffer
            while (bytes_left_to_process > 16) {
                int bytes_to_be_copied = 16 - storage_buffer_offset;
                assert(bytes_to_be_copied >= 0);
                // Copy some data from plaintext buffer into temporary storage
                // buffer but only enough to perform one Cipher Operation, ie.
                // 128 bits
                if (bytes_to_be_copied > 0) {
                    alcp::utils::CopyBytes(
                        storage_buffer + storage_buffer_offset,
                        plaintext + plaintext_bytes_processed_so_far,
                        bytes_to_be_copied);
                    plaintext_bytes_processed_so_far += bytes_to_be_copied;
                    storage_buffer_offset += bytes_to_be_copied;
                }

                // Temporary storage buffer is full. Process it.
                processChunk();

                // 128 bits was processed
                total_bytes_processed_so_far += 16;
                // combined bytes still left to process
                bytes_left_to_process =
                    total_bytes_to_be_processed - total_bytes_processed_so_far;
            }
        }
        alcp::utils::CopyBytes(storage_buffer + storage_buffer_offset,
                               plaintext + plaintext_bytes_processed_so_far,
                               bytes_left_to_process);
        storage_buffer_offset += bytes_left_to_process;
        return StatusOk();
    }

    alcp::base::Status finalize(const Uint8* plaintext, int plaintext_size)
    {

        if (key == nullptr || keylen == 0) {
            return InvalidArgumentError("Key is Empty");
        }
        if (plaintext_size != 0) {
            update(plaintext, plaintext_size);
        }
        assert(storage_buffer_offset <= 16);
        reg_128 xor_result;

        // Check if storage_buffer is complete ie, 128 bits
        if (storage_buffer_offset == 16) {
            // Since the final block was complete, ie 128 bit len, xor storage
            // buffer with k1 before final block processing
            xor_result.reg =
                _mm_xor_si128(_mm_loadu_si128((__m128i*)&k1[0]),
                              _mm_loadu_si128((__m128i*)storage_buffer));

            _mm_storeu_si128((__m128i*)this->storage_buffer, xor_result.reg);
        }
        // else: storage buffer is not complete. Pad it with 100000... to make
        // it complete
        else {
            /**
             * Set the first bit of the first byte of the unfilled bytes in
             * storage buffer as 1 and the remaining as zero
             */
            memset(storage_buffer + storage_buffer_offset, 0x80, 1);
            storage_buffer_offset += 1;
            memset(storage_buffer + storage_buffer_offset,
                   0x00,
                   16 - storage_buffer_offset);

            // Storage Buffer is filled with all 16 bytes
            storage_buffer_offset = 16;
            // Since the Final Block was Incomplete xor the already padded
            // storage buffer with k2 before final block processing.
            xor_result.reg =
                _mm_xor_si128(_mm_loadu_si128((__m128i*)&k2[0]),
                              _mm_loadu_si128((__m128i*)storage_buffer));
            _mm_storeu_si128((__m128i*)this->storage_buffer, xor_result.reg);
        }
        // Process the Final Block
        processChunk();
        m_finalized = true;
        return StatusOk();
    }

    alcp::base::Status copy(Uint8* buff, Uint32 size)
    {
        if (!m_finalized) {
            return InternalError("Cannot Copy CMAC without finalizing");
        } else {
            alcp::utils::CopyBytes(buff, temp_enc_result, size);
        }
        return StatusOk();
    }

  private:
    void get_subkeys()
    {
        if (CpuId::cpuHasAvx2()) {
            avx2::get_subkeys(k1, k2, encrypt_keys, getRounds());
        }
    }

    void processChunk()
    {
        //  Act like storage buffer is filled with 16 bytes and Perform
        //  operation
        assert(storage_buffer_offset == 16);

        if (CpuId::cpuHasAvx2()) {
            avx2::processChunk(
                temp_enc_result, storage_buffer, encrypt_keys, getRounds());
            storage_buffer_offset = 0;
            return;
        }
    }
};

Cmac::Cmac()
    : m_pImpl{ std::make_unique<Cmac::Impl>() }
{}

alcp::base::Status
Cmac::update(const Uint8* pMsgBuf, Uint64 size)
{
    return m_pImpl->update(pMsgBuf, size);
}

void
Cmac::finish()
{
    m_pImpl->finish();
}

alcp::base::Status
Cmac::reset()
{
    return m_pImpl->reset();
}

alcp::base::Status
Cmac::finalize(const Uint8* pMsgBuf, Uint64 size)
{
    return m_pImpl->finalize(pMsgBuf, size);
}

alcp::base::Status
Cmac::copy(Uint8* buff, Uint32 size)
{
    return m_pImpl->copy(buff, size);
}

alcp::base::Status
Cmac::setKey(const Uint8* key, Uint64 len)
{
    return m_pImpl->setKey(key, len);
}

Cmac::~Cmac(){};
} // namespace alcp::mac