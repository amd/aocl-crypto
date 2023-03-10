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

// TODO: Currently CMAC is AES-CMAC, Once IEncrypter is complete, revisit the
// class design
namespace alcp::mac {
using utils::CpuId;
using namespace status;
class Cmac::Impl : public cipher::Aes
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
        Status s{ StatusOk() };
        s = Aes::setKey(key, keylen);
        if (!s.ok()) {
            return s;
        }
        encrypt_keys = getEncryptKeys();
        get_subkeys();
        s = reset();
        return s;
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

    Status update(const Uint8 plaintext[], int plaintext_size)
    {
        Status status{ StatusOk() };
        if (key == nullptr || keylen == 0) {
            return InvalidArgument("Key is Empty");
        }
        // No need to Process anything for empty block
        if (plaintext_size == 0) {
            return StatusOk();
        }
        avx2::update(plaintext,  plaintext_size, storage_buffer,
               storage_buffer_offset, encrypt_keys,temp_enc_result,getRounds());


      
        return StatusOk();
    }

    Status finalize(const Uint8* plaintext, int plaintext_size)
    {

        if (key == nullptr || keylen == 0) {
            return InvalidArgument("Key is Empty");
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

    Status copy(Uint8* buff, Uint32 size)
    {
        if (!m_finalized) {
            return InternalError("Cannot Copy CMAC without finalizing");
        } else {
            utils::CopyBytes(buff, temp_enc_result, size);
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

Status
Cmac::update(const Uint8* pMsgBuf, Uint64 size)
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
Cmac::finalize(const Uint8* pMsgBuf, Uint64 size)
{
    return m_pImpl->finalize(pMsgBuf, size);
}

Status
Cmac::copy(Uint8* buff, Uint32 size)
{
    return m_pImpl->copy(buff, size);
}

Status
Cmac::setKey(const Uint8* key, Uint64 len)
{
    return m_pImpl->setKey(key, len);
}

Cmac::~Cmac(){};
} // namespace alcp::mac