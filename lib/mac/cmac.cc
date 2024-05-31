/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/mac/cmac.hh"
#include "alcp/cipher/common.hh"
#include "alcp/mac/macerror.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"

// TODO: Currently CMAC is AES-CMAC, Once IEncrypter is complete, revisit the
// class design
namespace alcp::mac {
using utils::CpuId;
using namespace status;
Cmac::Cmac()
{
    setMode(ALC_AES_MODE_NONE);
}

Cmac::Cmac(const Cmac& cmac) {}

Cmac::~Cmac()
{
    reset();
}

void
Cmac::getSubkeys()
{
    if (CpuId::cpuHasAvx2()) {
        avx2::get_subkeys(m_k1, m_k2, m_encrypt_keys, m_rounds);
        return;
    }

    // Reference algorithm for Subkey Derivation
    Uint32 temp[4]{};
    encryptBlock(temp, m_encrypt_keys, m_rounds);
    Uint8 rb[16]{};
    rb[15] = 0x87;

    cipher::dbl(reinterpret_cast<Uint8*>(temp), rb, m_k1);
    cipher::dbl(m_k1, rb, m_k2);
}

Status
Cmac::update(const Uint8 pMsgBuf[], Uint64 size)
{
    if (m_finalized) {
        return UpdateAfterFinalzeError("");
    }
    if (m_encrypt_keys == nullptr) {
        return EmptyKeyError("");
    }

    Status status{ StatusOk() };

    static bool has_avx2_aesni = CpuId::cpuHasAvx2() && CpuId::cpuHasAesni();

    // No need to Process anything for empty block
    if (size == 0) {
        return status;
    }

    /* Internal Storage buffer and Plaintext combined should be greater than
    block size to process it. Otherwise copy pMsgBuf also to internal
    buffer for later processing */
    if ((m_storage_buffer_offset + size) <= cAESBlockSize) {
        utils::CopyBlock<Uint64>(
            m_storage_buffer + m_storage_buffer_offset, pMsgBuf, size);
        m_storage_buffer_offset += size;
        return status;
    }

    int n_blocks = 0;
    // Variable to keep track of the number of bytes not processed in this
    // update which needs to be copied to the internal buffer
    int bytes_to_copy = 0;
    /* For processing, it is assumed storage buffer is always complete. So
    copy data from pMsgBuf buffer to internal storage buffer until it
    is complete */
    if (m_storage_buffer_offset <= cAESBlockSize) {
        int b = cAESBlockSize - (m_storage_buffer_offset);
        utils::CopyBlock<Uint64>(
            m_storage_buffer + m_storage_buffer_offset, pMsgBuf, b);
        m_storage_buffer_offset = cAESBlockSize;
        pMsgBuf += b;

        /* Calculations to check if internal storage buffer and pMsgBuf
        bytes combined is divisible by Cipher block size or not. If
        bytes_to_copy is zero it is divisible*/
        int ptxt_bytes_rem = size - b;
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

    if (has_avx2_aesni) {
        avx2::update(pMsgBuf,
                     m_storage_buffer,
                     m_encrypt_keys,
                     m_temp_enc_result_8,
                     m_rounds,
                     n_blocks);
    } else {
        // Using a separate pointer for pMsgBuf pointer operations so
        // original pMsgBuf pointer is unmodified
        const Uint8* p_plaintext = pMsgBuf;
        // Reference Algorithm for AES CMAC block processing
        alcp::cipher::xor_a_b(m_temp_enc_result_8,
                              m_storage_buffer,
                              m_temp_enc_result_8,
                              cAESBlockSize);
        encryptBlock(m_temp_enc_result_32, m_encrypt_keys, m_rounds);
        for (int i = 0; i < n_blocks; i++) {
            alcp::cipher::xor_a_b(m_temp_enc_result_8,
                                  p_plaintext,
                                  m_temp_enc_result_8,
                                  cAESBlockSize);
            encryptBlock(m_temp_enc_result_32, m_encrypt_keys, m_rounds);
            p_plaintext += cAESBlockSize;
        }
    }
    // Copy the unprocessed pMsgBuf bytes to the internal buffer
    utils::CopyBytes(
        m_storage_buffer, pMsgBuf + cAESBlockSize * n_blocks, bytes_to_copy);
    m_storage_buffer_offset = bytes_to_copy;

    return status;
}

Status
Cmac::reset()
{
    memset(m_temp_enc_result_8, 0, cAESBlockSize);
    memset(m_storage_buffer, 0, cAESBlockSize);
    m_storage_buffer_offset = 0;
    m_finalized             = false;
    return StatusOk();
}

Status
Cmac::finalize(Uint8 pMsgBuf[], Uint64 size)
{
    if (m_finalized) {
        return AlreadyFinalizedError("");
    }
    if (m_encrypt_keys == nullptr) {
        return EmptyKeyError("");
    }

    static bool has_avx2_aesni = CpuId::cpuHasAvx2() && CpuId::cpuHasAesni();

    Status s{ StatusOk() };

    if (has_avx2_aesni) {
        avx2::finalize(m_storage_buffer,
                       m_storage_buffer_offset,
                       cAESBlockSize,
                       m_k1,
                       m_k2,
                       m_rounds,
                       m_temp_enc_result_8,
                       m_encrypt_keys);
        utils::CopyBytes(pMsgBuf, m_temp_enc_result_8, size);
        m_finalized = true;
        return s;
    }
    // Check if storage_buffer is complete ie, Cipher Block Size bits
    if (m_storage_buffer_offset == cAESBlockSize) {
        // XOR Subkey1 with pMsgBuf bytes in storage buffer and store it
        // back to storage bufffer
        cipher::xor_a_b(
            m_k1, m_storage_buffer, m_storage_buffer, cAESBlockSize);
    } else {
        // Storage buffer is not complete. Pad it with 1000... to make it
        // complete
        m_storage_buffer[m_storage_buffer_offset] = 0x80;
        m_storage_buffer_offset += 1;
        memset(m_storage_buffer + m_storage_buffer_offset,
               0x00,
               cAESBlockSize - m_storage_buffer_offset);
        // XOR Subkey2 with pMsgBuf bytes in storage buffer and store it
        // back to storage bufffer
        cipher::xor_a_b(
            m_k2, m_storage_buffer, m_storage_buffer, cAESBlockSize);
    }
    // Xor the output from previous block (m_temp_enc_result_8) with
    // temporary storage buffer and store it back to storage_buffer
    cipher::xor_a_b(m_temp_enc_result_8,
                    m_storage_buffer,
                    m_temp_enc_result_8,
                    cAESBlockSize);
    // Encrypt the data from temp_enc_result and store it back to
    // temp_enc_result
    encryptBlock(m_temp_enc_result_32, m_encrypt_keys, m_rounds);

    utils::CopyBytes(pMsgBuf, m_temp_enc_result_8, size);

    m_finalized = true;
    return s;
}

Status
Cmac::init(const Uint8 key[], Uint64 keyLen)
{

    Status s{ StatusOk() };
    m_keyLen_in_bytes_aes = keyLen;

    if (Aes::setKey(nullptr, key, keyLen * 8) != ALC_ERROR_NONE) {
        // FIXME: Need to create another error function
        s = status::EmptyKeyError("Invalid Key Size");
        return s;
    }

    // FIXME: Check if this is required, looks like not required
    // data.keyLen_in_bytes = keyLen / 8;

    // Aes::init(&data, key, keyLen, nullptr, 0);
    m_encrypt_keys = m_cipher_key_data.m_enc_key;
    m_rounds       = getRounds();
    getSubkeys();
    s = reset();
    return s;
}
} // namespace alcp::mac