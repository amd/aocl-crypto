/*
 * Copyright (C) 2022-2025, Advanced Micro Devices. All rights reserved.
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
#include "alcp/cipher.hh"
#include "alcp/cipher/common.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"

// TODO: Currently CMAC is AES-CMAC, Once IEncrypter is complete, revisit the
// class design
namespace alcp::mac {
using utils::CpuId;
Cmac::Cmac()
{
    setMode(alcp::cipher::CipherMode::eCipherModeNone);
}

Cmac::Cmac(const Cmac& cmac)
{
    utils::CopyBytes(m_k1, cmac.m_k1, cAESBlockSize);
    utils::CopyBytes(m_k2, cmac.m_k2, cAESBlockSize);
    m_encrypt_keys = cmac.m_cipher_key_data.m_enc_key;
    utils::CopyBytes(m_buff, cmac.m_buff, cAESBlockSize);
    m_buff_offset = cmac.m_buff_offset;
    utils::CopyBytes(m_buffEnc, cmac.m_buffEnc, cAESBlockSize);
    m_pBuffEnc  = reinterpret_cast<Uint8*>(m_buffEnc);
    m_finalized = cmac.m_finalized;
}

Cmac::~Cmac()
{
    reset();
}

void
Cmac::getSubkeys()
{
    avx2::get_subkeys(m_k1, m_k2, m_encrypt_keys, m_nrounds);
    return;
}

alc_error_t
Cmac::update(const Uint8* pMsgBuf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (m_finalized) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }
    if (pMsgBuf == nullptr) {
        err = ALC_ERROR_NONE;
        return err;
    }
    if (m_encrypt_keys == nullptr) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }

    static bool has_avx2_aesni = CpuId::cpuHasAvx2() && CpuId::cpuHasAesni();

    // No need to Process anything for empty block
    if (size == 0) {
        err = ALC_ERROR_NONE;
        return err;
    }

    /* Internal Storage buffer and Plaintext combined should be greater than
    block size to process it. Otherwise copy pMsgBuf also to internal
    buffer for later processing */
    if ((m_buff_offset + size) <= cAESBlockSize) {
        utils::CopyBlock<Uint64>(m_buff + m_buff_offset, pMsgBuf, size);
        m_buff_offset += size;
        err = ALC_ERROR_NONE;
        return err;
    }

    int n_blocks = 0;
    // Variable to keep track of the number of bytes not processed in this
    // update which needs to be copied to the internal buffer
    int unprocessed_bytes_left = 0;
    /* For processing, it is assumed storage buffer is always complete. So
    copy data from pMsgBuf buffer to internal storage buffer until it
    is complete */

    int b = cAESBlockSize - (m_buff_offset);
    if (b > 0) {
        utils::CopyBlock<Uint64>(m_buff + m_buff_offset, pMsgBuf, b);
        m_buff_offset += b;
        pMsgBuf += b;
    }

    /* Calculations to check if internal storage buffer and pMsgBuf
    bytes combined is divisible by Cipher block size or not. If
    unprocessed_bytes_left is zero it is divisible*/
    /*This is just a modulus operation. This is done to see how many bytes we
    wont be able to process becauase
    it has to be a multiple of block size to be processed.*/
    int ptxt_bytes_rem     = size - b;
    n_blocks               = ((ptxt_bytes_rem) / cAESBlockSize);
    unprocessed_bytes_left = ((ptxt_bytes_rem)-cAESBlockSize * (n_blocks));

    if (unprocessed_bytes_left == 0) {
        // If the total number of blocks are a multiple of Cipher Block
        // Size then don't process the last block
        n_blocks = n_blocks - 1;
        // Assigning this will cause one unprocessed block to be copied
        // back to the buffer after update is complete
        unprocessed_bytes_left = cAESBlockSize;
    }

    if (has_avx2_aesni) {
        avx2::update(
            pMsgBuf, m_buff, m_encrypt_keys, m_pBuffEnc, m_nrounds, n_blocks);
    } else {
        // Using a separate pointer for pMsgBuf pointer operations so
        // original pMsgBuf pointer is unmodified
        const Uint8* p_plaintext = pMsgBuf;
        // Reference Algorithm for AES CMAC block processing
        alcp::cipher::xor_a_b(m_pBuffEnc, m_buff, m_pBuffEnc, cAESBlockSize);
        encryptBlock(m_buffEnc, m_encrypt_keys, m_nrounds);
        for (int i = 0; i < n_blocks; i++) {
            alcp::cipher::xor_a_b(
                m_pBuffEnc, p_plaintext, m_pBuffEnc, cAESBlockSize);
            encryptBlock(m_buffEnc, m_encrypt_keys, m_nrounds);
            p_plaintext += cAESBlockSize;
        }
    }
    // Copy the unprocessed pMsgBuf bytes to the internal buffer
    utils::CopyBytes(
        m_buff, pMsgBuf + cAESBlockSize * n_blocks, unprocessed_bytes_left);
    m_buff_offset = unprocessed_bytes_left;

    return err;
}

alc_error_t
Cmac::reset()
{
    memset(m_pBuffEnc, 0, cAESBlockSize);
    memset(m_buff, 0, cAESBlockSize);
    m_buff_offset = 0;
    m_finalized   = false;
    return ALC_ERROR_NONE;
}

alc_error_t
Cmac::finalize(Uint8* pMsgBuf, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (m_finalized) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }
    if (m_encrypt_keys == nullptr) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }

    static bool has_avx2_aesni = CpuId::cpuHasAvx2() && CpuId::cpuHasAesni();

    if (has_avx2_aesni) {
        avx2::finalize(m_buff,
                       m_buff_offset,
                       cAESBlockSize,
                       m_k1,
                       m_k2,
                       m_nrounds,
                       m_pBuffEnc,
                       m_encrypt_keys);
        utils::CopyBytes(pMsgBuf, m_pBuffEnc, size);
        m_finalized = true;
        return err;
    }
    // Check if storage_buffer is complete ie, Cipher Block Size bits
    if (m_buff_offset == cAESBlockSize) {
        // XOR Subkey1 with pMsgBuf bytes in storage buffer and store it
        // back to storage bufffer
        cipher::xor_a_b(m_k1, m_buff, m_buff, cAESBlockSize);
    } else {
        // Storage buffer is not complete. Pad it with 1000... to make it
        // complete
        m_buff[m_buff_offset] = 0x80;
        m_buff_offset += 1;
        memset(m_buff + m_buff_offset, 0x00, cAESBlockSize - m_buff_offset);
        // XOR Subkey2 with pMsgBuf bytes in storage buffer and store it
        // back to storage bufffer
        cipher::xor_a_b(m_k2, m_buff, m_buff, cAESBlockSize);
    }
    // Xor the output from previous block (m_pBuffEnc) with
    // temporary storage buffer and store it back to storage_buffer
    cipher::xor_a_b(m_pBuffEnc, m_buff, m_pBuffEnc, cAESBlockSize);
    // Encrypt the data from temp_enc_result and store it back to
    // temp_enc_result
    encryptBlock(m_buffEnc, m_encrypt_keys, m_nrounds);

    utils::CopyBytes(pMsgBuf, m_pBuffEnc, size);

    m_finalized = true;
    return err;
}

alc_error_t
Cmac::init(const Uint8* pKey, Uint64 keyLen)
{
    alc_error_t err       = ALC_ERROR_NONE;
    m_keyLen_in_bytes_aes = keyLen;

    if ((keyLen != 32) && (keyLen != 24) && (keyLen != 16)) {
        return ALC_ERROR_INVALID_SIZE;
    }

    if (Aes::setKey(pKey, keyLen * 8) != ALC_ERROR_NONE) {
        // FIXME: Need to create another error function
        return ALC_ERROR_INVALID_SIZE;
    }

    // Aes::init(&data, key, keyLen, nullptr, 0);
    m_encrypt_keys = m_cipher_key_data.m_enc_key;
    m_nrounds      = getRounds();
    getSubkeys();
    reset();
    return err;
}

} // namespace alcp::mac