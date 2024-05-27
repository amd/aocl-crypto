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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/cipher/aes_ccm.hh"
#include "alcp/cipher/cipher_error.hh"

#include <immintrin.h>
#include <sstream>
#include <string.h>
#include <wmmintrin.h>

using alcp::utils::CpuId;
namespace alcp::cipher {

// Macros
// FIXME: Better to use template instead of this.
#define CRYPT_AEAD_WRAPPER_FUNC(CLASS_NAME, WRAPPER_FUNC, FUNC_NAME, IS_ENC)   \
    alc_error_t CLASS_NAME::WRAPPER_FUNC(alc_cipher_data_t* ctx,               \
                                         const Uint8*       pInput,            \
                                         Uint8*             pOutput,           \
                                         Uint64             len)               \
    {                                                                          \
        Status s    = StatusOk();                                              \
        m_isEnc_aes = IS_ENC;                                                  \
        s           = Ccm::FUNC_NAME(pInput, pOutput, len, IS_ENC);            \
        return s.code();                                                       \
    } // namespace alcp::cipher

inline void
ctrInc(Uint8 ctr[])
{
    // From 8 Counter starts, added in reverse.
    Uint64 ind = 7;
    while (ind != 0) {
        ctr[ind + 8]++;
        if (ctr[ind + 8]) {
            return;
        }
        ind--;
    }
}

Ccm::Ccm(alc_cipher_data_t* ctx)
    : Aes(ctx)
{
}
#ifdef CCM_MULTI_UPDATE
alc_error_t
Ccm::setPlainTextLength(alc_cipher_data_t* ctx, Uint64 len)
{
    m_plainTextLength      = len;
    m_updatedLength        = 0;
    m_is_plaintext_len_set = true;
    return ALC_ERROR_NONE;
}
#endif

// FIXME: nRounds needs to be constexpr to be more efficient
Status
Ccm::cryptUpdate(const Uint8 pInput[],
                 Uint8       pOutput[],
                 Uint64      dataLen,
                 bool        isEncrypt)
{

#ifdef CCM_MULTI_UPDATE
    if (!m_ccm_data.key) {
        return status::InvalidValue("Key has to be set before update");
    }
    Status s = StatusOk();
    if ((pInput != NULL) && (pOutput != NULL)) {
        // Accelerate with AESNI
        if (CpuId::cpuHasAesni()) {
            if (m_updatedLength == 0) {
                aesni::ccm::SetAad(&m_ccm_data,
                                   m_additionalData,
                                   m_additionalDataLen,
                                   m_plainTextLength);
            }
            if (isEncrypt) {
                CCM_ERROR err =
                    aesni::ccm::Encrypt(&m_ccm_data, pInput, pOutput, dataLen);
                switch (err) {
                    case CCM_ERROR::LEN_MISMATCH:
                        s = status::EncryptFailed(
                            "Length of plainText mismatch!");
                        break;
                    case CCM_ERROR::DATA_OVERFLOW:
                        s = status::EncryptFailed(
                            "Overload of plaintext. Please reduce it!");
                        break;
                    default:
                        break;
                }
            } else {
                CCM_ERROR err =
                    aesni::ccm::Decrypt(&m_ccm_data, pInput, pOutput, dataLen);
                switch (err) {
                    case CCM_ERROR::LEN_MISMATCH:
                        s = status::DecryptFailed(
                            "Length of plainText mismatch!");
                        break;
                    default:
                        break;
                }
            }
            if (s.ok() != true) {
                // Burn everything
                memset(m_ccm_data.nonce, 0, 16);
                memset(m_ccm_data.cmac, 0, 16);
                memset(pOutput, 0, dataLen);
                return s;
            }
            if (s.ok()) {
                m_updatedLength += dataLen;
            }
            return s;
        }
        if (m_updatedLength == 0) {
            // Fallback to reference
            setAadRef(&m_ccm_data,
                      m_additionalData,
                      m_additionalDataLen,
                      m_plainTextLength);
        }
        // FIXME: Encrypt and Decrypt needs to be defined.
        if (isEncrypt) {
            s.update(encryptRef(&m_ccm_data, pInput, pOutput, dataLen));
        } else {
            s.update(decryptRef(&m_ccm_data, pInput, pOutput, dataLen));
        }
        if (s.ok() != true) {
            // Burn everything
            // FIXME: Need to clear key when errors
            // memset(reinterpret_cast<void*>(m_ccm_data.key), 0, 224);
            memset(m_ccm_data.nonce, 0, 16);
            memset(m_ccm_data.cmac, 0, 16);
            memset(pOutput, 0, dataLen);
            return s;
        }
    } else {
        s = status::InvalidValue("Input or Output Null Pointer!");
    }
    if (s.ok()) {
        m_updatedLength += dataLen;
    }
    return s;
#else

    Status s = StatusOk();

    if ((pInput != NULL) && (pOutput != NULL)) {

        const Uint8* p_keys  = getEncryptKeys();
        const Uint32 cRounds = m_nrounds;
        m_ccm_data.key       = p_keys;
        m_ccm_data.rounds    = cRounds;

        // Below Operations has to be done in order
        s.update(setIv(&m_ccm_data, m_iv_aes, m_ivLen_aes, dataLen));

        // Accelerate with AESNI
        if (CpuId::cpuHasAesni()) {
            aesni::ccm::SetAad(
                &m_ccm_data, m_additionalData, m_additionalDataLen);
            if (isEncrypt) {
                CCM_ERROR err =
                    aesni::ccm::Encrypt(&m_ccm_data, pInput, pOutput, dataLen);
                switch (err) {
                    case CCM_ERROR::LEN_MISMATCH:
                        s = status::EncryptFailed(
                            "Length of plainText mismatch!");
                        break;
                    case CCM_ERROR::DATA_OVERFLOW:
                        s = status::EncryptFailed(
                            "Overload of plaintext. Please reduce it!");
                        break;
                    default:
                        break;
                }
            } else {
                CCM_ERROR err =
                    aesni::ccm::Decrypt(&m_ccm_data, pInput, pOutput, dataLen);
                switch (err) {
                    case CCM_ERROR::LEN_MISMATCH:
                        s = status::DecryptFailed(
                            "Length of plainText mismatch!");
                        break;
                    default:
                        break;
                }
            }
            if (s.ok() != true) {
                // Burn everything
                memset(m_ccm_data.nonce, 0, 16);
                memset(m_ccm_data.cmac, 0, 16);
                memset(pOutput, 0, dataLen);
                return s;
            }
            return s;
        }

        // Fallback to reference
        setAadRef(&m_ccm_data, m_additionalData, m_additionalDataLen);
        // FIXME: Encrypt and Decrypt needs to be defined.
        if (isEncrypt) {
            s.update(encryptRef(&m_ccm_data, pInput, pOutput, dataLen));
        } else {
            s.update(decryptRef(&m_ccm_data, pInput, pOutput, dataLen));
        }
        if (s.ok() != true) {
            // Burn everything
            // FIXME: Need to clear key when errors
            // memset(reinterpret_cast<void*>(m_ccm_data.key), 0, 224);
            memset(m_ccm_data.nonce, 0, 16);
            memset(m_ccm_data.cmac, 0, 16);
            memset(pOutput, 0, dataLen);
            return s;
        }
    } else {
        s = status::InvalidValue("Input or Output Null Pointer!");
    }
    return s;
#endif
}

Status
Ccm::encryptRef(ccm_data_t* pccm_data,
                const Uint8 pPlainText[],
                Uint8       pCipherText[],
                size_t      ptLen)
{
    // Implementation block diagram
    // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_encryption.png
    Status       s = StatusOk();
    unsigned int i;
    if (pPlainText == nullptr || pCipherText == nullptr
        || pccm_data == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }
    Uint32 cmac[4], nonce[4], in_reg[4], temp_reg[4];
    Uint8* p_cmac_8 = reinterpret_cast<Uint8*>(cmac);
    Uint8* p_temp_8 = reinterpret_cast<Uint8*>(temp_reg);

    utils::CopyBytes(nonce, pccm_data->nonce, 16);
    utils::CopyBytes(cmac, pccm_data->cmac, 16);

    while (ptLen >= 16) {
        // Load the PlainText
        utils::CopyBytes(in_reg, pPlainText, 16);

        /* CBC */
        // Generate CMAC given plaintext by using cbc algorithm
        for (int i = 0; i < 4; i++) {
            cmac[i] ^= in_reg[i];
        }
        encryptBlock(cmac, pccm_data->key, pccm_data->rounds);

        /* CTR */
        // Generate ciphetext given plain text by using ctr algitrithm
        utils::CopyBytes(temp_reg, nonce, 16);
        encryptBlock(temp_reg, pccm_data->key, pccm_data->rounds);
        ctrInc(reinterpret_cast<Uint8*>(nonce)); // Increment counter
        for (int i = 0; i < 4; i++) {
            temp_reg[i] ^= in_reg[i];
        }

        // Store CipherText
        utils::CopyBytes(pCipherText, temp_reg, 16);

        pPlainText += 16;
        pCipherText += 16;
        ptLen -= 16;
    }
    if (ptLen) {
        /* CBC */
        // For what ever is left, generate block to encrypt using ctr
        for (i = 0; i < ptLen; i++) {
            p_cmac_8[i] ^= pPlainText[i];
        }
        encryptBlock(cmac, pccm_data->key, pccm_data->rounds);

        /* CTR */
        utils::CopyBytes(temp_reg, nonce, 16);
        encryptBlock(temp_reg, pccm_data->key, pccm_data->rounds);
        for (i = 0; i < ptLen; ++i)
            pCipherText[i] = p_temp_8[i] ^ pPlainText[i];
    }

    // Copy the current state of cmac and nonce back to memory.
    utils::CopyBytes(pccm_data->cmac, cmac, 16);
    utils::CopyBytes(pccm_data->nonce, nonce, 16);

    return s;
}

Status
Ccm::decryptRef(ccm_data_t* pccm_data,
                const Uint8 pCipherText[],
                Uint8       pPlainText[],
                size_t      ctLen)
{
    // Implementation block diagram
    // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_decryption.png
    Status       s = StatusOk();
    unsigned int i;
    if (pPlainText == nullptr || pCipherText == nullptr
        || pccm_data == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }
    Uint32 cmac[4], nonce[4], in_reg[4], temp_reg[4];
    Uint8* p_cmac_8 = reinterpret_cast<Uint8*>(cmac);
    Uint8* p_temp_8 = reinterpret_cast<Uint8*>(temp_reg);

    utils::CopyBytes(nonce, pccm_data->nonce, 16);
    utils::CopyBytes(cmac, pccm_data->cmac, 16);

    while (ctLen >= 16) {

        /* CTR */
        utils::CopyBytes(temp_reg, nonce, 16);
        encryptBlock(temp_reg, pccm_data->key, pccm_data->rounds);
        ctrInc(reinterpret_cast<Uint8*>(nonce)); // Increment counter

        utils::CopyBytes(in_reg, pCipherText, 16); // Load CipherText
        // Generate PlainText (Complete CTR)
        for (int i = 0; i < 4; i++) {
            temp_reg[i] ^= in_reg[i];
        }

        /* CBC */
        // Generate Partial result
        for (int i = 0; i < 4; i++) {
            cmac[i] ^= temp_reg[i];
        }

        utils::CopyBytes(pPlainText, temp_reg, 16); // Store plaintext.

        // Generate the partial tag, Xor of CBC is above
        encryptBlock(cmac, pccm_data->key, pccm_data->rounds);

        pCipherText += 16;
        pPlainText += 16;
        ctLen -= 16;
    }

    if (ctLen) {
        /* CTR */
        utils::CopyBytes(temp_reg, nonce, 16); // Copy Counter
        encryptBlock(temp_reg, pccm_data->key, pccm_data->rounds);

        for (i = 0; i < ctLen; ++i) {
            // CTR XOR operation to generate plaintext
            pPlainText[i] = p_temp_8[i] ^ pCipherText[i];
            // CBC XOR operation to generate cmac
            p_cmac_8[i] ^= pPlainText[i];
        }

        /* CBC */
        // CBC Xor is above, Encrypt the partial result to create partial
        // tag
        encryptBlock(cmac, pccm_data->key, pccm_data->rounds);
    }

    // Copy the current state of cmac and nonce back to memory.
    utils::CopyBlock(pccm_data->cmac, cmac, 16);
    utils::CopyBlock(pccm_data->nonce, nonce, 16);

    return s;
}

#ifdef CCM_MULTI_UPDATE
Status
Ccm::setIv(ccm_data_t* ccm_data, const Uint8 pIv[], size_t ivLen)
{
    Status       s = StatusOk();
    unsigned int q = ccm_data->nonce[0] & 7;

    if (ccm_data == nullptr || pIv == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }

    if (ivLen < (14 - q)) {
        s = status::InvalidValue("Length of nonce is too small!");
        return s;
    }
    if (sizeof(m_plainTextLength) == 8 && q >= 3) {
        ccm_data->nonce[8]  = static_cast<Uint8>(m_plainTextLength >> 56);
        ccm_data->nonce[9]  = static_cast<Uint8>(m_plainTextLength >> 48);
        ccm_data->nonce[10] = static_cast<Uint8>(m_plainTextLength >> 40);
        ccm_data->nonce[11] = static_cast<Uint8>(m_plainTextLength >> 32);
    } else {
        memset(ccm_data->nonce + 8, 0, 8);
    }

    ccm_data->nonce[12] = static_cast<Uint8>(m_plainTextLength >> 24);
    ccm_data->nonce[13] = static_cast<Uint8>(m_plainTextLength >> 16);
    ccm_data->nonce[14] = static_cast<Uint8>(m_plainTextLength >> 8);
    ccm_data->nonce[15] = static_cast<Uint8>(m_plainTextLength);

    ccm_data->nonce[0] &= ~0x40; /* clear Adata flag */
    utils::CopyBytes(&ccm_data->nonce[1], pIv, 14 - q);
    // EXITG();
    return s;
}
#else
Status
Ccm::setIv(ccm_data_t* ccm_data,
           const Uint8 pIv[],
           size_t      ivLen,
           size_t      dataLen)
{
    Status       s = StatusOk();
    unsigned int q = ccm_data->nonce[0] & 7;

    if (ccm_data == nullptr || pIv == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }

    if (ivLen < (14 - q)) {
        s = status::InvalidValue("Length of nonce is too small!");
        return s;
    }
    if (sizeof(dataLen) == 8 && q >= 3) {
        ccm_data->nonce[8]  = static_cast<Uint8>(dataLen >> 56);
        ccm_data->nonce[9]  = static_cast<Uint8>(dataLen >> 48);
        ccm_data->nonce[10] = static_cast<Uint8>(dataLen >> 40);
        ccm_data->nonce[11] = static_cast<Uint8>(dataLen >> 32);
    } else {
        memset(ccm_data->nonce + 8, 0, 8);
    }

    ccm_data->nonce[12] = static_cast<Uint8>(dataLen >> 24);
    ccm_data->nonce[13] = static_cast<Uint8>(dataLen >> 16);
    ccm_data->nonce[14] = static_cast<Uint8>(dataLen >> 8);
    ccm_data->nonce[15] = static_cast<Uint8>(dataLen);

    ccm_data->nonce[0] &= ~0x40; /* clear Adata flag */
    utils::CopyBytes(&ccm_data->nonce[1], pIv, 14 - q);
    // EXITG();
    return s;
}

#endif
#if CCM_MULTI_UPDATE
Status
Ccm::finalizeRef(ccm_data_t* pccm_data)
{
    Status        s = StatusOk();
    unsigned int  q;
    unsigned char flags0 = pccm_data->flags0;
    q                    = flags0 & 7;
    Uint32 cmac[4], nonce[4], temp_reg[4];
    utils::CopyBytes(nonce, pccm_data->nonce, 16);
    utils::CopyBytes(cmac, pccm_data->cmac, 16);
    Uint8* p_nonce_8 = reinterpret_cast<Uint8*>(nonce);

    // Zero out counter part
    for (int i = 15 - q; i < 16; ++i) // TODO: Optimize this with copy
        p_nonce_8[i] = 0;

    // CTR encrypt first counter and XOR with the partial tag to generate
    // the real tag
    utils::CopyBytes(temp_reg, nonce, 16);
    encryptBlock(temp_reg, pccm_data->key, pccm_data->rounds);

    for (int i = 0; i < 4; i++) {
        cmac[i] ^= temp_reg[i];
    }

    // Restore flags into nonce to restore nonce to original state
    p_nonce_8[0] = pccm_data->flags0;
    // Copy the current state of cmac and nonce back to memory.
    utils::CopyBytes(pccm_data->cmac, cmac, 16);
    utils::CopyBytes(pccm_data->nonce, nonce, 16);
    return s;
}
#endif
Status
Ccm::getTagRef(ccm_data_t* ctx, Uint8 ptag[], size_t tagLen)
{
    // Retrieve the tag length
    Status s = StatusOk();

    if (ctx == nullptr || ptag == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }
    unsigned int t = (ctx->nonce[0] >> 3) & 7;

    t *= 2;
    t += 2;
    if (tagLen != t) {
        s = status::InvalidValue(
            "Tag length is not what we agreed upon during start!");
        return s;
    }
    utils::CopyBytes(ptag, ctx->cmac, t);
    memset(ctx->cmac, 0, tagLen);
    // EXITG();
    return s;
}

#ifdef CCM_MUTLI_UPDATE
Status
Ccm::setAadRef(ccm_data_t* pccm_data,
               const Uint8 paad[],
               size_t      aadLen,
               size_t      plen)
{
    Status s         = StatusOk();
    Uint32 p_blk0[4] = {};
    Uint32 aad_32[4] = {};
    Uint8* p_blk0_8  = reinterpret_cast<Uint8*>(&p_blk0);
    Uint64 i         = {};

    // FIXME: Should we let paad be null when aadLen is 0
    // if (paad == nullptr || pccm_data == nullptr) {
    //     s = status::InvalidValue("Null Pointer is not expected!");
    //     return s;
    // }

    if (aadLen != 0) {
        // Set Adata Available Flag
        pccm_data->nonce[0] |= 0x40;

        utils::CopyBytes(p_blk0, pccm_data->nonce, 16);

        encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);

        pccm_data->blocks++;

        if (aadLen < (0x10000 - 0x100)) {
            // alen < (2^16 - 2^8)
            *(p_blk0_8 + 0) ^= static_cast<Uint8>(aadLen >> 8);
            *(p_blk0_8 + 1) ^= static_cast<Uint8>(aadLen);
            i = 2;
        } else if (sizeof(aadLen) == 8 && aadLen >= ((size_t)1 << 32)) {
            // alen > what 32 bits can hold.
            *(p_blk0_8 + 0) ^= 0xFF;
            *(p_blk0_8 + 1) ^= 0xFF;
            *(p_blk0_8 + 2) ^= static_cast<Uint8>(aadLen >> 56);
            *(p_blk0_8 + 3) ^= static_cast<Uint8>(aadLen >> 48);
            *(p_blk0_8 + 4) ^= static_cast<Uint8>(aadLen >> 40);
            *(p_blk0_8 + 5) ^= static_cast<Uint8>(aadLen >> 32);
            *(p_blk0_8 + 6) ^= static_cast<Uint8>(aadLen >> 24);
            *(p_blk0_8 + 7) ^= static_cast<Uint8>(aadLen >> 16);
            *(p_blk0_8 + 8) ^= static_cast<Uint8>(aadLen >> 8);
            *(p_blk0_8 + 9) ^= static_cast<Uint8>(aadLen);
            i = 10;
        } else {
            // alen is represented by 32 bits but larger than
            // what 16 bits can hold
            *(p_blk0_8 + 0) ^= 0xFF;
            *(p_blk0_8 + 1) ^= 0xFE;
            *(p_blk0_8 + 2) ^= static_cast<Uint8>(aadLen >> 24);
            *(p_blk0_8 + 3) ^= static_cast<Uint8>(aadLen >> 16);
            *(p_blk0_8 + 4) ^= static_cast<Uint8>(aadLen >> 8);
            *(p_blk0_8 + 5) ^= static_cast<Uint8>(aadLen);
            i = 6;
        }

        // i=2,6,10 to i=16 do the CBC operation
        for (; i < 16 && aadLen; ++i, ++paad, --aadLen)
            *(p_blk0_8 + i) ^= *paad;

        encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);
        pccm_data->blocks++;

        Uint64 alen_16 = aadLen / 16;
        for (Uint64 j = 0; j < alen_16; j++) {
            utils::CopyBytes(aad_32, paad, 16);
            // CBC XOR Operation
            for (int i = 0; i < 4; i++) {
                p_blk0[i] ^= aad_32[i];
            }
            // CBC Encrypt Operation
            encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);
            pccm_data->blocks++;
            paad += 16;
        }

        // Reduce already processed value from alen
        aadLen -= alen_16 * 16;

        if (aadLen != 0) {
            // Process the rest in the default way
            for (i = 0; i < 16 && aadLen; i++, paad++, aadLen--) {
                *(p_blk0_8 + i) ^= *paad;
            }

            // CBC Encrypt last block
            encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);
            pccm_data->blocks++;
        }

        // Store generated partial tag (cmac)
        utils::CopyBlock(pccm_data->cmac, p_blk0_8, 16);
    }

    size_t       n;
    unsigned int q;
    const Uint8* p_key = pccm_data->key;
    Uint32       cmac[4], nonce[4];

    Uint8* p_nonce_8 = reinterpret_cast<Uint8*>(nonce);

    utils::CopyBytes(nonce, pccm_data->nonce, 16);
    unsigned char flags0 = pccm_data->flags0 = pccm_data->nonce[0];
    if (!(flags0 & 0x40)) {
        utils::CopyBytes(cmac, nonce, 16);
        encryptBlock(cmac, p_key, pccm_data->rounds);
        pccm_data->blocks++;
    } else {
        // Additional data exists so load the cmac (already done in encrypt
        // aad)
        utils::CopyBytes(cmac, pccm_data->cmac, 16);
    }

    // Set nonce to just length to store size of plain text
    // extracted from flags
    p_nonce_8[0] = q = flags0 & 7;

    // Reconstruct length of plain text
    for (n = 0, i = 15 - q; i < 15; ++i) {
        n |= p_nonce_8[i];
        p_nonce_8[i] = 0;
        n <<= 8;
    }

    // Extract Length
    n |= p_nonce_8[15];
    p_nonce_8[15] = 1;

    // Check if input length matches the intialized length
    if (n != plen) {
        // EXITB();
        s = status::EncryptFailed("Length of plainText mismatch!");
        return s;
    }

    // Check with everything combined we won't have too many blocks to
    // encrypt
    pccm_data->blocks += ((plen + 15) >> 3) | 1;
    if (pccm_data->blocks > (Uint64(1) << 61)) {
        // EXITB();
        s = status::EncryptFailed("Overload of plaintext. Please reduce it!");
        return s;
    }

    utils::CopyBytes(pccm_data->cmac, cmac, 16);
    utils::CopyBytes(pccm_data->nonce, nonce, 16);

    return s;
}
#else

Status
Ccm::setAadRef(ccm_data_t* pccm_data, const Uint8 paad[], size_t aadLen)
{
    Status s         = StatusOk();
    Uint32 p_blk0[4] = {};
    Uint32 aad_32[4] = {};
    Uint8* p_blk0_8  = reinterpret_cast<Uint8*>(&p_blk0);
    Uint64 i         = {};

    // FIXME: Should we let paad be null when aadLen is 0
    if (paad == nullptr || pccm_data == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s;
    }

    if (aadLen == 0) {
        return s; // Nothing to be done
    }

    // Set Adata Available Flag
    pccm_data->nonce[0] |= 0x40;

    utils::CopyBytes(p_blk0, pccm_data->nonce, 16);

    encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);

    pccm_data->blocks++;

    if (aadLen < (0x10000 - 0x100)) {
        // alen < (2^16 - 2^8)
        *(p_blk0_8 + 0) ^= static_cast<Uint8>(aadLen >> 8);
        *(p_blk0_8 + 1) ^= static_cast<Uint8>(aadLen);
        i = 2;
    } else if (sizeof(aadLen) == 8 && aadLen >= ((size_t)1 << 32)) {
        // alen > what 32 bits can hold.
        *(p_blk0_8 + 0) ^= 0xFF;
        *(p_blk0_8 + 1) ^= 0xFF;
        *(p_blk0_8 + 2) ^= static_cast<Uint8>(aadLen >> 56);
        *(p_blk0_8 + 3) ^= static_cast<Uint8>(aadLen >> 48);
        *(p_blk0_8 + 4) ^= static_cast<Uint8>(aadLen >> 40);
        *(p_blk0_8 + 5) ^= static_cast<Uint8>(aadLen >> 32);
        *(p_blk0_8 + 6) ^= static_cast<Uint8>(aadLen >> 24);
        *(p_blk0_8 + 7) ^= static_cast<Uint8>(aadLen >> 16);
        *(p_blk0_8 + 8) ^= static_cast<Uint8>(aadLen >> 8);
        *(p_blk0_8 + 9) ^= static_cast<Uint8>(aadLen);
        i = 10;
    } else {
        // alen is represented by 32 bits but larger than
        // what 16 bits can hold
        *(p_blk0_8 + 0) ^= 0xFF;
        *(p_blk0_8 + 1) ^= 0xFE;
        *(p_blk0_8 + 2) ^= static_cast<Uint8>(aadLen >> 24);
        *(p_blk0_8 + 3) ^= static_cast<Uint8>(aadLen >> 16);
        *(p_blk0_8 + 4) ^= static_cast<Uint8>(aadLen >> 8);
        *(p_blk0_8 + 5) ^= static_cast<Uint8>(aadLen);
        i = 6;
    }

    // i=2,6,10 to i=16 do the CBC operation
    for (; i < 16 && aadLen; ++i, ++paad, --aadLen)
        *(p_blk0_8 + i) ^= *paad;

    encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);
    pccm_data->blocks++;

    Uint64 alen_16 = aadLen / 16;
    for (Uint64 j = 0; j < alen_16; j++) {
        utils::CopyBytes(aad_32, paad, 16);
        // CBC XOR Operation
        for (int i = 0; i < 4; i++) {
            p_blk0[i] ^= aad_32[i];
        }
        // CBC Encrypt Operation
        encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);
        pccm_data->blocks++;
        paad += 16;
    }

    // Reduce already processed value from alen
    aadLen -= alen_16 * 16;

    if (aadLen != 0) {
        // Process the rest in the default way
        for (i = 0; i < 16 && aadLen; i++, paad++, aadLen--) {
            *(p_blk0_8 + i) ^= *paad;
        }

        // CBC Encrypt last block
        encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);
        pccm_data->blocks++;
    }

    // Store generated partial tag (cmac)
    utils::CopyBlock(pccm_data->cmac, p_blk0_8, 16);
    return s;
}
#endif
// Auth class definitions
alc_error_t
CcmHash::setTagLength(alc_cipher_data_t* ctx, Uint64 tagLen)
{
    Status s = StatusOk();
    if (ctx == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s.code();
    }
    if (tagLen < 4 || tagLen > 16) {
        s = status::InvalidValue("Length of tag should be 4 < len < 16 ");
        return s.code();
    }
    // Stored to verify in the getTagLength API
    m_tagLen = tagLen;
    return s.code();
}

alc_error_t
CcmHash::setAad(alc_cipher_data_t* ctx, const Uint8* pInput, Uint64 aadLen)
{

    m_additionalData    = pInput;
    m_additionalDataLen = aadLen;

    return ALC_ERROR_NONE;
}

alc_error_t
CcmHash::getTag(alc_cipher_data_t* ctx, Uint8* pOutput, Uint64 tagLen)
{
#ifdef CCM_MULTI_UPDATE
    Status s = StatusOk();
    if (ctx == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s.code();
    }
    // Check if total updated data so far has exceeded the preestablished
    // plaintext Length. This check is here rather than in encrypt/decrypt to
    // allow multiupdate calls in benchmarking.
    if (m_updatedLength > m_plainTextLength) {
        return ALC_ERROR_INVALID_DATA;
    }
    if (tagLen < 4 || tagLen > 16 || tagLen == 0) {
        s = status::InvalidValue(
            "Tag length is not what we agreed upon during start!");
        return s.code();
    }
    // If tagLen is 0 that means something seriously went south
    if (m_tagLen == 0) {
        s = status::InvalidValue(
            "Tag length is unknown!, need to agree on tag before hand!");
    } else {

        if (CpuId::cpuHasAesni()) {
            aesni::ccm::Finalize(&m_ccm_data);
        } else {
            s.update(Ccm::finalizeRef(&m_ccm_data));
        }
        s.update(Ccm::getTagRef(&m_ccm_data, pOutput, tagLen));
    }
    return s.code();
#else
    Status s = StatusOk();
    if (ctx == nullptr) {
        s = status::InvalidValue("Null Pointer is not expected!");
        return s.code();
    }
    if (tagLen < 4 || tagLen > 16 || tagLen == 0) {
        s = status::InvalidValue(
            "Tag length is not what we agreed upon during start!");
        return s.code();
    }
    // If tagLen is 0 that means something seriously went south
    if (m_tagLen == 0) {
        s = status::InvalidValue(
            "Tag length is unknown!, need to agree on tag before hand!");
    } else {
        s.update(Ccm::getTagRef(&m_ccm_data, pOutput, tagLen));
    }
    return s.code();
#endif
}

alc_error_t
CcmHash::init(alc_cipher_data_t* ctx,
              const Uint8*       pKey,
              Uint64             keyLen,
              const Uint8*       pIv,
              Uint64             ivLen)
{
    int t = m_tagLen;
    int q = 15 - ivLen;

    if (pKey == nullptr && pIv == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }

    alc_error_t err = Aes::init(ctx, pKey, keyLen, pIv, ivLen);
    if (alcp_is_error(err)) {
        return err;
    }
    if (pKey != nullptr) {

        const Uint8* p_keys  = getEncryptKeys();
        const Uint32 cRounds = m_nrounds;
        m_ccm_data.key       = p_keys;
        m_ccm_data.rounds    = cRounds;
    }

    // if (pKey != nullptr) {
    //     Aes::init(ctx, pKey, keyLen, nullptr, 0);
    // }
    // if (pIv != nullptr) {
    //     Aes::init(ctx, nullptr, 0, pIv, ivLen)
    // }
#ifdef CCM_MULTI_UPDATE
    if (ivLen != 0 && (m_is_plaintext_len_set == false)) {
        return ALC_ERROR_BAD_STATE;
    }
#endif
    if (ivLen != 0 && m_tagLen != 0) {
        if (ivLen < 7 || ivLen > 13) {
            // s = status::InvalidValue(
            //     "IV length needs to be between 7 and 13 both not included!");
            return ALC_ERROR_INVALID_SIZE;
        }
        // Initialize ccm_data
        // m_ccm_data.blocks = 0;
        // m_ccm_data.key    = nullptr;
        // m_ccm_data.rounds = 0;
        memset(m_ccm_data.cmac, 0, 16);
        memset(m_ccm_data.nonce, 0, 16);
        // 15 = n + q where n is size of nonce (iv) and q is the size of
        // size in bytes of size in bytes of plaintext. Basically size of the
        // variable which can store size of plaintext. This size can be fixed to
        // a max of q = 15 - n.
        std::fill(
            m_ccm_data.nonce, m_ccm_data.nonce + sizeof(m_ccm_data.nonce), 0);
        std::fill(
            m_ccm_data.cmac, m_ccm_data.cmac + sizeof(m_ccm_data.cmac), 0);
        m_ccm_data.nonce[0] = (static_cast<Uint8>(q - 1) & 7)
                              | static_cast<Uint8>(((t - 2) / 2) & 7) << 3;

#ifdef CCM_MULTI_UPDATE
        setIv(&(m_ccm_data), pIv, ivLen);
#endif
    }
    m_ccm_data.blocks = 0;
    return ALC_ERROR_NONE;
}
// Aead class definitions
namespace vaes512 {
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead128, encrypt, cryptUpdate, ALCP_ENC)
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead128, decrypt, cryptUpdate, ALCP_DEC)

    CRYPT_AEAD_WRAPPER_FUNC(CcmAead192, encrypt, cryptUpdate, ALCP_ENC)
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead192, decrypt, cryptUpdate, ALCP_DEC)

    CRYPT_AEAD_WRAPPER_FUNC(CcmAead256, encrypt, cryptUpdate, ALCP_ENC)
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead256, decrypt, cryptUpdate, ALCP_DEC)
} // namespace vaes512

namespace vaes {
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead128, encrypt, cryptUpdate, ALCP_ENC)
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead128, decrypt, cryptUpdate, ALCP_DEC)

    CRYPT_AEAD_WRAPPER_FUNC(CcmAead192, encrypt, cryptUpdate, ALCP_ENC)
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead192, decrypt, cryptUpdate, ALCP_DEC)

    CRYPT_AEAD_WRAPPER_FUNC(CcmAead256, encrypt, cryptUpdate, ALCP_ENC)
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead256, decrypt, cryptUpdate, ALCP_DEC)
} // namespace vaes

namespace aesni {
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead128, encrypt, cryptUpdate, ALCP_ENC)
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead128, decrypt, cryptUpdate, ALCP_DEC)

    CRYPT_AEAD_WRAPPER_FUNC(CcmAead192, encrypt, cryptUpdate, ALCP_ENC)
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead192, decrypt, cryptUpdate, ALCP_DEC)

    CRYPT_AEAD_WRAPPER_FUNC(CcmAead256, encrypt, cryptUpdate, ALCP_ENC)
    CRYPT_AEAD_WRAPPER_FUNC(CcmAead256, decrypt, cryptUpdate, ALCP_DEC)
} // namespace aesni

} // namespace alcp::cipher