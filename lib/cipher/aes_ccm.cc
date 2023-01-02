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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "cipher/aes.hh"
#include "cipher/cipher_wrapper.hh"

#include "alcp/utils/cpuid.hh"

#include <immintrin.h>
#include <sstream>
#include <string.h>
#include <wmmintrin.h>

using alcp::utils::CpuId;
namespace alcp::cipher {

alc_error_t
Ccm::decrypt(const Uint8* pInput,
             Uint8*       pOutput,
             Uint64       len,
             const Uint8* pIv) const
{
    return ALC_ERROR_NONE;
}

alc_error_t
Ccm::encrypt(const Uint8* pInput,
             Uint8*       pOutput,
             Uint64       len,
             const Uint8* pIv) const
{
    return ALC_ERROR_NONE;
}

alc_error_t
Ccm::cryptUpdate(const Uint8* pInput,
                 Uint8*       pOutput,
                 Uint64       len,
                 const Uint8* pIv,
                 bool         isEncrypt)
{
    alc_error_t err = ALC_ERROR_NONE;
    if ((pInput != NULL) && (pOutput != NULL)) {

        m_len = len;

#if 0
        bool isAvx512Cap = false;
        if (CpuId::cpuHasVaes()) {
             if (CpuId::cpuHasAvx512(utils::AVX512_F)
                && CpuId::cpuHasAvx512(utils::AVX512_DQ)
                && CpuId::cpuHasAvx512(utils::AVX512_BW)) {
                isAvx512Cap = true;
            }
        }
#endif

        const Uint8* keys   = getEncryptKeys();
        const Uint32 rounds = getRounds();
        m_ccm_data.key      = keys;
        m_ccm_data.rounds   = rounds;

        // Below Operations has to be done in order
        bool err_ret = (CcmSetIv(&m_ccm_data, pIv, m_ivLen, len) == 0);

        // Accelerate with AESNI
        if (CpuId::cpuHasAesni()) {
            aesni::CcmSetAad(
                &m_ccm_data, m_additionalData, m_additionalDataLen);
            if (isEncrypt) {
                err_ret &=
                    (aesni::CcmEncrypt(&m_ccm_data, pInput, pOutput, len) == 0);
            } else {
                err_ret &=
                    (aesni::CcmDecrypt(&m_ccm_data, pInput, pOutput, len) == 0);
            }
            if (!err_ret) {
                err = ALC_ERROR_BAD_STATE;
                // Burn everything
                // FIXME: Need to clear key when errors
                // memset(reinterpret_cast<void*>(m_ccm_data.key), 0, 224);
                memset(m_ccm_data.nonce, 0, 16);
                memset(m_ccm_data.cmac, 0, 16);
                memset(pOutput, 0, len);
                return err;
            }
            err = ALC_ERROR_NONE;
            return err;
        }

        // Fallback to reference
        CcmSetAad(&m_ccm_data, m_additionalData, m_additionalDataLen);
        if (isEncrypt) {
            err_ret &= (CcmEncrypt(&m_ccm_data, pInput, pOutput, len) == 0);
        } else {
            err_ret &= (CcmDecrypt(&m_ccm_data, pInput, pOutput, len) == 0);
        }
        if (!err_ret) {
            err = ALC_ERROR_BAD_STATE;
            // Burn everything
            // FIXME: Need to clear key when errors
            // memset(reinterpret_cast<void*>(m_ccm_data.key), 0, 224);
            memset(m_ccm_data.nonce, 0, 16);
            memset(m_ccm_data.cmac, 0, 16);
            memset(pOutput, 0, len);
            return err;
        }
    } else {
        err = ALC_ERROR_INVALID_ARG;
    }
    return err;
}

alc_error_t
Ccm::decryptUpdate(const Uint8* pInput,
                   Uint8*       pOutput,
                   Uint64       len,
                   const Uint8* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;
    err             = cryptUpdate(pInput, pOutput, len, pIv, false);
    return err;
}

alc_error_t
Ccm::encryptUpdate(const Uint8* pInput,
                   Uint8*       pOutput,
                   Uint64       len,
                   const Uint8* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;
    err             = cryptUpdate(pInput, pOutput, len, pIv, true);
    return err;
}

alc_error_t
Ccm::setIv(Uint64 len, const Uint8* pIv)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (len < 7 || len > 13) {
        err = ALC_ERROR_INVALID_SIZE;
        return err;
    }

    m_ivLen = len;

    // Initialize ccm_data
    m_ccm_data.blocks = 0;
    m_ccm_data.key    = nullptr;
    m_ccm_data.rounds = 0;
    memset(m_ccm_data.cmac, 0, 16);
    memset(m_ccm_data.nonce, 0, 16);
    // 15 = n + q where n is size of nonce (iv) and q is the size of
    // size in bytes of size in bytes of plaintext. Basically size of the
    // variable which can store size of plaintext. This size can be fixed to a
    // max of q = 15 - n.
    CcmInit(&m_ccm_data, m_tagLen, 15 - len);
    return err;
}

alc_error_t
Ccm::setAad(const Uint8* pInput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;

    m_additionalData    = pInput;
    m_additionalDataLen = len;
    return err;
}

alc_error_t
Ccm::getTag(Uint8* pOutput, Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (len < 4 || len > 16 || len == 0) {
        err = ALC_ERROR_INVALID_SIZE;
        return err;
    }
    // If tagLen is 0 that means something seriously went south
    if (m_tagLen == 0) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    } else {
        bool ret = CcmGetTag(&m_ccm_data, pOutput, len);

        if (ret == 0) {
            err = ALC_ERROR_BAD_STATE;
            return err;
        }
    }
    return err;
}

alc_error_t
Ccm::setTagLength(Uint64 len)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (len < 4 || len > 16 || len == 0) {
        err = ALC_ERROR_INVALID_SIZE;
        return err;
    }
    m_tagLen = len;

    return err;
}

void
Ccm::CcmInit(ccm_data_p ccm_data, unsigned int t, unsigned int q)
{
    // ENTER();
    memset(ccm_data->nonce, 0, sizeof(ccm_data->nonce));
    ccm_data->nonce[0] = (static_cast<Uint8>(q - 1) & 7)
                         | static_cast<Uint8>(((t - 2) / 2) & 7) << 3;
    ccm_data->blocks = 0;
    // EXIT();
}

int
Ccm::CcmSetIv(ccm_data_p   ccm_data,
              const Uint8* pnonce,
              size_t       nlen,
              size_t       mlen)
{
    // ENTER();
    unsigned int q = ccm_data->nonce[0] & 7; /* the L parameter */

    if (nlen < (14 - q)) {
        // EXITB();
        return -1; /* nonce is too short */
    }
    if (sizeof(mlen) == 8 && q >= 3) {
        ccm_data->nonce[8]  = static_cast<Uint8>(mlen >> 56);
        ccm_data->nonce[9]  = static_cast<Uint8>(mlen >> 48);
        ccm_data->nonce[10] = static_cast<Uint8>(mlen >> 40);
        ccm_data->nonce[11] = static_cast<Uint8>(mlen >> 32);
    } else {
        memset(ccm_data->nonce + 8, 0, 8);
    }

    ccm_data->nonce[12] = static_cast<Uint8>(mlen >> 24);
    ccm_data->nonce[13] = static_cast<Uint8>(mlen >> 16);
    ccm_data->nonce[14] = static_cast<Uint8>(mlen >> 8);
    ccm_data->nonce[15] = static_cast<Uint8>(mlen);

    ccm_data->nonce[0] &= ~0x40; /* clear Adata flag */
    utils::CopyBytes(&ccm_data->nonce[1], pnonce, 14 - q);
    // EXITG();
    return 0;
}

size_t
Ccm::CcmGetTag(ccm_data_p ctx, Uint8* ptag, size_t len)
{
    // ENTER();
    // Retrieve the tag length
    unsigned int t = (ctx->nonce[0] >> 3) & 7;

    t *= 2;
    t += 2;
    if (len != t) {
        // EXITB();
        return 0;
    }
    utils::CopyBytes(ptag, ctx->cmac, t);
    // EXITG();
    return t;
}

void
Ccm::CcmSetAad(ccm_data_p pccm_data, const Uint8* paad, size_t alen)
{
    Uint32 pBlk0[4]  = {};
    Uint32 aad_32[4] = {};
    Uint8* pBlk0_8   = reinterpret_cast<Uint8*>(&pBlk0);
    Uint64 i         = {};

    if (alen == 0) {
        return;
    }

    // Set Adata Available Flag
    pccm_data->nonce[0] |= 0x40;

    utils::CopyBytes(pBlk0, pccm_data->nonce, 16);

    Rijndael::AesEncrypt(pBlk0, pccm_data->key, pccm_data->rounds);

    pccm_data->blocks++;

    if (alen < (0x10000 - 0x100)) {
        // alen < (2^16 - 2^8)
        *(pBlk0_8 + 0) ^= static_cast<Uint8>(alen >> 8);
        *(pBlk0_8 + 1) ^= static_cast<Uint8>(alen);
        i = 2;
    } else if (sizeof(alen) == 8 && alen >= ((size_t)1 << 32)) {
        // alen > what 32 bits can hold.
        *(pBlk0_8 + 0) ^= 0xFF;
        *(pBlk0_8 + 1) ^= 0xFF;
        *(pBlk0_8 + 2) ^= static_cast<Uint8>(alen >> 56);
        *(pBlk0_8 + 3) ^= static_cast<Uint8>(alen >> 48);
        *(pBlk0_8 + 4) ^= static_cast<Uint8>(alen >> 40);
        *(pBlk0_8 + 5) ^= static_cast<Uint8>(alen >> 32);
        *(pBlk0_8 + 6) ^= static_cast<Uint8>(alen >> 24);
        *(pBlk0_8 + 7) ^= static_cast<Uint8>(alen >> 16);
        *(pBlk0_8 + 8) ^= static_cast<Uint8>(alen >> 8);
        *(pBlk0_8 + 9) ^= static_cast<Uint8>(alen);
        i = 10;
    } else {
        // alen is represented by 32 bits but larger than
        // what 16 bits can hold
        *(pBlk0_8 + 0) ^= 0xFF;
        *(pBlk0_8 + 1) ^= 0xFE;
        *(pBlk0_8 + 2) ^= static_cast<Uint8>(alen >> 24);
        *(pBlk0_8 + 3) ^= static_cast<Uint8>(alen >> 16);
        *(pBlk0_8 + 4) ^= static_cast<Uint8>(alen >> 8);
        *(pBlk0_8 + 5) ^= static_cast<Uint8>(alen);
        i = 6;
    }

    // i=2,6,10 to i=16 do the CBC operation
    for (; i < 16 && alen; ++i, ++paad, --alen)
        *(pBlk0_8 + i) ^= *paad;

    Rijndael::AesEncrypt(pBlk0, pccm_data->key, pccm_data->rounds);
    pccm_data->blocks++;

    Uint64 alen_16 = alen / 16;
    for (Uint64 j = 0; j < alen_16; j++) {
        utils::CopyBytes(aad_32, paad, 16);
        // CBC XOR Operation
        for (int i = 0; i < 4; i++) {
            pBlk0[i] ^= aad_32[i];
        }
        // CBC Encrypt Operation
        Rijndael::AesEncrypt(pBlk0, pccm_data->key, pccm_data->rounds);
        pccm_data->blocks++;
        paad += 16;
    }

    // Reduce already processed value from alen
    alen -= alen_16 * 16;

    if (alen != 0) {
        // Process the rest in the default way
        for (i = 0; i < 16 && alen; i++, paad++, alen--) {
            *(pBlk0_8 + i) ^= *paad;
        }

        // CBC Encrypt last block
        Rijndael::AesEncrypt(pBlk0, pccm_data->key, pccm_data->rounds);
        pccm_data->blocks++;
    }

    // Store generated partial tag (cmac)
    utils::CopyBlock(pccm_data->cmac, pBlk0_8, 16);
}

inline void
CcmCtrInc(Uint8* ctr)
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

int
Ccm::CcmEncrypt(ccm_data_p   pccm_data,
                const Uint8* pinp,
                Uint8*       pout,
                size_t       len)
{
    // Implementation block diagram
    // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_encryption.png
    size_t        n;
    unsigned int  i, q;
    unsigned char flags0 = pccm_data->nonce[0];
    const Uint8*  pkey   = pccm_data->key;
    Uint32        cmac[4], nonce[4], inReg[4], tempReg[4];
    Uint8*        pcmac_8  = reinterpret_cast<Uint8*>(cmac);
    Uint8*        pnonce_8 = reinterpret_cast<Uint8*>(nonce);
    Uint8*        ptemp_8  = reinterpret_cast<Uint8*>(tempReg);

    utils::CopyBytes(nonce, pccm_data->nonce, 16);

    if (!(flags0 & 0x40)) {
        utils::CopyBytes(cmac, nonce, 16);
        Rijndael::AesEncrypt(cmac, pkey, pccm_data->rounds);
        pccm_data->blocks++;
    } else {
        // Additional data exists so load the cmac (already done in encrypt
        // aad)
        utils::CopyBytes(cmac, pccm_data->cmac, 16);
    }

    // Set nonce to just length to store size of plain text
    // extracted from flags
    pnonce_8[0] = q = flags0 & 7;

    // Reconstruct length of plain text
    for (n = 0, i = 15 - q; i < 15; ++i) {
        n |= pnonce_8[i];
        pnonce_8[i] = 0;
        n <<= 8;
    }
    n |= pnonce_8[15]; /* reconstructed length */
    pnonce_8[15] = 1;

    // Check if input length matches the intialized length
    if (n != len) {
        // EXITB();
        return -1; /* length mismatch */
    }

    // Check with everything combined we won't have too many blocks to
    // encrypt
    pccm_data->blocks += ((len + 15) >> 3) | 1;
    if (pccm_data->blocks > (Uint64(1) << 61)) {
        // EXITB();
        return -2; /* too much data */
    }

    while (len >= 16) {
        // Load the PlainText
        utils::CopyBytes(inReg, pinp, 16);

        /* CBC */
        // Generate CMAC given plaintext by using cbc algorithm
        for (int i = 0; i < 4; i++) {
            cmac[i] ^= inReg[i];
        }
        Rijndael::AesEncrypt(cmac, pccm_data->key, pccm_data->rounds);

        /* CTR */
        // Generate ciphetext given plain text by using ctr algitrithm
        utils::CopyBytes(tempReg, nonce, 16);
        Rijndael::AesEncrypt(tempReg, pccm_data->key, pccm_data->rounds);
        CcmCtrInc(reinterpret_cast<Uint8*>(nonce)); // Increment counter
        for (int i = 0; i < 4; i++) {
            tempReg[i] ^= inReg[i];
        }

        // Store CipherText
        utils::CopyBytes(pout, tempReg, 16);

        pinp += 16;
        pout += 16;
        len -= 16;
    }
    if (len) {
        /* CBC */
        // For what ever is left, generate block to encrypt using ctr
        for (i = 0; i < len; i++) {
            pcmac_8[i] ^= pinp[i];
        }
        Rijndael::AesEncrypt(cmac, pccm_data->key, pccm_data->rounds);

        /* CTR */
        utils::CopyBytes(tempReg, nonce, 16);
        Rijndael::AesEncrypt(tempReg, pccm_data->key, pccm_data->rounds);
        for (i = 0; i < len; ++i)
            pout[i] = ptemp_8[i] ^ pinp[i];
    }
    // Zero out counter part
    for (i = 15 - q; i < 16; ++i) // TODO: Optimize this with copy
        pnonce_8[i] = 0;

    // CTR encrypt first counter and XOR with the partial tag to generate
    // the real tag
    utils::CopyBytes(tempReg, nonce, 16);
    Rijndael::AesEncrypt(tempReg, pccm_data->key, pccm_data->rounds);

    for (int i = 0; i < 4; i++) {
        cmac[i] ^= tempReg[i];
    }

    // Restore flags into nonce to restore nonce to original state
    pnonce_8[0] = flags0;

    // Copy the current state of cmac and nonce back to memory.
    utils::CopyBytes(pccm_data->cmac, cmac, 16);
    utils::CopyBytes(pccm_data->nonce, nonce, 16);

    return 0;
}

int
Ccm::CcmDecrypt(ccm_data_p   pccm_data,
                const Uint8* pinp,
                Uint8*       pout,
                size_t       len)
{
    // Implementation block diagram
    // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_decryption.png
    size_t        n;
    unsigned int  i, q;
    unsigned char flags0 = pccm_data->nonce[0];
    const Uint8*  pkey   = pccm_data->key;
    Uint32        cmac[4], nonce[4], inReg[4], tempReg[4];
    Uint8*        pcmac_8  = reinterpret_cast<Uint8*>(cmac);
    Uint8*        pnonce_8 = reinterpret_cast<Uint8*>(nonce);
    Uint8*        ptemp_8  = reinterpret_cast<Uint8*>(tempReg);

    utils::CopyBytes(nonce, pccm_data->nonce, 16);

    if (!(flags0 & 0x40)) {
        utils::CopyBytes(cmac, nonce, 16);
        Rijndael::AesEncrypt(cmac, pkey, pccm_data->rounds);
        pccm_data->blocks++;
    } else {
        // Additional data exists so load the cmac (already done in encrypt
        // aad)
        utils::CopyBytes(cmac, pccm_data->cmac, 16);
    }

    // Set nonce to just length to store size of plain text
    // extracted from flags
    pnonce_8[0] = q = flags0 & 7;

    // Reconstruct length of plain text
    for (n = 0, i = 15 - q; i < 15; ++i) {
        n |= pnonce_8[i];
        pnonce_8[i] = 0;
        n <<= 8;
    }
    n |= pnonce_8[15]; /* reconstructed length */
    pnonce_8[15] = 1;

    // Check if input length matches the intialized length
    if (n != len) {
        // EXITB();
        return -1; /* length mismatch */
    }

    while (len >= 16) {

        /* CTR */
        utils::CopyBytes(tempReg, nonce, 16);
        Rijndael::AesEncrypt(tempReg, pccm_data->key, pccm_data->rounds);
        CcmCtrInc(reinterpret_cast<Uint8*>(nonce)); // Increment counter

        utils::CopyBytes(inReg, pinp, 16); // Load CipherText
        // Generate PlainText (Complete CTR)
        for (int i = 0; i < 4; i++) {
            tempReg[i] ^= inReg[i];
        }

        /* CBC */
        // Generate Partial result
        for (int i = 0; i < 4; i++) {
            cmac[i] ^= tempReg[i];
        }

        utils::CopyBytes(pout, tempReg, 16); // Store plaintext.

        // Generate the partial tag, Xor of CBC is above
        Rijndael::AesEncrypt(cmac, pccm_data->key, pccm_data->rounds);

        pinp += 16;
        pout += 16;
        len -= 16;
    }

    if (len) {
        /* CTR */
        utils::CopyBytes(tempReg, nonce, 16); // Copy Counter
        Rijndael::AesEncrypt(tempReg, pccm_data->key, pccm_data->rounds);

        for (i = 0; i < len; ++i) {
            // CTR XOR operation to generate plaintext
            pout[i] = ptemp_8[i] ^ pinp[i];
            // CBC XOR operation to generate cmac
            pcmac_8[i] ^= pout[i];
        }

        /* CBC */
        // CBC Xor is above, Encrypt the partial result to create partial
        // tag
        Rijndael::AesEncrypt(cmac, pccm_data->key, pccm_data->rounds);
    }

    // Zero out counter part
    for (i = 15 - q; i < 16; ++i) // TODO: Optimize this with copy
        pnonce_8[i] = 0;

    // CTR encrypt first counter and XOR with the partial tag to generate
    // the real tag
    utils::CopyBytes(tempReg, nonce, 16);
    Rijndael::AesEncrypt(tempReg, pccm_data->key, pccm_data->rounds);

    for (int i = 0; i < 4; i++) {
        cmac[i] ^= tempReg[i];
    }

    // Restore flags into nonce to restore nonce to original state
    pnonce_8[0] = flags0;

    // Copy the current state of cmac and nonce back to memory.
    utils::CopyBytes(pccm_data->cmac, cmac, 16);
    utils::CopyBytes(pccm_data->nonce, nonce, 16);

    return 0;
}

} // namespace alcp::cipher
