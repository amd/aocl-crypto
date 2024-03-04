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

// Impl Class
class Ccm::Impl
{
  private:
    Uint64       m_len               = 0;
    Uint64       m_ivLen             = 0;
    Uint64       m_tagLen            = 0;
    Uint64       m_additionalDataLen = 0;
    const Uint8* m_additionalData;
    Rijndael*    m_ccm_obj;

    ccm_data_t m_ccm_data;

  public:
    /**
     * @brief Initialize Impl with Ccm class object.
     * @param ccm_obj Object of Ccm class
     */
    Impl(Rijndael* ccm_obj);
    /**
     * @brief Get CCM Tag
     * @param ctx Intermediate Data
     * @param ptag tag memory
     * @param len Length of the tag
     * @return
     */
    Status getTag(ccm_data_t* ctx, Uint8 ptag[], size_t len);

    /**
     * @brief Set Additional Data.
     * @param pccm_data Intermediate Data
     * @param paad Additional Data Pointer
     * @param alen Length of additional data
     */
    Status setAad(ccm_data_t* pccm_data, const Uint8 paad[], size_t alen);

    /**
     * @brief Set IV(nonce)
     * @param ccm_data Intermediate Data
     * @param pnonce Nonce Pointer
     * @param nlen Length of Nonce
     * @param mlen Message length
     * @return
     */
    Status setIv(ccm_data_t* ccm_data,
                 const Uint8 pnonce[],
                 size_t      nlen,
                 size_t      mlen);

    /**
     * @brief Initialize CCM with tag length and Length of (Length of message).
     * @param ccm_data Intermediate Data
     * @param t Length Required to store tag.
     * @param q Length Required to store message.
     */
    void init(ccm_data_t* ccm_data, unsigned int t, unsigned int q);

    /**
     * @brief Do CCM Encryption/Decryption.
     * @param pInput Input PlainText/CipherText.
     * @param pOutput Output CipherText/PlainText.
     * @param len Length of message.
     * @param pIv Nonce(IV) pointer.
     * @param isEncrypt If true will be encrypt mode otherwise decrypt.
     * @return
     */
    Status cryptUpdate(const Uint8 pInput[],
                       Uint8       pOutput[],
                       Uint64      len,
                       const Uint8 pIv[],
                       bool        isEncrypt);

    /**
     * @brief Get the computed tag
     * @param pOutput Output Buffer for Tag
     * @param len Length of Tag
     * @return
     */
    Status getTag(Uint8 pOutput[], Uint64 len);

    /**
     * @brief Set Nonce (IV)
     * @param pIv Pointer to the IV
     * @param ivLen Length of the IV
     * @return
     */
    Status setIv(const Uint8 pIv[], Uint64 ivLen);

    /**
     * @brief Set additional data to be processed
     * @param pInput Additional Data Input Pointer
     * @param len Length of the additional data
     * @return
     */
    Status setAad(const Uint8 pInput[], Uint64 len);

    /**
     * @brief Set the tag length
     * @param len Length of the tag
     * @return
     */
    Status setTagLength(Uint64 len);

    /**
     * @brief Encrypt the Given Data
     * @param pInput Input Buffer
     * @param pOutput  Output Buffer
     * @param len Length of the Buffers
     * @return
     */
    Status encrypt(ccm_data_t* ccm_data,
                   const Uint8 pInput[],
                   Uint8       pOutput[],
                   Uint64      len);

    /**
     * @brief Decrypt the Given Data
     * @param pInput Input Buffer
     * @param pOutput Output Buffer
     * @param len Length of the Buffers
     * @return
     */
    Status decrypt(ccm_data_t* ccm_data,
                   const Uint8 pInput[],
                   Uint8       pOutput[],
                   Uint64      len);
};

// Impl Functions
Ccm::Impl::Impl(Rijndael* ccm_obj)
{
    m_ccm_obj = ccm_obj;
}

Status
Ccm::Impl::cryptUpdate(const Uint8 pInput[],
                       Uint8       pOutput[],
                       Uint64      len,
                       const Uint8 pIv[],
                       bool        isEncrypt)
{
    Status s = StatusOk();
    if ((pInput != NULL) && (pOutput != NULL)) {

        m_len = len;

        const Uint8* p_keys  = m_ccm_obj->getEncryptKeys();
        const Uint32 cRounds = m_ccm_obj->getRounds();
        m_ccm_data.key       = p_keys;
        m_ccm_data.rounds    = cRounds;

        // Below Operations has to be done in order
        s.update(setIv(&m_ccm_data, pIv, m_ivLen, len));

        // Accelerate with AESNI
        if (CpuId::cpuHasAesni()) {
            aesni::ccm::SetAad(
                &m_ccm_data, m_additionalData, m_additionalDataLen);
            if (isEncrypt) {
                CCM_ERROR err =
                    aesni::ccm::Encrypt(&m_ccm_data, pInput, pOutput, len);
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
                    aesni::ccm::Decrypt(&m_ccm_data, pInput, pOutput, len);
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
                memset(pOutput, 0, len);
                return s;
            }
            return s;
        }

        // Fallback to reference
        setAad(&m_ccm_data, m_additionalData, m_additionalDataLen);
        if (isEncrypt) {
            s.update(encrypt(&m_ccm_data, pInput, pOutput, len));
        } else {
            s.update(decrypt(&m_ccm_data, pInput, pOutput, len));
        }
        if (s.ok() != true) {
            // Burn everything
            // FIXME: Need to clear key when errors
            // memset(reinterpret_cast<void*>(m_ccm_data.key), 0, 224);
            memset(m_ccm_data.nonce, 0, 16);
            memset(m_ccm_data.cmac, 0, 16);
            memset(pOutput, 0, len);
            return s;
        }
    } else {
        s = status::InvalidValue("Input or Output Null Pointer!");
    }
    return s;
}

Status
Ccm::Impl::setIv(const Uint8 pIv[], Uint64 ivLen)
{
    Status s = StatusOk();
    if (ivLen < 7 || ivLen > 13) {
        s = status::InvalidValue(
            "IV length needs to be between 7 and 13 both not included!");
        return s;
    }

    m_ivLen = ivLen;

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
    init(&m_ccm_data, m_tagLen, 15 - ivLen);
    return s;
}

Status
Ccm::Impl::setAad(const Uint8 pInput[], Uint64 len)
{
    Status s = StatusOk();

    m_additionalData    = pInput;
    m_additionalDataLen = len;
    return s;
}

// FIXME: To Change this from alc_error_t to Status, it will require a
// parse of whole cipher.
Status
Ccm::Impl::getTag(Uint8 pOutput[], Uint64 len)
{
    Status s = StatusOk();
    if (len < 4 || len > 16 || len == 0) {
        s = status::InvalidValue(
            "Tag length is not what we agreed upon during start!");
        return s;
    }
    // If tagLen is 0 that means something seriously went south
    if (m_tagLen == 0) {
        s = status::InvalidValue(
            "Tag length is unknown!, need to agree on tag before hand!");
    } else {
        s.update(getTag(&m_ccm_data, pOutput, len));
    }
    return s;
}

Status
Ccm::Impl::setTagLength(Uint64 len)
{
    Status s = StatusOk();
    if (len < 4 || len > 16) {
        s = status::InvalidValue("Length of tag should be 4 < len < 16 ");
        return s;
    }
    m_tagLen = len;

    return s;
}

void
Ccm::Impl::init(ccm_data_t* ccm_data, unsigned int t, unsigned int q)
{
    // ENTER();
    std::fill(ccm_data->nonce, ccm_data->nonce + sizeof(ccm_data->nonce), 0);
    std::fill(ccm_data->cmac, ccm_data->cmac + sizeof(ccm_data->cmac), 0);
    ccm_data->nonce[0] = (static_cast<Uint8>(q - 1) & 7)
                         | static_cast<Uint8>(((t - 2) / 2) & 7) << 3;
    ccm_data->blocks = 0;
    // EXIT();
}

Status
Ccm::Impl::setIv(ccm_data_t* ccm_data,
                 const Uint8 pnonce[],
                 size_t      nlen,
                 size_t      mlen)
{
    // ENTER();
    Status       s = StatusOk();
    unsigned int q = ccm_data->nonce[0] & 7;

    if (nlen < (14 - q)) {
        // EXITB();
        s = status::InvalidValue("Length of nonce is too small!");
        return s;
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
    return s;
}

Status
Ccm::Impl::getTag(ccm_data_t* ctx, Uint8 ptag[], size_t len)
{
    // ENTER();
    // Retrieve the tag length
    Status       s = StatusOk();
    unsigned int t = (ctx->nonce[0] >> 3) & 7;

    t *= 2;
    t += 2;
    if (len != t) {
        // EXITB();
        s = status::InvalidValue(
            "Tag length is not what we agreed upon during start!");
        return s;
    }
    utils::CopyBytes(ptag, ctx->cmac, t);
    memset(ctx->cmac, 0, len);
    // EXITG();
    return s;
}

Status
Ccm::Impl::setAad(ccm_data_t* pccm_data, const Uint8 paad[], size_t alen)
{
    Status s         = StatusOk();
    Uint32 p_blk0[4] = {};
    Uint32 aad_32[4] = {};
    Uint8* p_blk0_8  = reinterpret_cast<Uint8*>(&p_blk0);
    Uint64 i         = {};

    if (alen == 0) {
        return s; // Nothing to be done
    }

    // Set Adata Available Flag
    pccm_data->nonce[0] |= 0x40;

    utils::CopyBytes(p_blk0, pccm_data->nonce, 16);

    m_ccm_obj->encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);

    pccm_data->blocks++;

    if (alen < (0x10000 - 0x100)) {
        // alen < (2^16 - 2^8)
        *(p_blk0_8 + 0) ^= static_cast<Uint8>(alen >> 8);
        *(p_blk0_8 + 1) ^= static_cast<Uint8>(alen);
        i = 2;
    } else if (sizeof(alen) == 8 && alen >= ((size_t)1 << 32)) {
        // alen > what 32 bits can hold.
        *(p_blk0_8 + 0) ^= 0xFF;
        *(p_blk0_8 + 1) ^= 0xFF;
        *(p_blk0_8 + 2) ^= static_cast<Uint8>(alen >> 56);
        *(p_blk0_8 + 3) ^= static_cast<Uint8>(alen >> 48);
        *(p_blk0_8 + 4) ^= static_cast<Uint8>(alen >> 40);
        *(p_blk0_8 + 5) ^= static_cast<Uint8>(alen >> 32);
        *(p_blk0_8 + 6) ^= static_cast<Uint8>(alen >> 24);
        *(p_blk0_8 + 7) ^= static_cast<Uint8>(alen >> 16);
        *(p_blk0_8 + 8) ^= static_cast<Uint8>(alen >> 8);
        *(p_blk0_8 + 9) ^= static_cast<Uint8>(alen);
        i = 10;
    } else {
        // alen is represented by 32 bits but larger than
        // what 16 bits can hold
        *(p_blk0_8 + 0) ^= 0xFF;
        *(p_blk0_8 + 1) ^= 0xFE;
        *(p_blk0_8 + 2) ^= static_cast<Uint8>(alen >> 24);
        *(p_blk0_8 + 3) ^= static_cast<Uint8>(alen >> 16);
        *(p_blk0_8 + 4) ^= static_cast<Uint8>(alen >> 8);
        *(p_blk0_8 + 5) ^= static_cast<Uint8>(alen);
        i = 6;
    }

    // i=2,6,10 to i=16 do the CBC operation
    for (; i < 16 && alen; ++i, ++paad, --alen)
        *(p_blk0_8 + i) ^= *paad;

    m_ccm_obj->encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);
    pccm_data->blocks++;

    Uint64 alen_16 = alen / 16;
    for (Uint64 j = 0; j < alen_16; j++) {
        utils::CopyBytes(aad_32, paad, 16);
        // CBC XOR Operation
        for (int i = 0; i < 4; i++) {
            p_blk0[i] ^= aad_32[i];
        }
        // CBC Encrypt Operation
        m_ccm_obj->encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);
        pccm_data->blocks++;
        paad += 16;
    }

    // Reduce already processed value from alen
    alen -= alen_16 * 16;

    if (alen != 0) {
        // Process the rest in the default way
        for (i = 0; i < 16 && alen; i++, paad++, alen--) {
            *(p_blk0_8 + i) ^= *paad;
        }

        // CBC Encrypt last block
        m_ccm_obj->encryptBlock(p_blk0, pccm_data->key, pccm_data->rounds);
        pccm_data->blocks++;
    }

    // Store generated partial tag (cmac)
    utils::CopyBlock(pccm_data->cmac, p_blk0_8, 16);
    return s;
}

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

Status
Ccm::Impl::encrypt(ccm_data_t* pccm_data,
                   const Uint8 pinp[],
                   Uint8       pout[],
                   size_t      len)
{
    // Implementation block diagram
    // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_encryption.png
    Status        s = StatusOk();
    size_t        n;
    unsigned int  i, q;
    unsigned char flags0 = pccm_data->nonce[0];
    const Uint8*  p_key  = pccm_data->key;
    Uint32        cmac[4], nonce[4], in_reg[4], temp_reg[4];
    Uint8*        p_cmac_8  = reinterpret_cast<Uint8*>(cmac);
    Uint8*        p_nonce_8 = reinterpret_cast<Uint8*>(nonce);
    Uint8*        p_temp_8  = reinterpret_cast<Uint8*>(temp_reg);

    utils::CopyBytes(nonce, pccm_data->nonce, 16);

    if (!(flags0 & 0x40)) {
        utils::CopyBytes(cmac, nonce, 16);
        m_ccm_obj->encryptBlock(cmac, p_key, pccm_data->rounds);
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
    if (n != len) {
        // EXITB();
        s = status::EncryptFailed("Length of plainText mismatch!");
        return s;
    }

    // Check with everything combined we won't have too many blocks to
    // encrypt
    pccm_data->blocks += ((len + 15) >> 3) | 1;
    if (pccm_data->blocks > (Uint64(1) << 61)) {
        // EXITB();
        s = status::EncryptFailed("Overload of plaintext. Please reduce it!");
        return s;
    }

    while (len >= 16) {
        // Load the PlainText
        utils::CopyBytes(in_reg, pinp, 16);

        /* CBC */
        // Generate CMAC given plaintext by using cbc algorithm
        for (int i = 0; i < 4; i++) {
            cmac[i] ^= in_reg[i];
        }
        m_ccm_obj->encryptBlock(cmac, pccm_data->key, pccm_data->rounds);

        /* CTR */
        // Generate ciphetext given plain text by using ctr algitrithm
        utils::CopyBytes(temp_reg, nonce, 16);
        m_ccm_obj->encryptBlock(temp_reg, pccm_data->key, pccm_data->rounds);
        ctrInc(reinterpret_cast<Uint8*>(nonce)); // Increment counter
        for (int i = 0; i < 4; i++) {
            temp_reg[i] ^= in_reg[i];
        }

        // Store CipherText
        utils::CopyBytes(pout, temp_reg, 16);

        pinp += 16;
        pout += 16;
        len -= 16;
    }
    if (len) {
        /* CBC */
        // For what ever is left, generate block to encrypt using ctr
        for (i = 0; i < len; i++) {
            p_cmac_8[i] ^= pinp[i];
        }
        m_ccm_obj->encryptBlock(cmac, pccm_data->key, pccm_data->rounds);

        /* CTR */
        utils::CopyBytes(temp_reg, nonce, 16);
        m_ccm_obj->encryptBlock(temp_reg, pccm_data->key, pccm_data->rounds);
        for (i = 0; i < len; ++i)
            pout[i] = p_temp_8[i] ^ pinp[i];
    }
    // Zero out counter part
    for (i = 15 - q; i < 16; ++i) // TODO: Optimize this with copy
        p_nonce_8[i] = 0;

    // CTR encrypt first counter and XOR with the partial tag to generate
    // the real tag
    utils::CopyBytes(temp_reg, nonce, 16);
    m_ccm_obj->encryptBlock(temp_reg, pccm_data->key, pccm_data->rounds);

    for (int i = 0; i < 4; i++) {
        cmac[i] ^= temp_reg[i];
    }

    // Restore flags into nonce to restore nonce to original state
    p_nonce_8[0] = flags0;

    // Copy the current state of cmac and nonce back to memory.
    utils::CopyBytes(pccm_data->cmac, cmac, 16);
    utils::CopyBytes(pccm_data->nonce, nonce, 16);

    return s;
}

Status
Ccm::Impl::decrypt(ccm_data_t* pccm_data,
                   const Uint8 pinp[],
                   Uint8       pout[],
                   size_t      len)
{
    // Implementation block diagram
    // https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/CCM_decryption.png
    Status        s = StatusOk();
    size_t        n;
    unsigned int  i, q;
    unsigned char flags0 = pccm_data->nonce[0];
    const Uint8*  p_key  = pccm_data->key;
    Uint32        cmac[4], nonce[4], in_reg[4], temp_reg[4];
    Uint8*        p_cmac_8  = reinterpret_cast<Uint8*>(cmac);
    Uint8*        p_nonce_8 = reinterpret_cast<Uint8*>(nonce);
    Uint8*        p_temp_8  = reinterpret_cast<Uint8*>(temp_reg);

    utils::CopyBytes(nonce, pccm_data->nonce, 16);

    if (!(flags0 & 0x40)) {
        utils::CopyBytes(cmac, nonce, 16);
        m_ccm_obj->encryptBlock(cmac, p_key, pccm_data->rounds);
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
    n |= p_nonce_8[15]; /* reconstructed length */
    p_nonce_8[15] = 1;

    // Check if input length matches the intialized length
    if (n != len) {
        // EXITB();
        s = status::DecryptFailed("Length of plainText mismatch!");
        return s;
    }

    while (len >= 16) {

        /* CTR */
        utils::CopyBytes(temp_reg, nonce, 16);
        m_ccm_obj->encryptBlock(temp_reg, pccm_data->key, pccm_data->rounds);
        ctrInc(reinterpret_cast<Uint8*>(nonce)); // Increment counter

        utils::CopyBytes(in_reg, pinp, 16); // Load CipherText
        // Generate PlainText (Complete CTR)
        for (int i = 0; i < 4; i++) {
            temp_reg[i] ^= in_reg[i];
        }

        /* CBC */
        // Generate Partial result
        for (int i = 0; i < 4; i++) {
            cmac[i] ^= temp_reg[i];
        }

        utils::CopyBytes(pout, temp_reg, 16); // Store plaintext.

        // Generate the partial tag, Xor of CBC is above
        m_ccm_obj->encryptBlock(cmac, pccm_data->key, pccm_data->rounds);

        pinp += 16;
        pout += 16;
        len -= 16;
    }

    if (len) {
        /* CTR */
        utils::CopyBytes(temp_reg, nonce, 16); // Copy Counter
        m_ccm_obj->encryptBlock(temp_reg, pccm_data->key, pccm_data->rounds);

        for (i = 0; i < len; ++i) {
            // CTR XOR operation to generate plaintext
            pout[i] = p_temp_8[i] ^ pinp[i];
            // CBC XOR operation to generate cmac
            p_cmac_8[i] ^= pout[i];
        }

        /* CBC */
        // CBC Xor is above, Encrypt the partial result to create partial
        // tag
        m_ccm_obj->encryptBlock(cmac, pccm_data->key, pccm_data->rounds);
    }

    // Zero out counter part
    for (i = 15 - q; i < 16; ++i) // TODO: Optimize this with copy
        p_nonce_8[i] = 0;

    // CTR encrypt first counter and XOR with the partial tag to generate
    // the real tag
    utils::CopyBlock(temp_reg, nonce, 16);
    m_ccm_obj->encryptBlock(temp_reg, pccm_data->key, pccm_data->rounds);

    for (int i = 0; i < 4; i++) {
        cmac[i] ^= temp_reg[i];
    }

    // Restore flags into nonce to restore nonce to original state
    p_nonce_8[0] = flags0;

    // Copy the current state of cmac and nonce back to memory.
    utils::CopyBlock(pccm_data->cmac, cmac, 16);
    utils::CopyBlock(pccm_data->nonce, nonce, 16);

    return s;
}

// Ccm Functions
Ccm::Ccm()
    : pImpl{ std::make_unique<Impl>(this) }
{}

Ccm::Ccm(const Uint8* pKey, const Uint32 keyLen)
    //: Aes(pKey, keyLen),
    : pImpl{ std::make_unique<Impl>(this) }
{}

alc_error_t
Ccm::decrypt(const Uint8 pInput[],
             Uint8       pOutput[],
             Uint64      len,
             const Uint8 pIv[]) const
{
    Status s = StatusOk();
    s        = pImpl->cryptUpdate(pInput, pOutput, len, pIv, false);
    return s.code();
}

alc_error_t
Ccm::encrypt(const Uint8 pInput[],
             Uint8       pOutput[],
             Uint64      len,
             const Uint8 pIv[]) const
{
    Status s = StatusOk();
    s        = pImpl->cryptUpdate(pInput, pOutput, len, pIv, true);
    return s.code();
}

alc_error_t
Ccm::decryptUpdate(const Uint8 pInput[],
                   Uint8       pOutput[],
                   Uint64      len,
                   const Uint8 pIv[])
{
    Status s = StatusOk();
    s        = pImpl->cryptUpdate(pInput, pOutput, len, pIv, false);
    return s.code();
}

alc_error_t
Ccm::encryptUpdate(const Uint8 pInput[],
                   Uint8       pOutput[],
                   Uint64      len,
                   const Uint8 pIv[])
{
    Status s = StatusOk();
    s        = pImpl->cryptUpdate(pInput, pOutput, len, pIv, true);
    return s.code();
}

alc_error_t
Ccm::getTag(Uint8 pOutput[], Uint64 len)
{
    Status s = StatusOk();
    s        = pImpl->getTag(pOutput, len);
    return s.code();
}

alc_error_t
Ccm::setIv(const Uint8 pIv[], Uint64 ivLen)
{
    Status s = StatusOk();
    s        = pImpl->setIv(pIv, ivLen);
    return s.code();
}

alc_error_t
Ccm::setTagLength(Uint64 len)
{
    Status s = StatusOk();
    s        = pImpl->setTagLength(len);
    return s.code();
}

alc_error_t
Ccm::setAad(const Uint8 pInput[], Uint64 len)
{
    Status s = StatusOk();
    s        = pImpl->setAad(pInput, len);
    return s.code();
}

Ccm::~Ccm() {}

} // namespace alcp::cipher