/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#pragma once

/* C++ headers */
#include "alcp/base.hh"
#include "alcp/rsa.h"
#include "alcp/rsa/rsa_internal.hh"
#include "digest.hh"

namespace alcp::rsa {

struct RsaPublicKey
{
    Uint64 public_exponent = 0;
    Uint8* modulus         = nullptr;
    Uint64 size            = 0;
};

class ALCP_API_EXPORT Rsa
{
  public:
    Rsa() = default;
    ~Rsa();
    Rsa(const Rsa& rsa);
    /**
     * @brief Function encrypt the buffer
     *
     * @param [in]  pText          pointer to Input text
     * @param [in]  textSize       Input text size
     * @param [out] pEncText       pointer to encrypted text
     *
     * @return alc_error_t Error code
     */
    alc_error_t encryptPublic(const Uint8* pText,
                              Uint64       textSize,
                              Uint8*       pEncText);

    /**
     * @brief set the Digest to be used by OAEP / PSS / PKCSV15 padding
     * @param [in] digest         Digest class to be used by OAEP / PSS /
     * PKCSV15 padding.
     */
    void setDigest(digest::IDigest* digest);

    /**
     * @brief set the MGF to be used by OAEP/ PKCSV15 padding
     * @param [in]  mgf           Digest class to be used by OAEP/ PKCSV15
     * padding.
     *
     */
    void setMgf(digest::IDigest* mgf);

    /**
     * @brief Function encrypt the buffer using oaep padding
     *
     * @param [in]  pText          pointer to Input text
     * @param [in]  textSize       Input text size
     * @param [in]  plabel         pointer to initial label
     * @param [in]  labelSize      label size
     * @param [in]  pSeed          pointer to seed with hashlen
     * @param [out] pEncText       pointer to encrypted text
     *
     * @return alc_error_t Error code
     */
    alc_error_t encryptPublicOaep(const Uint8* pText,
                                  Uint64       textSize,
                                  const Uint8* plabel,
                                  Uint64       labelSize,
                                  const Uint8* pSeed,
                                  Uint8*       pEncText);

    /**
     * @brief Function decrypt the buffer
     *
     * @param [in]  pEncText    pointer to encrypted text
     * @param [in]  encSize     encrypted data size
     * @param [out] pText       pointer to decrypted text
     *
     * @return alc_error_t Error code
     */
    alc_error_t decryptPrivate(const Uint8* pEncText,
                               Uint64       encSize,
                               Uint8*       pText);

    /**
     * @brief Function decrypt the buffer with oaep padding
     *
     * @param [in]  pEncText    pointer to encrypted text
     * @param [in]  encSize     encrypted data size
     * @param [in]  label       pointer to initial label
     * @param [in]  labelSize   pointer to label size
     * @param [out] pText       pointer to decrypted text
     * @param [out] textSize    size of decrypted text
     *
     * @return alc_error_t Error code
     */

    alc_error_t decryptPrivateOaep(const Uint8* pEncText,
                                   Uint64       encSize,
                                   const Uint8* label,
                                   Uint64       labelSize,
                                   Uint8*       pText,
                                   Uint64&      textSize);

    /**
     * @brief Function signs the buffer with pss padding
     *
     * @param [in]  check       - signed message verification for fault attack
     * @param [in]  pText       - pointer to input text
     * @param [in]  textSize    - size of input text
     * @param [in]  salt        - pointer to salt
     * @param [in]  saltSize    - size of salt
     * @param [out] pSignedBuff - pointer to signed text
     *
     * @return alc_error_t Error code
     */
    alc_error_t signPrivatePss(bool         check,
                               const Uint8* pText,
                               Uint64       textSize,
                               const Uint8* salt,
                               Uint64       saltSize,
                               Uint8*       pSignedBuff);

    /**
     * @brief Function verifies the buffer with pss padding
     *
     * @param [in] pText       - pointer to input text
     * @param [in] textSize    - size of input text
     * @param [in] pSignedBuff - pointer to signed text
     *
     * @return alc_error_t Error code
     */
    alc_error_t verifyPublicPss(const Uint8* pText,
                                Uint64       textSize,
                                const Uint8* pSignedBuff);

    /**
     * @brief Function signs the hash with pss padding
     *
     * @param [in]  pHash       - pointer to hash
     * @param [in]  hashSize    - size of hash
     * @param [in]  salt        - pointer to salt
     * @param [in]  saltSize    - size of salt
     * @param [out] pSignedBuff - pointer to signed text
     *
     * @return alc_error_t Error code
     */
    alc_error_t signPrivateHashPss(const Uint8* pHash,
                                   Uint64       hashSize,
                                   const Uint8* salt,
                                   Uint64       saltSize,
                                   Uint8*       pSignedBuff);

    /**
     * @brief Function verifies the hash with pss padding
     *
     * @param [in] pHash       - pointer to hash
     * @param [in] hashSize    - size of hash
     * @param [in] pSignedBuff - pointer to signed text
     *
     * @return alc_error_t Error code
     */
    alc_error_t verifyPublicHashPss(const Uint8* pHash,
                                    Uint64       hashSize,
                                    const Uint8* pSignedBuff);

    /**
     * @brief Function signs the buffer with pkcsv15 padding
     *
     * @param [in]  check       - signed message verification for fault
     * attack
     * @param [in]  pText       - pointer to input text
     * @param [in]  textSize    - size of input text
     * @param [out] pSignedBuff - pointer to signed text
     *
     * @return alc_error_t Error code
     */
    alc_error_t signPrivatePkcsv15(bool         check,
                                   const Uint8* pText,
                                   Uint64       textSize,
                                   Uint8*       pSignedBuff);

    /**
     * @brief Function verifies the buffer with pkcsv15 padding
     *
     * @param [in] pText       - pointer to input text
     * @param [in] textSize    - size of input text
     * @param [in] pSignedBuff - pointer to signed text
     *
     * @return alc_error_t Error code
     */
    alc_error_t verifyPublicPkcsv15(const Uint8* pText,
                                    Uint64       textSize,
                                    const Uint8* pSignedBuff);

    /**
     * @brief Function signs the buffer with pkcsv15 padding
     *
     * @param [in]  pHash       - pointer to hash + DigestInfo
     * @param [in]  hashSize    - size of hash
     * @param [out] pSignedBuff - pointer to signed text
     *
     * @return alc_error_t Error code
     */
    alc_error_t signPrivateHashPkcsv15(const Uint8* pHash,
                                       Uint64       hashSize,
                                       Uint8*       pSignedBuff);

    /**
     * @brief Function verifies the buffer with pkcsv15 padding
     *
     * @param [in] pHash       - pointer to hash + digestInfo
     * @param [in] hashSize    - size of hash
     * @param [in] pSignedBuff - pointer to signed text
     *
     * @return alc_error_t Error code
     */
    alc_error_t verifyPublicHashPkcsv15(const Uint8* pHash,
                                        Uint64       hashSize,
                                        const Uint8* pSignedBuff);

    /**
     * @brief Function encrypt the buffer using pkcsv15 padding
     *
     * @param [in]  pText          pointer to Input text
     * @param [in]  textSize       Input text size
     * @param [out] pEncText       pointer to encrypted text
     * @param [in]  randomPad      pointer to random pad
     *
     * @return alc_error_t Error code
     */
    alc_error_t encryptPublicPkcsv15(const Uint8* pText,
                                     Uint64       textSize,
                                     Uint8*       pEncText,
                                     const Uint8* randomPad);

    /**
     * @brief Function decrypt the buffer with pkcs padding
     *
     * @param [in]  pEncText    pointer to encrypted text
     * @param [out] pText       pointer to decrypted text
     * @param [out] textSize    text size
     *
     * @return alc_error_t Error code
     */
    alc_error_t decryptPrivatePkcsv15(const Uint8* pEncText,
                                      Uint8*       pText,
                                      Uint64*      textSize);
    /**
     * @brief Function fetches the public key
     *
     * @param [out] pPublicKey      Refrence to public key structure
     *
     * @return alc_error_t Error code
     */

    alc_error_t getPublickey(RsaPublicKey& pPublicKey);

    /**
     * @brief Function sets the public key
     *
     * @param [in]  exponent    public exponent
     * @param [in]  mod         pointer to the modulus
     * @param [in]  size        size of modulus
     *
     * @return alc_error_t Error code
     */
    alc_error_t setPublicKey(const Uint64 exponent,
                             const Uint8* mod,
                             const Uint64 size);

    /**
     * @brief Function sets the public key in Big num form
     *
     * @param [in]  exponent    pointer to BigNum exponent
     * @param [in]  pModulus    pointer to BigNum modulus
     *
     * @return alc_error_t Error code
     */
    alc_error_t setPublicKeyAsBigNum(const BigNum* exponent,
                                     const BigNum* pModulus);

    /**
     * @brief Function sets the private key
     *
     * @param [in]   dp         - pointer to first exponent
     * @param [in]   dq         - pointer to second exponent
     * @param [in]   p          - pointer to first modulus
     * @param [in]   q          - pointer to second modulus
     * @param [in]   qinv       - pointer to inverse of second modulus
     * @param [in]   mod        - pointer to mult of first and second modulus
     * @param [in]   size       - size of modulus
     *
     * @return alc_error_t Error code
     */
    alc_error_t setPrivateKey(const Uint8* dp,
                              const Uint8* dq,
                              const Uint8* p,
                              const Uint8* q,
                              const Uint8* qinv,
                              const Uint8* mod,
                              const Uint64 size);

    /**
     * @brief Function sets the private key in bignum form
     *
     * @param [in]   dp         - pointer to first Bignum exponent
     * @param [in]   dq         - pointer to second Bignum exponent
     * @param [in]   p          - pointer to first Bignum modulus
     * @param [in]   q          - pointer to second Bignum modulus
     * @param [in]   qinv       - pointer to inverse of Bignum second modulus
     * @param [in]   mod        - pointer to mult of Bignum first and second
     * modulus
     *
     * @return alc_error_t Error code
     */
    alc_error_t setPrivateKeyAsBigNum(const BigNum* dp,
                                      const BigNum* dq,
                                      const BigNum* p,
                                      const BigNum* q,
                                      const BigNum* qinv,
                                      const BigNum* mod);

    /**
     * @brief Function returns the private key size
     *
     * @return The key size in bytes
     */
    Uint64 getKeySize();

    /**
     * @brief Resets the internal state
     */
    void reset();

  private:
    void maskGenFunct(Uint8*       mask,
                      Uint64       maskSize,
                      const Uint8* input,
                      Uint64       inputLen);

    RsaPrivateKeyBignum m_priv_key;
    RsaPublicKeyBignum  m_pub_key;
    MontContextBignum   m_context_pub;
    MontContextBignum   m_context_p;
    MontContextBignum   m_context_q;
    Uint64              m_key_size          = 2048 / 8;
    Uint64              m_hash_len          = 0;
    Uint64              m_mgf_hash_len      = 0;
    DigestIndex         m_digest_info_index = SHA_UNKNOWN;
    Uint64              m_digest_info_size  = 0;
    digest::IDigest*    m_digest            = nullptr;
    digest::IDigest*    m_mgf               = nullptr;
};

} // namespace alcp::rsa
