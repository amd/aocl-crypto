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

template<alc_rsa_key_size T>
class ALCP_API_EXPORT Rsa
{
  public:
    static_assert(T == KEY_SIZE_1024 || T == KEY_SIZE_2048);
    Rsa();
    ~Rsa();
    /**
     * @brief Function encrypt the buffer
     *
     * @param [in]  pText          pointer to Input text
     * @param [in]  textSize       Input text size
     * @param [out] pEncText       pointer to encrypted text
     *
     * @return Status Error code
     */
    Status encryptPublic(const Uint8* pText, Uint64 textSize, Uint8* pEncText);

    /**
     * @brief set the Digest to be used by OAEP encrytion
     * @param [in] digest         Digest class to be used by OAEP encrytion.
     * Should be called before calling encryptPublicOaep
     */
    void setDigestOaep(digest::IDigest* digest);

    /**
     * @brief set the MGF to be used by OAEP encrytion
     * @param [in]  mgf           Digest class to be used by OAEP encrytion.
     * Should be called before calling encryptPublicOaep
     */
    void setMgfOaep(digest::IDigest* mgf);

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
     * @return Status Error code
     */
    Status encryptPublicOaep(const Uint8* pText,
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
     * @return Status Error code
     */
    Status decryptPrivate(const Uint8* pEncText, Uint64 encSize, Uint8* pText);

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
     * @return Status Error code
     */

    Status decryptPrivateOaep(const Uint8* pEncText,
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
     * @return Status Error code
     */
    Status signPrivatePss(bool         check,
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
     * @return Status Error code
     */
    Status verifyPublicPss(const Uint8* pText,
                           Uint64       textSize,
                           const Uint8* pSignedBuff);

    /**
     * @brief Function fetches the public key
     *
     * @param [out] pPublicKey      Refrence to public key structure
     *
     * @return Status Error code
     */

    Status getPublickey(RsaPublicKey& pPublicKey);

    /**
     * @brief Function sets the public key
     *
     * @param [in]  exponent    public exponent
     * @param [in]  mod         pointer to the modulus
     * @param [in]  size        size of modulus
     *
     * @return Status Error code
     */
    Status setPublicKey(const Uint64 exponent,
                        const Uint8* mod,
                        const Uint64 size);

    /**
     * @brief Function sets the public key
     *
     * @param [in]   dp         - pointer to first exponent
     * @param [in]   dq         - pointer to second exponent
     * @param [in]   p          - pointer to first modulus
     * @param [in]   q          - pointer to second modulus
     * @param [in]   qinv       - pointer to inverse of second modulus
     * @param [in]   mod        - pointer to mult of first and second modulus
     * @param [in]   size       - size of modulus
     *
     * @return Status Error code
     */
    Status setPrivateKey(const Uint8* dp,
                         const Uint8* dq,
                         const Uint8* p,
                         const Uint8* q,
                         const Uint8* qinv,
                         const Uint8* mod,
                         const Uint64 size);

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

    RsaPrivateKeyBignum<T> m_priv_key;
    RsaPublicKeyBignum<T>  m_pub_key;
    MontContextBignum<T>   m_context_pub;
    MontContextBignum<T>   m_context_p;
    MontContextBignum<T>   m_context_q;
    Uint64                 m_key_size;
    Uint64                 m_hash_len;
    Uint64                 m_mgf_hash_len;
    digest::IDigest*       m_digest = nullptr;
    digest::IDigest*       m_mgf    = nullptr;
};

} // namespace alcp::rsa
