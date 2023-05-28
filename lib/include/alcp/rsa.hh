/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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
#include "rng/drbg.hh"

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
    Rsa();
    ~Rsa();
    /**
     * @brief Function encrypt the buffer
     *
     * @param [in]  pad            padding scheme used in RSA
     * @param [in]  pubKey         Reference to public key structure
     * @param [in]  pText          pointer to Input text
     * @param [in]  textSize       Input text size
     * @param [out] pEncText       pointer to encrypted text
     * publicKey
     * @return Status Error code
     */
    Status encryptPublic(alc_rsa_padding     pad,
                         const RsaPublicKey& pubKey,
                         const Uint8*        pText,
                         Uint64              textSize,
                         Uint8*              pEncText);

    /**
     * @brief set the Digest to be used by OAEP encrytion
     * @param digest: Digest class to be used by OAEP encrytion. Should be
     * called before calling encryptPublicOaep
     */
    void setDigestOaep(digest::IDigest* digest);

    /**
     * @brief set the DRBG to be used by OAEP encrytion
     * @param digest: Drbg class to be used by OAEP encrytion. Should be
     * called before calling encryptPublicOaep
     */
    void setDrbgOaep(rng::IDrbg* drbg);

    /**
     * @brief set the MGF to be used by OAEP encrytion
     * @param mgf: Digest class to be used by OAEP encrytion. Should be
     * called before calling encryptPublicOaep
     */
    void setMgfOaep(digest::IDigest* mgf);

    /**
     * @brief Function encrypt the buffer
     *
     * @param [in]  pad            padding scheme used in RSA
     * @param [in]  pubKey         Reference to public key structure
     * @param [in]  pText          pointer to Input text
     * @param [in]  textSize       Input text size
     * @param [out] pEncText       pointer to encrypted text
     * publicKey
     * @return Status Error code
     */
    Status encryptPublicOaep(const RsaPublicKey& pubKey,
                             const Uint8*        pText,
                             Uint64              textSize,
                             const Uint8*        label,
                             Uint64              labelSize,
                             Uint8*              pEncText);

    /**
     * @brief Function decrypt the buffer
     *
     * @param [in]  pad         padding scheme used in RSA
     * @param [in]  pEncText    pointer to encrypted text
     * @param [in]  encSize     encrypted data size
     * @param [out] pText       pointer to decrypted text
     * publicKey
     * @return Status Error code
     */
    Status decryptPrivate(alc_rsa_padding pad,
                          const Uint8*    pEncText,
                          Uint64          encSize,
                          Uint8*          pText);

    Status decryptPrivateOaep(const Uint8* pEncText,
                              Uint64       encSize,
                              const Uint8* label,
                              Uint64       labelSize,
                              Uint8*       pText,
                              Uint64&      textSize);
    /**
     * @brief Function fetches the public key
     *
     * @param [out] pPublicKey      Refrence to public key structure
     * publicKey
     * @return Status Error code
     */

    Status getPublickey(RsaPublicKey& pPublicKey);

    // todo : add documentation
    Status setPublicKey(const Uint64 exponent,
                        const Uint8* mod,
                        const Uint64 size);

    // todo : add documentation
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
    Status maskGenFunct(Uint8*       mask,
                        Uint64       maskSize,
                        const Uint8* input,
                        Uint64       inputLen);

    Uint64              m_key_size;
    RsaPrivateKeyBignum m_priv_key_type2;
    RsaPublicKeyBignum  m_pub_key_2;
    MontContextBignum   m_context_pub, m_context_p, m_context_q;
    digest::IDigest*    m_digest = nullptr;
    rng::IDrbg*         m_drbg   = nullptr;
    digest::IDigest*    m_mgf    = nullptr;
};

} // namespace alcp::rsa
