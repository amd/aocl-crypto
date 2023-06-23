/*
 * Copyright (C) 2021-2023, Advanced Micro Devices. All rights reserved.
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

#ifndef _CIPHER_AES_HH_
#define _CIPHER_AES_HH_ 2

#include "alcp/cipher.h"

// #include "algorithm.hh"
#include "alcp/base.hh"
#include "alcp/cipher.hh"
#include "alcp/cipher/rijndael.hh"
#include "alcp/utils/bits.hh"

#include <immintrin.h>
#include <wmmintrin.h>

#define RIJ_SIZE_ALIGNED(x) ((x * 2) + x)

namespace alcp::cipher {

using Status = alcp::base::Status;

/*
 * @brief       AES (Advanced Encryption Standard)
 *
 * @note       AES is currently same as Rijndael, This may be renamed to
 *              other as well in the future.
 *
 * TODO: We need to move the exception to an init() function. as the constructor
 * is notes fully complete, and exception would cause destructor to be called on
 * object that is not fully constructed
 */
class Aes : public Rijndael
{
  public:
    explicit Aes(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo)
        : Rijndael{ keyInfo }
        , m_mode{ aesInfo.ai_mode }
    {}

    explicit Aes(const Uint8* pKey, const Uint32 keyLen)
        : Rijndael(pKey, keyLen)
    {}

  protected:
    virtual ~Aes() {}

    // FIXME:
    // Without CMAC-SIV extending AES, we cannot access it with protected,
    // Please change to protected if needed in future
  public:
    Aes() { m_this = this; }

    ALCP_API_EXPORT virtual Status setKey(const Uint8* pUserKey,
                                          Uint64       len) override;

  protected:
    ALCP_API_EXPORT virtual Status setMode(alc_cipher_mode_t mode);

  protected:
    alc_cipher_mode_t m_mode;
    void*             m_this;
};

/*
 * @brief        AES Encryption in OFB(Output Feedback)
 * @note        TODO: Move this to a aes_ofb.hh or other
 */
class ALCP_API_EXPORT Ofb final : public Aes
{
  public:
    explicit Ofb(const alc_cipher_algo_info_t& aesInfo,
                 const alc_key_info_t&         keyInfo)
        : Aes(aesInfo, keyInfo)
    {}

    ~Ofb() {}

  public:
    static bool isSupported(const alc_cipher_algo_info_t& cipherInfo,
                            const alc_key_info_t&         keyInfo)
    {
        return true;
    }

    virtual bool isSupported(const alc_cipher_info_t& cipherInfo) override
    {
        if (cipherInfo.ci_type == ALC_CIPHER_TYPE_AES) {
            auto aip = &cipherInfo.ci_algo_info;
            if (aip->ai_mode == ALC_AES_MODE_OFB) {
                return true;
            }
        }

        return false;
    }

    /**
     * @brief   OFB Encrypt Operation
     * @note
     * @param   pPlainText      Pointer to output buffer
     * @param   pCipherText     Pointer to encrypted buffer
     * @param   len             Len of plain and encrypted text
     * @param   pIv             Pointer to Initialization Vector
     * @return  alc_error_t     Error code
     */
    virtual alc_error_t encrypt(const Uint8* pPlainText,
                                Uint8*       pCipherText,
                                Uint64       len,
                                const Uint8* pIv) const final;

    /**
     * @brief   OFB Decrypt Operation
     * @note
     * @param   pCipherText     Pointer to encrypted buffer
     * @param   pPlainText      Pointer to output buffer
     * @param   len             Len of plain and encrypted text
     * @param   pIv             Pointer to Initialization Vector
     * @return  alc_error_t     Error code
     */
    virtual alc_error_t decrypt(const Uint8* pCipherText,
                                Uint8*       pPlainText,
                                Uint64       len,
                                const Uint8* pIv) const final;

  private:
    Ofb(){};

  private:
};

} // namespace alcp::cipher

#endif /* _CIPHER_AES_HH_ */
