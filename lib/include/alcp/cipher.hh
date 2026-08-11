/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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

#include "config.h"

#include "alcp/alcp.hh"

#include "alcp/alcp.h"
#include "alcp/base.hh"
#include "alcp/error.h"


#include "alcp/utils/cpuid.hh"

using alcp::utils::CpuArchLevel;

namespace alcp { namespace cipher {
    enum class CipherKeyLen
    {
        eKey128Bit = 128,
        eKey192Bit = 192,
        eKey256Bit = 256
    };

    enum class CipherMode
    {
        eCipherModeNone = 0,
        /* aes ciphers */
        eAesCBC,
        eAesOFB,
        eAesCTR,
        eAesCFB,
        eAesXTS,
        eCHACHA20, // non-aes
        /* aes aead ciphers */
        eAesGCM,
        eAesCCM,
        eAesSIV,
        eCHACHA20_POLY1305, // non-aes
        eCipherModeMax,
    };


    // Base cipher interface
    class iCipher
    {

      public:
        virtual ~iCipher() = default;

        // Set key & iv
        virtual alc_error_t init(const Uint8* pKey,
                                 Uint64       keyLen,
                                 const Uint8* pIv,
                                 Uint64       ivLen) = 0;

        virtual alc_error_t encrypt(const Uint8* pSrc,
                                    Uint8*       pDst,
                                    Uint64       len,
                                    Uint64*      outlen) = 0;

        virtual alc_error_t decrypt(const Uint8* pSrc,
                                    Uint8*       pDst,
                                    Uint64       len,
                                    Uint64*      outlen) = 0;

        virtual alc_error_t CopyCtx(const iCipher* pSrc, iCipher* pDst) = 0;

        virtual alc_error_t finish() = 0;
    };

    /**
     * @brief Interface for multibuffer cipher operations
     *
     * Enables parallel encryption/decryption of multiple independent buffers
     * using a single key but different IVs. Supported only by CBC and CFB modes.
     *
     * Usage:
     *   1. Call multibufferInit() with key and array of IVs
     *   2. Call flush() to queue plaintext buffers
     *   3. Call dequeue() to encrypt and retrieve ciphertext
     *
     * @note This interface is inherited only by cipher classes that support it.
     *       Use dynamic_cast<iMultibuffer*> to check support at runtime.
     */
    class iMultibuffer
    {
      public:
        virtual ~iMultibuffer() = default;

        /**
         * @brief Initialize multibuffer operation with key and multiple IVs
         *
         * @param pKey       Pointer to encryption key
         * @param keyLen     Key length in bits
         * @param pIv        Array of IV pointers (one per buffer)
         * @param ivLen      Length of each IV in bytes
         * @param numBuffers Number of buffers (max 127)
         * @return ALC_ERROR_NONE on success
         */
        virtual alc_error_t multibufferInit(const Uint8*  pKey,
                                            Uint64        keyLen,
                                            const Uint8** pIv,
                                            Uint64        ivLen,
                                            Uint64        numBuffers) = 0;

        /**
         * @brief Primary multi-buffer flush API (variable-length)
         *
         * Implementations must override this. The uniform-length version
         * below provides a default implementation that calls this.
         */
        virtual alc_error_t flush(const Uint8**  pPlainText,
                                  const Uint64*  pLengths,
                                  Uint64         numBuffers)          = 0;

        /**
         * @brief Primary multi-buffer dequeue API (variable-length)
         *
         * Implementations must override this. The uniform-length version
         * below provides a default implementation that calls this.
         */
        virtual alc_error_t dequeue(Uint8**       pCipherText,
                                    Uint64        numBuffers,
                                    const Uint64* pLengths)           = 0;
    };

    // Segmented cipher interface (supports block-level operations)
    class iCipherSegment : public iCipher
    {
      public:
        virtual ~iCipherSegment() = default;

        virtual alc_error_t encryptSegment(const Uint8* pSrc,
                                           Uint8*       pDst,
                                           Uint64       len,
                                           Uint64       startBlockNum) = 0;

        virtual alc_error_t decryptSegment(const Uint8* pSrc,
                                           Uint8*       pDst,
                                           Uint64       len,
                                           Uint64       startBlockNum) = 0;
    };

    // AEAD cipher interface (includes authentication methods)
    class iCipherAead : public iCipher
    {
      public:
        virtual ~iCipherAead() = default;

        // Authentication methods
        virtual alc_error_t setAad(const Uint8* pAad, Uint64 aadLen) = 0;
        virtual alc_error_t getTag(Uint8* pTag, Uint64 tagLen)       = 0;
        virtual alc_error_t setTagLength(Uint64 tagLen)              = 0;
    };

    // CCM-specific interface for plaintext length requirement
    // CCM mode requires knowing the plaintext length before encryption
    class iCipherCcm : public iCipherAead
    {
      public:
        virtual ~iCipherCcm() = default;

        // CCM-specific: set plaintext length before encryption (multi-update)
        virtual alc_error_t setPlainTextLength(Uint64 plaintextLen) = 0;
    };

    /* Direct cipher creation functions */

    /**
     * @brief Create AEAD cipher object directly
     * @param mode Cipher mode (GCM, CCM, SIV, ChaCha20-Poly1305)
     * @param keyLen Key length (128, 192, or 256 bits)
     * @param pCipherState Optional external cipher state (for GCM)
     * @return Pointer to created AEAD cipher, or nullptr on error
     */
    iCipherAead* createCipherAead(
        CipherMode          mode,
        CipherKeyLen        keyLen,
        alc_cipher_state_t* pCipherState = nullptr);

    /**
     * @brief Create non-AEAD cipher object directly
     * @param mode Cipher mode (CBC, CTR, OFB, CFB, XTS, ChaCha20)
     * @param keyLen Key length (128, 192, or 256 bits)
     * @return Pointer to created cipher, or nullptr on error
     */
    iCipher* createCipher(CipherMode   mode,
                                          CipherKeyLen keyLen);

    /**
     * @brief Create cipher with segmented capability
     * @param mode Cipher mode (XTS block mode)
     * @param keyLen Key length (128 or 256 bits)
     * @return Pointer to iCipherSegment, or nullptr on error
     * 
     * @note Use encryptSegment()/decryptSegment() for block-level operations.
     */
    iCipherSegment* createCipherSeg(CipherMode   mode,
                                                    CipherKeyLen keyLen);

}} // namespace alcp::cipher
