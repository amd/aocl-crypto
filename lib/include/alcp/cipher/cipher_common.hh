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

/**
 * @file cipher_common.hh
 * @brief Common components and utilities for cipher operations
 *
 * This file contains focused utility classes that each handle one aspect
 * of cipher operations, following the Single Responsibility Principle.
 *
 * These components are composed into cipher classes (GCM, XTS, CCM, etc.)
 * using composition rather than inheritance.
 *
 * Components:
 * - StateManager: State machine for cipher operation phases
 * - KeyManager: Key storage and validation (no key expansion)
 * - IvManager: IV/nonce storage, validation, and limits
 * - PartialBuffer: Partial block buffering for streaming operations
 * - MultibufferManager: Multiple IV management for parallel encryption
 */

#include "alcp/base.hh"
#include "alcp/cipher.h"
#include "alcp/cipher.hh"
#include "alcp/cipher/rijndael.hh"
#include "alcp/error.h"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"
#include "alcp/utils/memory.hh"

#include <cstdint>
#include <cstring>
#include <immintrin.h>

namespace alcp::cipher {

#define UNROLL_2 _Pragma("GCC unroll 2")
#define UNROLL_8 _Pragma("GCC unroll 8")
#define UNROLL_4 _Pragma("GCC unroll 4")

#define ALCP_ENC               1
#define ALCP_DEC               0
#define MAX_CIPHER_IV_SIZE     (1024 / 8)
#define MAX_CIPHER_BUFFER_SIZE (127)

typedef struct alc_cipher_key_data
{
    const Uint8* m_enc_key; // Pointer to expanded encryption key
    const Uint8* m_dec_key; // Pointer to expanded decryption key
} alc_cipher_key_data_t;

/**
 * @brief Cipher operation state enumeration
 */
enum class CipherState : Uint8
{
    Uninitialized = 0, ///< No key or IV set
    KeySet,            ///< Key set, IV not yet set
    IvSet,             ///< IV set, key not yet set (rare)
    Ready,             ///< Key and IV set, ready for operations
    Processing,        ///< Actively encrypting or decrypting
    Finalized          ///< Operation complete, needs reset for reuse
};

/**
 * @brief Tracks cipher state and validates operation transitions
 *
 * Responsibilities:
 * - Track current cipher state
 * - Validate state transitions
 * - Provide state query methods
 */
class StateManager
{
  public:
    StateManager() = default;

    CipherState getState() const { return m_state; }

    bool isReady() const
    {
        return m_state == CipherState::Ready
            || m_state == CipherState::Processing;
    }

    bool canSetKey() const
    {
        return m_state == CipherState::Uninitialized
            || m_state == CipherState::KeySet
            || m_state == CipherState::Ready
            || m_state == CipherState::Finalized;
    }

    bool canSetIv() const
    {
        return m_state == CipherState::KeySet
            || m_state == CipherState::IvSet
            || m_state == CipherState::Ready
            || m_state == CipherState::Finalized;
    }

    bool canSetAad() const
    {
        return m_state == CipherState::Ready;
    }

    bool canProcess() const
    {
        return m_state == CipherState::Ready
            || m_state == CipherState::Processing;
    }

    bool canFinalize() const
    {
        return m_state == CipherState::Processing
            || m_state == CipherState::Ready;
    }

    void onKeySet()
    {
        if (m_state == CipherState::IvSet || m_state == CipherState::Ready) {
            m_state = CipherState::Ready;
        } else {
            m_state = CipherState::KeySet;
        }
    }

    void onIvSet()
    {
        if (m_state == CipherState::KeySet || m_state == CipherState::Ready
            || m_state == CipherState::Finalized) {
            m_state = CipherState::Ready;
        } else {
            m_state = CipherState::IvSet;
        }
    }

    void onProcessStart()
    {
        if (m_state == CipherState::Ready) {
            m_state = CipherState::Processing;
        }
    }

    void onFinalize()
    {
        m_state = CipherState::Finalized;
    }

    void reset()
    {
        m_state = CipherState::Uninitialized;
    }

  private:
    CipherState m_state = CipherState::Uninitialized;
};

/**
 * @brief Manages key storage, validation, and expansion
 *
 * Responsibilities:
 * - Store original key for comparison
 * - Validate key length
 * - Track key-set state
 * - Perform key expansion via inherited Rijndael
 *
 * Inherits from Rijndael to provide key expansion functionality.
 * When setKey() detects a key change, it automatically expands the key.
 *
 * @note Memory is locked for security.
 */
class KeyManager : public Rijndael
{
  public:
    static constexpr Uint32 cMaxKeyBytes = 32; // 256-bit max

    KeyManager()
        : Rijndael()
    {
        utils::memlock(m_originalKey, cMaxKeyBytes);
    }

    explicit KeyManager(Uint32 expectedKeyLen)
        : Rijndael()
        , m_expectedKeyLen(expectedKeyLen)
    {
        utils::memlock(m_originalKey, cMaxKeyBytes);
    }

    ~KeyManager()
    {
        std::fill(m_originalKey, m_originalKey + cMaxKeyBytes, 0);
        utils::memunlock(m_originalKey, cMaxKeyBytes);
    }

    // Non-copyable (contains sensitive data)
    KeyManager(const KeyManager&)            = delete;
    KeyManager& operator=(const KeyManager&) = delete;

    /**
     * @brief Set, validate, and expand the encryption key
     * @param pKey Pointer to key data
     * @param keyLenBits Key length in bits
     * @return ALC_ERROR_NONE on success
     *
     * This method always expands the key via Rijndael::setKey().
     * The expanded keys can be accessed via getEncryptKeys() and
     * getDecryptKeys().
     */
    alc_error_t setKey(const Uint8* pKey, Uint64 keyLenBits)
    {
        if (pKey == nullptr) {
            return ALC_ERROR_INVALID_ARG;
        }

        if (keyLenBits == 0 || keyLenBits % utils::BitsPerByte != 0
            || keyLenBits > cMaxKeyBytes * utils::BitsPerByte) {
            return ALC_ERROR_INVALID_SIZE;
        }

        Uint32 keyLenBytes = static_cast<Uint32>(keyLenBits / 8);

        // Validate expected key length if set
        if (m_expectedKeyLen > 0 && keyLenBytes != m_expectedKeyLen) {
            return ALC_ERROR_INVALID_SIZE;
        }

        // Copy the key and expand
        utils::CopyBytes(m_originalKey, pKey, keyLenBytes);
        m_keyLenBytes = keyLenBytes;
        m_isKeySet    = true;

        // Expand the key via Rijndael
        Rijndael::setKey(pKey, static_cast<int>(keyLenBits));
        
        // Update cipher key data pointers
        m_cipherKeyData.m_enc_key = getEncryptKeys();
        m_cipherKeyData.m_dec_key = getDecryptKeys();

        return ALC_ERROR_NONE;
    }

    void setExpectedKeyLen(Uint32 keyLenBytes)
    {
        m_expectedKeyLen = keyLenBytes;
    }

    bool         isKeySet() const { return m_isKeySet; }
    Uint32       getKeyLenBytes() const { return m_keyLenBytes; }
    Uint32       getKeyLenBits() const { return m_keyLenBytes * 8; }
    const Uint8* getOriginalKey() const { return m_originalKey; }
    
    /**
     * @brief Get cipher key data containing pointers to expanded keys
     * @return Reference to cipher key data struct
     * @note Auto-populated during setKey() after key expansion
     */
    const alc_cipher_key_data_t& getCipherKeyData() const { return m_cipherKeyData; }

    /**
     * @brief Copy expanded key state from another KeyManager
     * @param src Source KeyManager to copy from
     * 
     * Copies the Rijndael expanded keys and updates cipher key data pointers.
     * Used by CopyCtx to duplicate cipher state.
     */
    void copyKeyStateFrom(const KeyManager& src)
    {
        // Copy Rijndael expanded keys using mutable accessors
        memcpy(getEncryptKeysRoundMut(), src.getEncryptKeysRound(), Rijndael::cRoundKeySize);
        memcpy(getDecryptKeysRoundMut(), src.getDecryptKeysRound(), Rijndael::cRoundKeySize);
        setRounds(src.getRounds());
        
        // Initialize Rijndael key pointers to point to our storage
        initKeyPointers();
        
        // Copy original key and state
        utils::CopyBytes(m_originalKey, src.m_originalKey, src.m_keyLenBytes);
        m_keyLenBytes = src.m_keyLenBytes;
        m_isKeySet    = src.m_isKeySet;
        
        // Update cipher key data pointers to our storage
        m_cipherKeyData.m_enc_key = getEncryptKeys();
        m_cipherKeyData.m_dec_key = getDecryptKeys();
    }

    void reset()
    {
        std::fill(m_originalKey, m_originalKey + cMaxKeyBytes, 0);
        m_keyLenBytes = 0;
        m_isKeySet    = false;
        m_cipherKeyData = {};
    }

    /**
     * @brief Encrypt a single AES block in-place
     * @param block Block to encrypt (4 x Uint32, modified in place)
     * @param pKey Pointer to expanded encryption keys
     * @param nRounds Number of AES rounds
     * 
     * Public wrapper for Rijndael::encryptBlock for use by CMAC and other MACs.
     */
    void encryptBlock(Uint32 (&block)[4], const Uint8* pKey, int nRounds)
    {
        Rijndael::encryptBlock(block, pKey, nRounds);
    }

  private:
    alignas(16) Uint8 m_originalKey[cMaxKeyBytes] = {};
    Uint32            m_keyLenBytes               = 0;
    Uint32            m_expectedKeyLen            = 0; // 0 = any valid length
    bool              m_isKeySet                  = false;
    
    // Cipher key data pointers (auto-populated during setKey)
    alc_cipher_key_data_t m_cipherKeyData{};
};

/**
 * @brief Manages IV/nonce storage with configurable limits
 *
 * Responsibilities:
 * - Store and validate IV/nonce
 * - Enforce min/max length limits
 * - Track IV-set state
 *
 * @note Memory is locked for security.
 */
class IvManager
{
  public:
    static constexpr Uint32 cMaxIvBytes = MAX_CIPHER_IV_SIZE;

    IvManager(Uint32 minLen = 1, Uint32 maxLen = cMaxIvBytes)
        : m_minLen(minLen)
        , m_maxLen(maxLen)
    {
        utils::memlock(m_iv, cMaxIvBytes);
    }

    ~IvManager()
    {
        std::fill(m_iv, m_iv + cMaxIvBytes, 0);
        utils::memunlock(m_iv, cMaxIvBytes);
    }

    // Non-copyable
    IvManager(const IvManager&)            = delete;
    IvManager& operator=(const IvManager&) = delete;

    /**
     * @brief Set the IV/nonce
     * @param pIv Pointer to IV data
     * @param ivLen IV length in bytes
     * @return ALC_ERROR_NONE on success
     */
    alc_error_t setIv(const Uint8* pIv, Uint64 ivLen)
    {
        if (pIv == nullptr) {
            return ALC_ERROR_INVALID_ARG;
        }

        if (ivLen < m_minLen || ivLen > m_maxLen) {
            return ALC_ERROR_INVALID_SIZE;
        }

        utils::CopyBytes(m_iv, pIv, ivLen);
        m_ivLen = ivLen;
        m_isSet = true;
        return ALC_ERROR_NONE;
    }

    void setLimits(Uint32 min, Uint32 max)
    {
        m_minLen = min;
        m_maxLen = max;
    }

    bool         isIvSet() const { return m_isSet; }
    Uint8*       getIv() { return m_iv; }
    const Uint8* getIv() const { return m_iv; }
    Uint64       getIvLen() const { return m_ivLen; }
    Uint32       getMinLen() const { return m_minLen; }
    Uint32       getMaxLen() const { return m_maxLen; }

    void reset()
    {
        std::fill(m_iv, m_iv + cMaxIvBytes, 0);
        m_ivLen = 0;
        m_isSet = false;
    }

  private:
    alignas(16) Uint8 m_iv[cMaxIvBytes] = {};
    Uint64            m_ivLen           = 0;
    Uint32            m_minLen;
    Uint32            m_maxLen;
    bool              m_isSet = false;
};

/**
 * @brief Buffers partial blocks for streaming cipher operations
 *
 * Responsibilities:
 * - Buffer incomplete blocks (0-15 bytes)
 * - Track buffer fill level
 * - Provide append/extract operations
 */
class PartialBuffer
{
  public:
    static constexpr Uint32 cBlockSize = 16;

    PartialBuffer() = default;

    /**
     * @brief Append data to the buffer
     * @param data Data to append
     * @param len Length of data
     * @return Number of bytes actually appended
     */
    Uint32 append(const Uint8* data, Uint64 len)
    {
        Uint32 space    = cBlockSize - m_len;
        Uint32 toAppend = static_cast<Uint32>(len < space ? len : space);
        utils::CopyBytes(m_buffer + m_len, data, toAppend);
        m_len += toAppend;
        return toAppend;
    }

    bool   isFull() const { return m_len == cBlockSize; }
    bool   isEmpty() const { return m_len == 0; }
    Uint32 size() const { return m_len; }
    Uint32 remaining() const { return cBlockSize - m_len; }

    Uint8*       data() { return m_buffer; }
    const Uint8* data() const { return m_buffer; }

    void clear()
    {
        std::fill(m_buffer, m_buffer + cBlockSize, 0);
        m_len = 0;
    }

    /**
     * @brief Extract all buffered data
     * @param dest Destination buffer (must be at least size() bytes)
     * @return Number of bytes extracted
     */
    Uint32 extract(Uint8* dest)
    {
        Uint32 extracted = m_len;
        utils::CopyBytes(dest, m_buffer, m_len);
        clear();
        return extracted;
    }

    /**
     * @brief Set buffer length directly (for restoring state)
     */
    void setLen(Uint32 len)
    {
        m_len = (len <= cBlockSize) ? len : cBlockSize;
    }

  private:
    alignas(16) Uint8 m_buffer[cBlockSize] = {};
    Uint32            m_len                = 0;
};

/**
 * @brief Empty component used as placeholder when a feature is not needed
 *
 * Used with std::conditional_t to compile out unused components.
 * Has minimal footprint (1 byte due to C++ requirements for empty classes).
 */
struct EmptyComponent
{
    // No-op methods to satisfy interface requirements
    constexpr EmptyComponent() noexcept = default;
};

} // namespace alcp::cipher
