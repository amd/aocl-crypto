/*
 * Copyright (C) 2024-2026, Advanced Micro Devices. All rights reserved.
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

#include "alcp/cipher/aes_generic.hh"
#include "alcp/cipher/cipher_wrapper.hh"

#include "alcp/utils/bits.hh"
#include <stdexcept>

// Branch prediction hints (no-op on MSVC)
#if defined(__GNUC__) || defined(__clang__)
#define ALCP_EXPECT(x, v) __builtin_expect(!!(x), (v))
#else
#define ALCP_EXPECT(x, v) (x)
#endif

using alcp::utils::CpuId;

namespace alcp::cipher {

template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::multibufferInit(const Uint8* pKey,
                                                            Uint64       keyLen,
                                                            const Uint8** pIv,
                                                            Uint64        ivLen,
                                                            Uint64 numBuffers)
{
    // Only CBC and CFB support multibuffer operations
    if constexpr (!SupportsMultibuffer<mode>) {
        return ALC_ERROR_NOT_SUPPORTED;
    } else {
        if (numBuffers == 0 || ivLen == 0) {
            return ALC_ERROR_INVALID_ARG;
        }

        if (ivLen > 16 || numBuffers > MultibufferStorage::cMaxBufferCount) {
            return ALC_ERROR_INVALID_ARG;
        }

        // Set key via KeyManager (handles comparison and expansion internally)
        if (pKey != nullptr && keyLen != 0) {
            alc_error_t err = m_keyManager.setKey(pKey, keyLen);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
            m_stateManager.onKeySet();
        }

        // Validate and copy IVs to multibuffer storage
        for (Uint64 i = 0; i < numBuffers; ++i) {
            if (pIv[i] == nullptr) {
                return ALC_ERROR_INVALID_ARG;
            }
            utils::CopyBytes(m_multibuffer.m_ivs[i], pIv[i], ivLen);
        }
        m_multibuffer.m_numBuffers = numBuffers;
        
        // Also set the primary IV for single-buffer operations
        m_ivManager.setIv(pIv[0], ivLen);
        m_stateManager.onIvSet();

        return ALC_ERROR_NONE;
    }
}

/**
 * @brief Initialize cipher with key and/or IV
 *
 * This function can be called to set the key alone, iv alone or both together
 */
template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::init(const Uint8* pKey,
                                                  Uint64       keyLen,
                                                  const Uint8* pIv,
                                                  Uint64       ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;

#ifdef AES_MULTI_UPDATE
    // Re-init resets streaming state: any partial block from a previous
    // call must be discarded so the next operation cannot overflow the
    // caller-supplied output buffer.
    m_partialBuffer.clear();
#endif

    // Validate and set IV -- let IvManager reject null/bad length
    if (pIv != nullptr) {
        err = m_ivManager.setIv(pIv, static_cast<Uint32>(ivLen));
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        m_stateManager.onIvSet();
    }

    // Validate and set key -- let KeyManager reject null/bad length
    if (keyLen != 0 || pKey != nullptr) {
        err = m_keyManager.setKey(pKey, keyLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }

        m_stateManager.onKeySet();

        // For non-AEAD modes: If IV was not set in this call and not previously
        // set, use default zero IV. This is done to match OpenSSL's behavior where the
        // IV buffer is zero-initialized and usable by default. By doing this here,
        // we can match OpenSSL's provider layer and not have to do the state management in the provider layer

        if (!m_ivManager.isIvSet()) {
            static constexpr Uint8 zero_iv[16] = { 0 };
            m_ivManager.setIv(zero_iv, 16);
            m_stateManager.onIvSet();
        }
    }

    return err;
}

// flush function to store the multibuffer data to the memory (variable-length version)
template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::flush(const Uint8**  pPlainText,
                                                  const Uint64*  pLengths,
                                                  Uint64         numBuffers)
{
    // Only CBC and CFB support multibuffer
    if constexpr (!SupportsMultibuffer<mode>) {
        return ALC_ERROR_NOT_SUPPORTED;
    } else {
        if (pPlainText == nullptr || pLengths == nullptr) {
            printf("\nError: Invalid input pointer\n");
            return ALC_ERROR_INVALID_ARG;
        }
        if (numBuffers > MAX_CIPHER_BUFFER_SIZE) {
            return ALC_ERROR_INVALID_ARG;
        }

        // Store data pointers and lengths for dequeue
        m_multibuffer.m_pData = pPlainText;
        m_multibuffer.m_numBuffers = numBuffers;
        for (Uint64 i = 0; i < numBuffers; i++) {
            m_multibuffer.m_bufferLengths[i] = pLengths[i];
        }
        return ALC_ERROR_NONE;
    }
}

/**
 * @brief Dequeue processed ciphertext buffers with variable lengths (multi-buffer API)
 *
 * This function implements the **Iterative MinLen Algorithm** for processing multiple
 * buffers with varying lengths while maximizing SIMD parallelism.
 *
 * ## Algorithm Overview
 *
 * The naive approach of processing each buffer individually wastes SIMD lanes. Instead,
 * we use an iterative strategy that keeps all SIMD lanes utilized as long as possible:
 *
 * ```
 * Example with 4 buffers of lengths: [64, 128, 128, 256] bytes
 *
 * Iteration 1: minLen = 64
 *   Process all 4 buffers for 64 bytes (VAES512 - 4 lanes active)
 *   Buffer 0 completes, removed from active list
 *   Remaining: [-, 64, 64, 192]
 *
 * Iteration 2: minLen = 64
 *   Process 3 buffers for 64 bytes (VAES512 + AESNI decomposition)
 *   Buffers 1,2 complete
 *   Remaining: [-, -, -, 128]
 *
 * Iteration 3: Single buffer remains
 *   Process buffer 3 for 128 bytes (AESNI single-buffer path)
 * ```
 *
 * ## Processing Steps
 *
 * 1. **Initialize**: Track active buffer indices and current offsets (all start at 0)
 * 2. **Iterate**: While 2+ buffers active:
 *    - Find minimum remaining length among active buffers
 *    - Process all active buffers for that length using SIMD
 *    - Remove completed buffers from active list
 * 3. **Single Buffer**: If one buffer remains, process with AESNI
 * 4. **Tails**: Process any remaining unaligned bytes individually
 *
 * @param[out] pCipherText  Array of pointers to ciphertext output buffers
 * @param[in]  numBuffers   Number of buffers to process (max 127)
 * @param[in]  pLengths     Array of per-buffer lengths in bytes (or nullptr to use
 *                          lengths from prior flush() call)
 * @return ALC_ERROR_NONE on success, error code otherwise
 *
 * @note This function requires AVX512 VAES support. Falls back to AESNI
 *       single-buffer path on systems without AVX512.
 * @note Only CBC and CFB modes are currently supported for variable-length multi-buffer.
 */
template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::dequeue(Uint8**       pCipherText,
                                                    Uint64        numBuffers,
                                                    const Uint64* pLengths)
{
    // Only CBC and CFB modes support variable-length multi-buffer
    if constexpr (!SupportsMultibuffer<mode>) {
        return ALC_ERROR_NOT_SUPPORTED;
    } else {
        alc_error_t err = ALC_ERROR_NONE;

        // Validate cipher state - key must be set for multibuffer ops
        if (!m_keyManager.isKeySet()) {
            printf("\nError: Key not set\n");
            return ALC_ERROR_BAD_STATE;
        }

        // Require AVX512 VAES for multi-buffer operations
        // AESNI single buffer path is the fallback for all architectures.
        // Don't have to check for aesni support here. since it is already checked in CpuId::getArchLevel(AlgorithmType::eCipher)
        // reference implemetation will never reach here.
        if constexpr (arch < CpuArchLevel::eZen4) {

            const Uint64* actualLengths =
                pLengths ? pLengths : m_multibuffer.m_bufferLengths;

            for (Uint64 i = 0; i < numBuffers; i++) {
                if constexpr (mode == CipherMode::eAesCBC) {
                    err = aesni::EncryptCbc(
                        m_multibuffer.m_pData[i],
                        pCipherText[i],
                        actualLengths[i],
                        m_keyManager.getCipherKeyData().m_enc_key,
                        m_keyManager.getRounds(),
                        m_multibuffer.m_ivs[i]);
                } else { // CipherMode::eAesCFB
                    err = aesni::EncryptCfb(
                        m_multibuffer.m_pData[i],
                        pCipherText[i],
                        actualLengths[i],
                        m_keyManager.getCipherKeyData().m_enc_key,
                        m_keyManager.getRounds(),
                        m_multibuffer.m_ivs[i]);
                }

                if (err != ALC_ERROR_NONE) {
                    return err;
                }
            }
            return ALC_ERROR_NONE;
        }

        // Validate buffer count (must fit in stack-allocated arrays)
        if (__builtin_expect(numBuffers > MAX_CIPHER_BUFFER_SIZE, 0)) {
            return ALC_ERROR_INVALID_ARG;
        }

        // Use provided lengths or fall back to lengths from flush() call
        const Uint64* actualLengths = pLengths ? pLengths : m_multibuffer.m_bufferLengths;
        const Uint8** pData = m_multibuffer.m_pData;

    // Step 1: Initialize active buffer tracking
    // activeIndices: Maps position in processing arrays to original buffer index
    // This allows us to remove completed buffers without reordering original data
    Uint64 activeIndices[MAX_CIPHER_BUFFER_SIZE];
    Uint64 activeCount = numBuffers;
    for (Uint64 i = 0; i < numBuffers; i++) {
        activeIndices[i] = i;
    }

    // Track how many bytes we've processed for each buffer
    Uint64 currentOffsets[MAX_CIPHER_BUFFER_SIZE];
    for (Uint64 i = 0; i < numBuffers; i++) {
        currentOffsets[i] = 0;
    }

    // Step 2: Iterative MinLen processing loop
    // Continue while we have 2+ buffers (can use SIMD parallelism)
    while (activeCount > 2) {
        // Find minimum remaining length among all active buffers
        // This is the amount we can safely process for ALL buffers in parallel
        Uint64 minLen = UINT64_MAX;
        for (Uint64 i = 0; i < activeCount; i++) {
            Uint64 bufIdx = activeIndices[i];
            Uint64 remaining = actualLengths[bufIdx] - currentOffsets[bufIdx];
            if (remaining < minLen) {
                minLen = remaining;
            }
        }

        // Align to AES block boundary (16 bytes)
        // Any remaining bytes < 16 will be handled in Step 4
        minLen = (minLen / 16) * 16;

        // If no aligned data remains, exit loop to process unaligned tails
        if (minLen == 0) {
            break;
        }

        // Power-of-2 decomposition: Process buffers in optimal SIMD batches
        // Example: 5 buffers → batch of 4 (VAES512) + batch of 1 (AESNI)
        // This ensures we always use the widest SIMD path available
        Uint64 processed = 0;
        Uint64 toProcess = activeCount;

        while (toProcess > 0) {
            // Find highest set bit to get largest power-of-2 batch size
            // __builtin_clzll counts leading zeros, so 63 - clz gives bit position
            int i = 63 - __builtin_clzll(toProcess);
            size_t batchCount = static_cast<size_t>(1ULL << i);

            // Prepare contiguous arrays for SIMD processing
            // Map from active buffer positions to original buffer data
            const Uint8* batchInputs[MAX_CIPHER_BUFFER_SIZE];
            Uint8* batchOutputs[MAX_CIPHER_BUFFER_SIZE];
            Uint8* batchIvs[MAX_CIPHER_BUFFER_SIZE];

            for (size_t j = 0; j < batchCount; j++) {
                Uint64 bufIdx = activeIndices[processed + j];
                batchInputs[j] = pData[bufIdx] + currentOffsets[bufIdx];
                batchOutputs[j] = pCipherText[bufIdx] + currentOffsets[bufIdx];
                batchIvs[j] = m_multibuffer.m_ivs[bufIdx];
            }

            // Dispatch to optimal SIMD implementation based on batch size:
            //   i=0 (1 buffer):  AESNI single-buffer
            //   i=1 (2 buffers): VAES256 (2 lanes)
            //   i≥2 (4+ buffers): VAES512 (4 lanes per ZMM register)
            if constexpr (mode == CipherMode::eAesCBC) {
                if (i == 0) {
                    // Single buffer - use aesni
                    err = aesni::EncryptCbc(batchInputs[0],
                                            batchOutputs[0],
                                            minLen,
                                            m_keyManager.getCipherKeyData().m_enc_key,
                                            m_keyManager.getRounds(),
                                            batchIvs[0]);
                } else if (i == 1) {
                    // 2 buffers - use VAES256
                    err = vaes::EncryptCbc(batchInputs,
                                           batchOutputs,
                                           minLen,
                                           m_keyManager.getCipherKeyData().m_enc_key,
                                           m_keyManager.getRounds(),
                                           batchCount,
                                           batchIvs);
                } else {
                    // 4+ buffers - use VAES512
                    err = vaes512::EncryptCbc(batchInputs,
                                              batchOutputs,
                                              minLen,
                                              m_keyManager.getCipherKeyData().m_enc_key,
                                              m_keyManager.getRounds(),
                                              batchCount,
                                              batchIvs);
                }
            } else {  // CipherMode::eAesCFB
                if (i == 0) {
                    // Single buffer - use aesni
                    err = aesni::EncryptCfb(batchInputs[0],
                                            batchOutputs[0],
                                            minLen,
                                            m_keyManager.getCipherKeyData().m_enc_key,
                                            m_keyManager.getRounds(),
                                            batchIvs[0]);
                } else if (i == 1) {
                    // 2 buffers - use VAES256
                    err = vaes::EncryptCfb(batchInputs,
                                           batchOutputs,
                                           minLen,
                                           m_keyManager.getCipherKeyData().m_enc_key,
                                           m_keyManager.getRounds(),
                                           batchCount,
                                           batchIvs);
                } else {
                    // 4+ buffers - use VAES512
                    err = vaes512::EncryptCfb(batchInputs,
                                              batchOutputs,
                                              minLen,
                                              m_keyManager.getCipherKeyData().m_enc_key,
                                              m_keyManager.getRounds(),
                                              batchCount,
                                              batchIvs);
                }
            }

            if (err != ALC_ERROR_NONE) {
                return err;
            }

            // Update offsets for processed buffers
            for (size_t j = 0; j < batchCount; j++) {
                Uint64 bufIdx = activeIndices[processed + j];
                currentOffsets[bufIdx] += minLen;
            }

            processed += batchCount;
            toProcess &= ~(1ULL << i);  // Clear the bit we just processed
        }

        // Compact active buffer list by removing completed buffers
        // A buffer is complete when its offset equals its total length
        Uint64 newActiveCount = 0;
        for (Uint64 i = 0; i < activeCount; i++) {
            Uint64 bufIdx = activeIndices[i];
            if (currentOffsets[bufIdx] < actualLengths[bufIdx]) {
                activeIndices[newActiveCount++] = bufIdx;
            }
        }
        activeCount = newActiveCount;
    }

    // Step 3: Handle single/two remaining buffer
    // When only two buffers remains use VAES Path
    if (activeCount == 2) {
        Uint64 bufIdx0 = activeIndices[0];
        Uint64 bufIdx1 = activeIndices[1];

        Uint64 remaining0 = actualLengths[bufIdx0] - currentOffsets[bufIdx0];
        Uint64 remaining1 = actualLengths[bufIdx1] - currentOffsets[bufIdx1];
        Uint64 minLen = (remaining0 < remaining1 ? remaining0 : remaining1);
        Uint64 alignedLen = (minLen / 16) * 16;

        if (alignedLen > 0) {
            const Uint8* batchInputs[2] = {
                pData[bufIdx0] + currentOffsets[bufIdx0],
                pData[bufIdx1] + currentOffsets[bufIdx1]
            };
            Uint8* batchOutputs[2] = {
                pCipherText[bufIdx0] + currentOffsets[bufIdx0],
                pCipherText[bufIdx1] + currentOffsets[bufIdx1]
            };
            Uint8* batchIvs[2] = {
                m_multibuffer.m_ivs[bufIdx0],
                m_multibuffer.m_ivs[bufIdx1]
            };

            if constexpr (mode == CipherMode::eAesCBC) {
                err = vaes::EncryptCbc(batchInputs,
                                       batchOutputs,
                                       alignedLen,
                                       m_keyManager.getCipherKeyData().m_enc_key,
                                       m_keyManager.getRounds(),
                                       2,
                                       batchIvs);
            } else { // eAesCFB
                err = vaes::EncryptCfb(batchInputs,
                                       batchOutputs,
                                       alignedLen,
                                       m_keyManager.getCipherKeyData().m_enc_key,
                                       m_keyManager.getRounds(),
                                       2,
                                       batchIvs);
            }

            if (err != ALC_ERROR_NONE) {
                return err;
            }

            currentOffsets[bufIdx0] += alignedLen;
            currentOffsets[bufIdx1] += alignedLen;
        }
    }

    // When only one buffer remains, SIMD parallelism isn't beneficial
    // Use single-buffer AESNI path for remaining aligned data
    if (activeCount == 1) {
        Uint64 bufIdx = activeIndices[0];
        Uint64 remaining = actualLengths[bufIdx] - currentOffsets[bufIdx];
        Uint64 alignedLen = (remaining / 16) * 16;

        if (alignedLen > 0) {
            const Uint8* input = pData[bufIdx] + currentOffsets[bufIdx];
            Uint8* output = pCipherText[bufIdx] + currentOffsets[bufIdx];

            if constexpr (mode == CipherMode::eAesCBC) {
                err = aesni::EncryptCbc(input,
                                        output,
                                        alignedLen,
                                        m_keyManager.getCipherKeyData().m_enc_key,
                                        m_keyManager.getRounds(),
                                        m_multibuffer.m_ivs[bufIdx]);
            } else {  // CipherMode::eAesCFB
                err = aesni::EncryptCfb(input,
                                        output,
                                        alignedLen,
                                        m_keyManager.getCipherKeyData().m_enc_key,
                                        m_keyManager.getRounds(),
                                        m_multibuffer.m_ivs[bufIdx]);
            }

            if (err != ALC_ERROR_NONE) {
                return err;
            }

            currentOffsets[bufIdx] += alignedLen;
        }
    }

    // =========================================================================
    // Step 4: Process unaligned tail bytes
    // =========================================================================
    // Any buffer with length not divisible by 16 has remaining bytes
    // These must be processed individually (cannot parallelize partial blocks)
    for (Uint64 i = 0; i < numBuffers; i++) {
        Uint64 remaining = actualLengths[i] - currentOffsets[i];

        if (remaining > 0) {
            const Uint8* tailInput = pData[i] + currentOffsets[i];
            Uint8* tailOutput = pCipherText[i] + currentOffsets[i];

            if constexpr (mode == CipherMode::eAesCBC) {
                err = aesni::EncryptCbc(tailInput,
                                        tailOutput,
                                        remaining,
                                        m_keyManager.getCipherKeyData().m_enc_key,
                                        m_keyManager.getRounds(),
                                        m_multibuffer.m_ivs[i]);
            } else {  // CipherMode::eAesCFB
                err = aesni::EncryptCfb(tailInput,
                                        tailOutput,
                                        remaining,
                                        m_keyManager.getCipherKeyData().m_enc_key,
                                        m_keyManager.getRounds(),
                                        m_multibuffer.m_ivs[i]);
            }

            if (err != ALC_ERROR_NONE) {
                return err;
            }
        }
    }

    return ALC_ERROR_NONE;
    } // end else SupportsMultibuffer
}

template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::encrypt(const Uint8* pInput,
                                                    Uint8*       pOutput,
                                                    Uint64       len,
                                                    Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (pInput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen = 0;
    
    if (!m_stateManager.isReady()) {
        return ALC_ERROR_BAD_STATE;
    }

    Uint8* pIv = m_ivManager.getIv();

    if constexpr (arch < CpuArchLevel::eZen) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    if constexpr (mode == CipherMode::eAesCBC) {
#ifdef AES_MULTI_UPDATE
        // Complete partial block if available
        if (m_partialBuffer.size() > 0 && len > 0) {
            Uint32 need = 16U - m_partialBuffer.size();
            Uint32 take = static_cast<Uint32>(len < static_cast<Uint64>(need)
                                                  ? len
                                                  : static_cast<Uint64>(need));
            m_partialBuffer.append(pInput, take);
            pInput += take;
            len -= take;
            if (m_partialBuffer.isFull()) {
                err = aesni::EncryptCbc(m_partialBuffer.data(),
                                        pOutput,
                                        16,
                                        m_keyManager.getCipherKeyData().m_enc_key,
                                        m_keyManager.getRounds(),
                                        pIv);
                if (err != ALC_ERROR_NONE) {
                    return err;
                }
                pOutput += 16;
                *outlen += 16;
                m_partialBuffer.clear();
            }
        }

        // Process full blocks from remaining input
        Uint64 fullBytes = (len / 16ULL) * 16ULL;
        if (fullBytes > 0) {
            err = aesni::EncryptCbc(pInput,
                                    pOutput,
                                    fullBytes,
                                    m_keyManager.getCipherKeyData().m_enc_key,
                                    m_keyManager.getRounds(),
                                    pIv);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
            pInput += fullBytes;
            pOutput += fullBytes;
            len -= fullBytes;
            *outlen += fullBytes;
        }

        // Buffer trailing bytes (<16)
        if (len > 0) {
            m_partialBuffer.append(pInput, len);
        }

#else
        err = aesni::EncryptCbc(pInput,
                                pOutput,
                                len,
                                m_keyManager.getCipherKeyData().m_enc_key,
                                m_keyManager.getRounds(),
                                pIv);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        *outlen = len;
#endif // AES_MULTI_UPDATE
    } else if constexpr (mode == CipherMode::eAesOFB) {
        err = aesni::EncryptOfb(pInput,
                                pOutput,
                                len,
                                m_keyManager.getCipherKeyData().m_enc_key,
                                m_keyManager.getRounds(),
                                pIv);
    } else if constexpr (mode == CipherMode::eAesCTR) {
        if constexpr (arch == CpuArchLevel::eZen4) {
            err = CryptCtr<keyLenBits, arch>(pInput,
                                             pOutput,
                                             len,
                                             m_keyManager.getCipherKeyData().m_enc_key,
                                             m_keyManager.getRounds(),
                                             pIv);
        } else if constexpr (arch == CpuArchLevel::eZen3) {
            err = vaes::CryptCtr(pInput,
                                 pOutput,
                                 len,
                                 m_keyManager.getCipherKeyData().m_enc_key,
                                 m_keyManager.getRounds(),
                                 pIv);
        } else if constexpr (arch == CpuArchLevel::eZen) {
            err = aesni::CryptCtr(pInput,
                                  pOutput,
                                  len,
                                  m_keyManager.getCipherKeyData().m_enc_key,
                                  m_keyManager.getRounds(),
                                  pIv);
        }
    } else if constexpr (mode == CipherMode::eAesCFB) {
        err = aesni::EncryptCfb(pInput,
                                pOutput,
                                len,
                                m_keyManager.getCipherKeyData().m_enc_key,
                                m_keyManager.getRounds(),
                                pIv);
    }

    // Set output length for stream modes
    if constexpr (mode != CipherMode::eAesCBC) {
        *outlen = len;
    }

    return err;
}

template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::decrypt(const Uint8* pInput,
                                                    Uint8*       pOutput,
                                                    Uint64       len,
                                                    Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (pInput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (outlen == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    *outlen = 0;
    
    if (!m_stateManager.isReady()) {
        return ALC_ERROR_BAD_STATE;
    }

    Uint8* pIv = m_ivManager.getIv();

    if constexpr (arch < CpuArchLevel::eZen) {
        return ALC_ERROR_NOT_SUPPORTED;
    }

    if constexpr (mode == CipherMode::eAesCBC) {
#ifdef AES_MULTI_UPDATE
        // 1) Complete partial block if available
        if (m_partialBuffer.size() > 0 && len > 0) {
            Uint32 need = 16U - m_partialBuffer.size();
            Uint32 take = static_cast<Uint32>(len < static_cast<Uint64>(need)
                                                  ? len
                                                  : static_cast<Uint64>(need));
            m_partialBuffer.append(pInput, take);
            pInput += take;
            len -= take;
            if (m_partialBuffer.isFull()) {
                err = alcp::cipher::tDecryptCbc<keyLenBits, arch>(
                    m_partialBuffer.data(),
                    pOutput,
                    16,
                    m_keyManager.getCipherKeyData().m_dec_key,
                    pIv);
                if (err != ALC_ERROR_NONE) {
                    return err;
                }
                pOutput += 16;
                *outlen += 16;
                m_partialBuffer.clear();
            }
        }

        // 2) Process full blocks from remaining input
        Uint64 fullBytes = (len / 16ULL) * 16ULL;
        if (fullBytes > 0) {
            err = alcp::cipher::tDecryptCbc<keyLenBits, arch>(
                pInput,
                pOutput,
                fullBytes,
                m_keyManager.getCipherKeyData().m_dec_key,
                pIv);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
            pInput += fullBytes;
            pOutput += fullBytes;
            len -= fullBytes;
            *outlen += fullBytes;
        }

        // 3) Buffer trailing bytes (<16)
        if (len > 0) {
            m_partialBuffer.append(pInput, len);
        }

#else
        err = alcp::cipher::tDecryptCbc<keyLenBits, arch>(
            pInput, pOutput, len, m_keyManager.getCipherKeyData().m_dec_key, pIv);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        *outlen = len;
#endif // AES_MULTI_UPDATE
    } else if constexpr (mode == CipherMode::eAesOFB) {
        err = aesni::DecryptOfb(pInput,
                                pOutput,
                                len,
                                m_keyManager.getCipherKeyData().m_enc_key,
                                m_keyManager.getRounds(),
                                pIv);
    } else if constexpr (mode == CipherMode::eAesCTR) {
        if constexpr (arch == CpuArchLevel::eZen4) {
            err = CryptCtr<keyLenBits, arch>(pInput,
                                             pOutput,
                                             len,
                                             m_keyManager.getCipherKeyData().m_enc_key,
                                             m_keyManager.getRounds(),
                                             pIv);
        } else if constexpr (arch == CpuArchLevel::eZen3) {
            err = vaes::CryptCtr(pInput,
                                 pOutput,
                                 len,
                                 m_keyManager.getCipherKeyData().m_enc_key,
                                 m_keyManager.getRounds(),
                                 pIv);
        } else if constexpr (arch == CpuArchLevel::eZen) {
            err = aesni::CryptCtr(pInput,
                                  pOutput,
                                  len,
                                  m_keyManager.getCipherKeyData().m_enc_key,
                                  m_keyManager.getRounds(),
                                  pIv);
        }
    } else if constexpr (mode == CipherMode::eAesCFB) {
        err = DecryptCfb<keyLenBits, arch>(pInput,
                                           pOutput,
                                           len,
                                           m_keyManager.getCipherKeyData().m_enc_key,
                                           m_keyManager.getRounds(),
                                           pIv);
    }

    // Set output length for stream modes
    if constexpr (mode != CipherMode::eAesCBC) {
        *outlen = len;
    }

    return err;
}

template<alcp::cipher::CipherMode       mode,
         alcp::cipher::CipherKeyLen     keyLenBits,
         alcp::utils::CpuArchLevel arch>
alc_error_t
AesGenericCiphersT<mode, keyLenBits, arch>::CopyCtx(const iCipher* pSrc,
                                                    iCipher*       pDst)
{
    if (pSrc == nullptr || pDst == nullptr) {
        return ALC_ERROR_BAD_STATE;
    }

    const auto* src =
        dynamic_cast<const AesGenericCiphersT<mode, keyLenBits, arch>*>(pSrc);
    auto* dst = dynamic_cast<AesGenericCiphersT<mode, keyLenBits, arch>*>(pDst);

    if (src == nullptr || dst == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }

    // Copy key state from source to destination KeyManager
    dst->m_keyManager.copyKeyStateFrom(src->m_keyManager);
    
    // Update state manager to reflect key is set
    dst->m_stateManager.onKeySet();

    // Copy IV from source's IvManager to destination's IvManager
    if (src->m_ivManager.isIvSet()) {
        dst->m_ivManager.setIv(src->m_ivManager.getIv(), src->m_ivManager.getIvLen());
        // Update state manager to reflect IV is set (makes cipher ready)
        dst->m_stateManager.onIvSet();
    }

    return ALC_ERROR_NONE;
}

/* eAesCBC */
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen4>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen4>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen4>;

template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen3>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen3>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen3>;

template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen>;
template class AesGenericCiphersT<CipherMode::eAesCBC,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen>;

/* eAesOFB */
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen4>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen4>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen4>;

template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen3>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen3>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen3>;

template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen>;
template class AesGenericCiphersT<CipherMode::eAesOFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen>;

/* eAesCTR */
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen4>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen4>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen4>;

template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen3>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen3>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen3>;

template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen>;
template class AesGenericCiphersT<CipherMode::eAesCTR,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen>;

/* eAesCFB */
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen4>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen4>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen4>;

template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen3>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen3>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen3>;

template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey128Bit,
                                  CpuArchLevel::eZen>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey192Bit,
                                  CpuArchLevel::eZen>;
template class AesGenericCiphersT<CipherMode::eAesCFB,
                                  alcp::cipher::CipherKeyLen::eKey256Bit,
                                  CpuArchLevel::eZen>;

// other generic modes to be added.

} // namespace alcp::cipher
