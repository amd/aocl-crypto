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

#include "alcp/cipher/chacha20_poly1305.hh"
#include "alcp/base.hh"
#include "alcp/utils/endian.hh"

#include <algorithm>

namespace alcp::cipher {

using mac::poly1305::Poly1305;
using alcp::utils::StoreLittleEndian;

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::setIvInternal(const Uint8* iv, Uint64 ivLen)
{
    if (iv == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (ivLen != 12) {
        return ALC_ERROR_INVALID_SIZE;
    }
    
    // ChaCha20-Poly1305 uses 12-byte nonce with 4-byte counter prefix
    // Store in IvManager via parent class (16 bytes total: 4 counter + 12 nonce)
    Uint8 fullIv[16] = {};
    memset(fullIv, 0, 4);          // Counter = 0
    memcpy(fullIv + 4, iv, ivLen); // Nonce
    
    alc_error_t err = ChaCha256T<arch>::m_ivManager.setIv(fullIv, 16);
    if (err == ALC_ERROR_NONE) {
        ChaCha256T<arch>::m_stateManager.onIvSet();
    }
    return err;
}

template<CpuArchLevel arch>
inline alc_error_t
ChaChPolyT<arch>::initPoly1305Key()
{
    // Set counter to 0 in IV buffer - block 0 is reserved for Poly1305 key gen
    setChaChaCounter(0);

    // Encrypt 32 zero bytes with counter=0 to derive the Poly1305 one-time key
    Uint8   polyKey[32] = {};
    Uint64  outlen      = 0;
    alc_error_t err     =
        ChaCha256T<arch>::encrypt(polyKey, polyKey, 32, &outlen);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    m_len_input_processed.u64 = 0;
    m_len_aad_processed.u64   = 0;

    return Poly1305<arch>::init(polyKey, 32);
}

// RFC 8439 requires AAD to be padded with zeros to a 16-byte boundary
// before feeding ciphertext into Poly1305. This is called once, either
// on the first encrypt/decrypt update or during getTag for AAD-only messages.
template<CpuArchLevel arch>
inline alc_error_t
ChaChPolyT<arch>::padAadToBlockBoundary()
{
    if (m_aadPadded) {
        return ALC_ERROR_NONE;
    }

    const Uint64 aad_remainder = m_len_aad_processed.u64 % 16;
    if (aad_remainder != 0) {
        const Uint64 aad_padding = 16 - aad_remainder;
        alc_error_t  err         = Poly1305<arch>::update(m_zero_padding, aad_padding);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }
    m_aadPadded = true;
    return ALC_ERROR_NONE;
}

// Write the 32-bit block counter into the first 4 bytes of the IV buffer.
// ChaCha20 uses counter=0 for Poly1305 key generation, counter>=1 for message.
template<CpuArchLevel arch>
inline void
ChaChPolyT<arch>::setChaChaCounter(Uint32 counter)
{
    Uint8* pIv = ChaCha256T<arch>::getIv();
    StoreLittleEndian(pIv, counter);
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::init(const Uint8* pKey,
                       Uint64       keyLen,
                       const Uint8* pIv,
                       Uint64       ivLen)
{
    alc_error_t err = ALC_ERROR_NONE;

    // Set IV if provided
    if (pIv != nullptr) {
        err = setIvInternal(pIv, ivLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    } else if (ivLen != 0) {
        // pIv=NULL with non-zero ivLen is invalid
        return ALC_ERROR_INVALID_ARG;
    }

    // Set key if provided
    if (pKey != nullptr) {
        err = ChaCha256T<arch>::setKey(pKey, keyLen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    } else if (keyLen != 0) {
        // key=NULL with non-zero keyLen is invalid
        return ALC_ERROR_INVALID_ARG;
    }

    // Generate Poly1305 key and reset AEAD state when both key and IV are
    // available (either set in this call or stored from a previous call)
    bool haveKey = (pKey != nullptr)
                   || ChaCha256T<arch>::m_keyManager.isKeySet();
    bool haveIv  = (pIv != nullptr)
                   || ChaCha256T<arch>::m_ivManager.isIvSet();

    if (haveKey && haveIv) {
        err = initPoly1305Key();
        if (err != ALC_ERROR_NONE) {
            return err;
        }

        // Reset multi-update state for new AEAD operation.
        if (m_keystreamValid > 0) {
            std::fill(m_keystreamBuffer,
                      m_keystreamBuffer + m_keystreamValid,
                      0);
        }
        m_chacha20Counter = 1;
        m_keystreamOffset = 0;
        m_keystreamValid  = 0;
        m_aadPadded       = false;
    }

    return ALC_ERROR_NONE;
}

// Shared encrypt/decrypt implementation, templated on direction.
// ChaCha20 is a stream cipher: encrypt and decrypt are the same XOR.
// The AEAD difference is Poly1305 authentication ordering:
//   encrypt (isDecrypt=false): Poly1305 processes outputBuffer AFTER XOR
//   decrypt (isDecrypt=true):  Poly1305 processes inputBuffer BEFORE XOR
// The before-XOR ordering for decrypt is required for in-place operation
// where inputBuffer == outputBuffer (XOR overwrites ciphertext with plaintext).
template<CpuArchLevel arch>
template<bool isDecrypt>
alc_error_t
ChaChPolyT<arch>::cryptAndAuth(const Uint8* inputBuffer,
                               Uint8*       outputBuffer,
                               Uint64       bufferLength,
                               Uint64*      outlen)
{
    alc_error_t err = ALC_ERROR_NONE;

    // Zero-length AEAD updates are valid for AAD-only authentication.
    // Only require input/output buffers when there is payload to process.
    if (bufferLength > 0) {
        if (inputBuffer == nullptr || outputBuffer == nullptr) {
            return ALC_ERROR_INVALID_ARG;
        }
    }

    // ChaCha20-Poly1305 authenticates:
    //   AAD || pad16(AAD) || ciphertext || pad16(ciphertext) || lengths
    // Before the first ciphertext bytes are fed, close the AAD section by
    // appending zero padding up to the next 16-byte boundary.
    err = padAadToBlockBoundary();
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    const Uint8* pIn  = inputBuffer;
    Uint8*       pOut = outputBuffer;
    Uint64       processed = 0;
    // Snapshot the call pattern before this update mutates the counter.
    // If prior updates have already produced message keystream, this looks
    // like a multi-update stream and the tail path should refill a full
    // 4-block batch. If this is the first message update, keep the refill
    // sized to this request so single-shot callers do not over-generate
    // keystream that getTag() will immediately wipe.
    const bool   streaming = (m_chacha20Counter > 1);

    // For decrypt, feed ciphertext (input) to Poly1305 BEFORE XOR decryption.
    // This is critical for in-place operation (inputBuffer == outputBuffer)
    // where the XOR would overwrite the ciphertext with plaintext.
    if constexpr (isDecrypt) {
        if (bufferLength > 0) {
            err = Poly1305<arch>::update(inputBuffer, bufferLength);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
        }
    }

    // Drain cached keystream from a previous short update before
    // entering the kernel again. The Zen4 ChaCha20 kernel produces a
    // 4-block batch efficiently; caching the unused bytes lets several
    // short streaming updates share one kernel invocation.
    if (m_keystreamOffset < m_keystreamValid && bufferLength > 0) {
        Uint64 avail = m_keystreamValid - m_keystreamOffset;
        Uint64 use   = (bufferLength < avail) ? bufferLength : avail;
        const Uint8* pKs = m_keystreamBuffer + m_keystreamOffset;
        for (Uint64 i = 0; i < use; i++) {
            pOut[i] = pIn[i] ^ pKs[i];
        }
        m_keystreamOffset += static_cast<Uint32>(use);
        processed += use;
    }

    // Refuse requests that would require counter wrap within one message.
    Uint64 remaining    = bufferLength - processed;
    Uint64 blocksNeeded =
        (remaining + cChaChaBlockSize - 1) / cChaChaBlockSize;
    if (blocksNeeded > UINT32_MAX - m_chacha20Counter) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    // Full 4-block batches go directly through the optimized ChaCha20 kernel.
    if (remaining >= cKsBatchBytes) {
        Uint64 batchBytes = (remaining / cKsBatchBytes) * cKsBatchBytes;
        setChaChaCounter(m_chacha20Counter);
        Uint64 chacha_outlen = 0;
        err                  = ChaCha256T<arch>::encrypt(
            pIn + processed,
            pOut + processed,
            batchBytes,
            &chacha_outlen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        m_chacha20Counter += static_cast<Uint32>(batchBytes / cChaChaBlockSize);
        processed += batchBytes;
    }

    // Handle remaining bytes that don't fill a complete 4-block batch.
    // For the first short update of an operation, generate only enough
    // 64-byte blocks to cover the request. Once the operation has already
    // produced message keystream, assume a streaming caller and refill a
    // full 4-block batch so follow-up short updates drain from cache.
    remaining = bufferLength - processed;
    if (remaining > 0) {
        Uint64 reqBytes = cKsBatchBytes;
        if (!streaming) {
            Uint64 needBlocks =
                (remaining + cChaChaBlockSize - 1) / cChaChaBlockSize;
            reqBytes = needBlocks * cChaChaBlockSize;
        }
        Uint64 reqBlocks = reqBytes / cChaChaBlockSize;
        if (reqBlocks > UINT32_MAX - m_chacha20Counter) {
            return ALC_ERROR_NOT_PERMITTED;
        }

        Uint8 zeros[cKsBatchBytes] = {};
        setChaChaCounter(m_chacha20Counter);

        // Generate keystream by encrypting zeros.
        Uint64 ksOutlen = 0;
        err = ChaCha256T<arch>::encrypt(
            zeros, m_keystreamBuffer, reqBytes, &ksOutlen);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
        m_chacha20Counter += static_cast<Uint32>(reqBlocks);

        // XOR only the remaining bytes with the keystream
        for (Uint64 i = 0; i < remaining; i++) {
            pOut[processed + i] = pIn[processed + i] ^ m_keystreamBuffer[i];
        }

        // Mark how many keystream bytes were consumed; the rest are
        // available for the next update call to resume from
        m_keystreamOffset = static_cast<Uint32>(remaining);
        m_keystreamValid  = static_cast<Uint32>(reqBytes);
    }

    // For encrypt, feed ciphertext (output) to Poly1305 after XOR.
    // Decrypt already fed the ciphertext (input) before XOR above.
    if constexpr (!isDecrypt) {
        if (bufferLength > 0) {
            err = Poly1305<arch>::update(outputBuffer, bufferLength);
            if (err != ALC_ERROR_NONE) {
                return err;
            }
        }
    }

    m_len_input_processed.u64 += bufferLength;
    if (outlen != nullptr) {
        *outlen = bufferLength;
    }
    return ALC_ERROR_NONE;
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::encrypt(const Uint8* inputBuffer,
                          Uint8*       outputBuffer,
                          Uint64       bufferLength,
                          Uint64*      outlen)
{
    // Encrypt: Poly1305 authenticates the ciphertext (outputBuffer) after XOR
    return cryptAndAuth<false>(inputBuffer, outputBuffer, bufferLength, outlen);
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::decrypt(const Uint8* inputBuffer,
                          Uint8*       outputBuffer,
                          Uint64       bufferLength,
                          Uint64*      outlen)
{
    // Decrypt: Poly1305 authenticates the ciphertext (inputBuffer) before XOR
    return cryptAndAuth<true>(inputBuffer, outputBuffer, bufferLength, outlen);
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::setAad(const Uint8* pInput, Uint64 len)
{
    if (pInput == nullptr && len > 0) {
        return ALC_ERROR_INVALID_ARG;
    }
    if (pInput == nullptr) {
        return ALC_ERROR_NONE;
    }
    alc_error_t err = Poly1305<arch>::update(pInput, len);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    m_len_aad_processed.u64 += len;
    return err;
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::getTag(Uint8* pOutput, Uint64 len)
{
    if (pOutput == nullptr) {
        return ALC_ERROR_INVALID_ARG;
    }

    alc_error_t err = ALC_ERROR_NONE;

    // Close the AAD section if not already closed during encrypt/decrypt
    // (handles zero-payload messages where only AAD is authenticated)
    err = padAadToBlockBoundary();
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // Pad ciphertext to 16-byte boundary before appending length fields
    const Uint64 ct_remainder = m_len_input_processed.u64 % 16;
    if (ct_remainder != 0) {
        const Uint64 ct_padding = 16 - ct_remainder;
        err                     = Poly1305<arch>::update(m_zero_padding, ct_padding);
        if (err != ALC_ERROR_NONE) {
            return err;
        }
    }

    // Append little-endian 64-bit AAD and ciphertext lengths
    constexpr Uint64 cSizeLength = sizeof(Uint64);
    err = Poly1305<arch>::update(
        m_len_aad_processed.u8, cSizeLength);
    if (err != ALC_ERROR_NONE) {
        return err;
    }
    err = Poly1305<arch>::update(
        m_len_input_processed.u8, cSizeLength);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // Compute and write the 16-byte authentication tag
    err = Poly1305<arch>::finalize(pOutput, len);

    // AEAD operation is complete. Zero any generated keystream cache
    // to clear residual key-derived material from memory.
    if (m_keystreamValid > 0) {
        std::fill(m_keystreamBuffer,
                  m_keystreamBuffer + m_keystreamValid,
                  0);
        m_keystreamOffset = 0;
        m_keystreamValid  = 0;
    }

    return err;
}

template<CpuArchLevel arch>
alc_error_t
ChaChPolyT<arch>::setTagLength(Uint64 tagLength)
{
    if (tagLength != 16) {
        return ALC_ERROR_INVALID_SIZE;
    }
    return ALC_ERROR_NONE;
}

// Explicit template instantiations
template class ChaChPolyT<CpuArchLevel::eZen4>;
template class ChaChPolyT<CpuArchLevel::eReference>;

} // namespace alcp::cipher
