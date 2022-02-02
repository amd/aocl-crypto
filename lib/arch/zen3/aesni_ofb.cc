/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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
#include <cstdint>
#include <immintrin.h>
#include <wmmintrin.h>

#include "cipher/aes.hh"
#include "error.hh"
#include "key.hh"
#include "aesni_macros.hh"
#include "cipher/aesni.hh"

namespace alcp::cipher::aesni {

/*
    OFB mode encrypt and decrypt is same.
    We re-use cryptOfb() for both

    */
#if !SINGLE_KEY_LOAD

alc_error_t
cryptOfb(  const uint8_t* pInputText,  // ptr to inputText
           uint8_t*       pOutputText, // ptr to outputtext
           uint64_t       len,         // message length in bytes
           const uint8_t* pKey,        // ptr to Key
           int            nRounds,     // No. of rounds
           const uint8_t* pIv          // ptr to Initialization Vector
)
{
    alc_error_t err = ALC_ERROR_NONE;
    int blocks = len / AES_BLOCK_SIZE(128);
    __m128i a1;//plaintext data
    __m128i b1;
    int i = 0;
    __m128i* pInput128  = (__m128i*)pInputText;
    __m128i* pOutput128 = (__m128i*)pOutputText;
    __m128i* pkey128    = (__m128i*)pKey;

	b1 = _mm_loadu_si128((__m128i*)pIv);

	/*
	Effective usage of two 128bit AESENC pipe is not done, since
	OFB has dependency on previous output.
	*/

	for (i = 0; i < blocks; i++) {
		a1 = _mm_loadu_si128(pInput128);//plaintext
		//10 rounds
		aesni::AesEncrypt(&b1, pkey128, nRounds);

		a1 = _mm_xor_si128(a1, b1);// cipher = plaintext xor AESENCoutput
		_mm_storeu_si128(pOutput128, a1);
		pInput128++;
		pOutput128++;
	}

    return err;
}

#else

//SINGLE_KEY_LOAD

alc_error_t
cryptOfb(  const uint8_t* pInputText,  // ptr to inputText
           uint8_t*       pOutputText, // ptr to outputtext
           uint64_t       len,         // message length in bytes
           const uint8_t* pKey,        // ptr to Key
           int            nRounds,     // No. of rounds
           const uint8_t* pIv          // ptr to Initialization Vector
)
{
    alc_error_t err = ALC_ERROR_NONE;
    int blocks = len / AES_BLOCK_SIZE(128);
    __m128i a1;//plaintext data
    __m128i b1;
    int i = 0;
    __m128i* pInput128  = (__m128i*)pInputText;
    __m128i* pOutput128 = (__m128i*)pOutputText;
    __m128i* pkey128    = (__m128i*)pKey;

	/*
     * load first 10 keys in xmm register
     * 2 or 4 extra keys are loaded based on nRounds
     */
	ALCP_AES_LOAD_KEYS_10_ROUND_XMM(pkey128)

	b1 = _mm_loadu_si128((__m128i*)pIv);

	/*
	* loading of keys are minimized for 10,12 and 14 round
	* Effective usage of two 128bit AESENC pipe is not done, since
	* OFB has dependency on previous output.
	*/
	if (nRounds == 10)
	{
        //11 xmm registers for keys + 2 xmm registers used.
        for (i = 0; i < blocks; i++) {
            a1 = _mm_loadu_si128(pInput128);
            b1 = _mm_xor_si128(b1, key_128_0);

            ALCP_AESENC_128BIT_10ROUND_LAST(b1, key_128)
            /* cipher = plaintext xor AESENCoutput*/
            a1 = _mm_xor_si128(a1, b1);
            _mm_storeu_si128(pOutput128, a1);
            pInput128++;
            pOutput128++;
	    }
	}
	else if (nRounds == 12)
	{
        //13 xmm registers for keys + 2 xmm registers used.
        ALCP_AES_LOAD_KEYS_12_ROUND_XMM_EXTRA2(pkey128)
        for (i = 0; i < blocks; i++) {
            a1 = _mm_loadu_si128(pInput128);
            b1 = _mm_xor_si128(b1, key_128_0);

            ALCP_AESENC_128BIT_12ROUND_LAST(b1, key_128)
            /* cipher = plaintext xor AESENCoutput*/
            a1 = _mm_xor_si128(a1, b1);
            _mm_storeu_si128(pOutput128, a1);
            pInput128++;
            pOutput128++;
	    }
	}
	else
	{
        //15 xmm registers for keys + 2 xmm registers used.
        ALCP_AES_LOAD_KEYS_12_ROUND_XMM_EXTRA2(pkey128)
	    ALCP_AES_LOAD_KEYS_14_ROUND_XMM_EXTRA2(pkey128)
        for (i = 0; i < blocks; i++) {
            a1 = _mm_loadu_si128(pInput128);
            b1 = _mm_xor_si128(b1, key_128_0);

            ALCP_AESENC_128BIT_14ROUND_LAST(b1, key_128)
            /* cipher = plaintext xor AESENCoutput*/
            a1 = _mm_xor_si128(a1, b1);
            _mm_storeu_si128(pOutput128, a1);
            pInput128++;
            pOutput128++;
	    }
	}
    return err;
}
#endif

alc_error_t
EncryptOfb(const uint8_t* pPlainText,  // ptr to plaintext
           uint8_t*       pCipherText, // ptr to ciphertext
           uint64_t       len,         // message length in bytes
           const uint8_t* pKey,        // ptr to Key
           int            nRounds,     // No. of rounds
           const uint8_t* pIv          // ptr to Initialization Vector
)
{
    alc_error_t err = ALC_ERROR_NONE;
    err = cryptOfb( pPlainText,  // ptr to inputText
                    pCipherText, // ptr to outputtext
                    len,         // message length in bytes
                    pKey,        // ptr to Key
                    nRounds,     // No. of rounds
                    pIv);        // ptr to Initialization Vector
    return err;
}

alc_error_t
DecryptOfb(const uint8_t* pCipherText, // ptr to ciphertext
           uint8_t*       pPlainText,  // ptr to plaintext
           uint64_t       len,         // message length in bytes
           const uint8_t* pKey,        // ptr to Key
           int            nRounds,     // No. of rounds
           const uint8_t* pIv          // ptr to Initialization Vector
)
{
    alc_error_t err = ALC_ERROR_NONE;
    err = cryptOfb( pCipherText, // ptr to inputText
                    pPlainText,  // ptr to outputtext
                    len,         // message length in bytes
                    pKey,        // ptr to Key
                    nRounds,     // No. of rounds
                    pIv);        // ptr to Initialization Vector
    return err;
}

} // namespace alcp::cipher::aesni