/*
 * Copyright (C) 2021-2024, Advanced Micro Devices. All rights reserved.
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
#ifndef _ALCP_CIPHER_H_
#define _ALCP_CIPHER_H_ 2

#include "alcp/error.h"
#include "alcp/key.h"
#include "alcp/macros.h"

// FIXME: to be removed, after using u128
#include <immintrin.h>
#include <wmmintrin.h>

// #define DEBUG_PROV_GCM_INIT 0

EXTERN_C_BEGIN

/**
 * @defgroup cipher Cipher API
 * @brief
 * Cipher is a cryptographic technique used to
 * secure information by transforming message into a cryptic form that can
 * only be read by those with the key to decipher it.
 *  @{
 */

/**
 *
 * @brief Specify which type of cipher to be used.
 *
 * @typedef enum alc_cipher_type_t
 *
 */
typedef enum _alc_cipher_type
{
    ALC_CIPHER_TYPE_NONE = 0,

    ALC_CIPHER_TYPE_AES,
    ALC_CIPHER_TYPE_DES,
    ALC_CIPHER_TYPE_3DES,
    ALC_CIPHER_TYPE_TWOFISH,
    ALC_CIPHER_TYPE_SERPENT,
    ALC_CIPHER_TYPE_CHACHA20,
    ALC_CIPHER_TYPE_CHACHA20_POLY1305,
    ALC_CIPHER_TYPE_MAX,
} alc_cipher_type_t;

/**
 * @brief Specify which Mode of AES to be used for encrypt and decrypt.
 *
 * @typedef enum  alc_cipher_mode_t
 */
typedef enum _alc_cipher_mode
{
    ALC_AES_MODE_NONE = 0,

    ALC_AES_MODE_ECB,
    ALC_AES_MODE_CBC,
    ALC_AES_MODE_OFB,
    ALC_AES_MODE_CTR,
    ALC_AES_MODE_CFB,
    ALC_AES_MODE_XTS,
    ALC_AES_MODE_GCM,
    ALC_AES_MODE_CCM,
    ALC_AES_MODE_SIV,

    // FIXME: This needs to be handled better
    ALC_CHACHA20,
    ALC_CHACHA20_POLY1305,

    ALC_AES_MODE_MAX,

} alc_cipher_mode_t;
// FIXME: Below typedef is not used, need to remove or use it.
/**
 *
 * @brief Set control flags supported by cipher algorithms.
 *
 * @typedef enum  alc_aes_ctrl_t
 *
 * @note Currently not in use
 */
typedef enum _alc_aes_ctrl
{
    ALC_AES_CTRL_NONE = 0,

    ALC_AES_CTRL_SET_IV_LEN,
    ALC_AES_CTRL_GET_IV_LEN,
    ALC_AES_CTRL_SET_AD_LEN,
    ALC_AES_CTRL_GET_AD_LEN,
    ALC_AES_CTRL_SET_TAG_LEN,
    ALC_AES_CTRL_GET_TAG,

    ALC_AES_CTRL_MAX,
} alc_aes_ctrl_t;

// FIXME: _alc_cipher_xts_data structure needs further refinement.

#define IV_STATE_UNINITIALISED 0 /* initial state is not initialized */
#define IV_STATE_BUFFERED      1 /* iv has been copied to the iv buffer */
#define IV_STATE_COPIED        2 /* iv has been copied from the iv buffer */
#define IV_STATE_FINISHED      3 /* the iv has been used - so don't reuse it */

#define MAX_NUM_512_BLKS 8

typedef struct _alc_cipher_gcm_data
{
    // gcm specific params
    __attribute__((aligned(64))) Uint64 m_hashSubkeyTable[MAX_NUM_512_BLKS * 8];

} _alc_cipher_gcm_data_t;

#define __RIJ_SIZE_ALIGNED(x) ((x * 2) + x)

typedef struct _alc_cipher_xts_data
{
    __attribute__((aligned(64))) Uint8 m_iv_xts[16];
    __attribute__((aligned(64))) Uint8 m_tweak_block[16];
    Uint8  m_tweak_round_key[(__RIJ_SIZE_ALIGNED(32) * (16))];
    Uint8* m_pTweak_key; // this pointer can be removed.
    Int64  m_aes_block_id;

} _alc_cipher_xts_data_t;

#define AES_BLOCK_SIZE 16

typedef struct _alc_cipher_generic_data
{
    // generic cipher params
    Uint8 oiv_buff[AES_BLOCK_SIZE];

    Uint32 updated : 1; /* Set to 1 during update for one shot ciphers */
    Uint32 variable_keylength : 1;
    Uint32 inverse_cipher     : 1; /* set to 1 to use inverse cipher */
    Uint32 use_bits : 1;   /* Set to 0 for cfb1 to use bits instead of bytes */
    Uint32 tlsversion;     /* If TLS padding is in use the TLS version number */
    Uint8* tlsmac;         /* tls MAC extracted from the last record */
    Int32  alloced;        /*
                            * Whether the tlsmac data has been allocated or
                            * points into the user buffer.
                            */
    size_t tlsmacsize;     /* Size of the TLS MAC */
    Int32  removetlspad;   /* Whether TLS padding should be removed or not */
    size_t removetlsfixed; /*
                            * Length of the fixed size data to remove when
                            * processing TLS data (equals mac size plus
                            * IV size if applicable)
                            */

    /*
     * num contains the number of bytes of |iv| which are valid for modes that
     * manage partial blocks themselves.
     */
    unsigned int num;

    size_t blocksize;
    size_t bufsz; /* Number of bytes in buf */

} _alc_cipher_generic_data_t;

#define MAX_CIPHER_IV_SIZE (1024 / 8)
typedef struct _alc_cipher_data
{
    alc_cipher_mode_t m_mode;

    // iv info
    const Uint8* pIv;
    Uint8        iv_buff[MAX_CIPHER_IV_SIZE];
    Uint64       ivLen;

    // key info
    const Uint8* m_pKey;
    Uint32       keyLen_in_bytes;

    // state
    Uint32 ivState;
    Uint32 isKeySet;

    Uint32 enc : 1; /* Set to 1 if we are encrypting or 0 otherwise */
    Uint32 pad : 1; /* Whether padding should be used or not */

    Uint64 tls_enc_records; /* Number of TLS records encrypted */
    unsigned int
        iv_gen_rand     : 1; /* No IV was specified, so generate a rand IV */
    unsigned int iv_gen : 1; /* It is OK to generate IVs */

    // aead params
    Uint64 tagLength;
    Uint64 tls_aad_len;
    Uint32 tls_aad_pad_sz;

    Uint8 buf[AES_BLOCK_SIZE]; /* Buffer of partial blocks processed via
                                      update calls */

    // variations!
    //_alc_cipher_gcm_data_t m_gcm;
    //_alc_cipher_xts_data_t m_xts;

    // generic cipher
    _alc_cipher_generic_data_t generic;

} alc_cipher_data_t;

/**
 *
 * @brief  Opaque cipher context, populated from the library.
 *
 * @param ci_type Specify which cipher type (request param)
 * @param ci_mode Specify which cipher mode (request param)
 * @param ci_keyLen Specify key length in bits (request param)
 * @param ci_key key data (init param)
 * @param ci_iv  Initialization Vector (init param)
 * @param ci_algo_info Algorithm specific info is stored
 *
 * @struct  alc_cipher_info_t
 *
 */
typedef struct _alc_cipher_info
{
    // request params
    alc_cipher_type_t ci_type;   /*! Type: ALC_CIPHER_AES etc */
    alc_cipher_mode_t ci_mode;   /*! Mode: ALC_AES_MODE_CTR etc */
    Uint64            ci_keyLen; /*! Key length in bits */

    // init params
    const Uint8* ci_key;   /*! key data */
    const Uint8* ci_iv;    /*! Initialization Vector */
    Uint64       ci_ivLen; /*! Initialization Vector length */

} alc_cipher_info_t;

/**
 * @brief  Opaque type of a cipher context, comes from the library.
 *
 * @typedef void alc_cipher_context_t
 */
typedef void                  alc_cipher_context_t;
typedef alc_cipher_context_t* alc_cipher_context_p;

/**
 *
 * @brief Handle for maintaining session.
 *
 * @param alc_cipher_context_p pointer to the user allocated context of the
 * cipher
 *
 * @struct alc_cipher_handle_t
 *
 */
typedef struct _alc_cipher_handle
{
    alc_cipher_context_p ch_context;
    void*                alc_cipher_data;
} alc_cipher_handle_t, *alc_cipher_handle_p;

/**
 * @brief       Gets the size of the context for a session described by
 *              pCipherInfo
 * @parblock <br> &nbsp;
 * <b>This API should be called before @ref alcp_cipher_request to identify the
 * memory to be allocated for context </b>
 * @endparblock
 *
 * @return      Size of Context
 */
ALCP_API_EXPORT Uint64
alcp_cipher_context_size(void);

/**
 * @brief    Request for populating handle with algorithm specified by
 * cipher mode and key Length.
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_context_size is called </b>
 * @endparblock
 * @note     Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, ctx
 * to be considered valid.
 * @param [in]    cipherMode       cipher mode to be set
 * @param [in]    keyLen           key length in bits
 * @param [out]   pCipherHandle    Library populated session handle for future
 * cipher operations.
 * @return   &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_request(const alc_cipher_mode_t cipherMode,
                    const Uint64            keyLen,
                    alc_cipher_handle_p     pCipherHandle);

/**
 * @brief  Cipher init.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_request is
 * called.</b>
 * @endparblock
 * @param [in] pCipherHandle Session handle for cipher operation
 * @param[in] pKey  Key
 * @param[in] keyLen  key Length in bits
 * @param[in] pIv  IV/Nonce
 * @param[in] ivLen  iv Length in bits
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_cipher_aead_error or @ref alcp_error_str
 * needs to be called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_init(const alc_cipher_handle_p pCipherHandle,
                 const Uint8*              pKey,
                 Uint64                    keyLen,
                 const Uint8*              pIv,
                 Uint64                    ivLen);

/**
 * @brief    Encrypt plain text and write it to cipher text with provided
 * handle.
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_cipher_request is called and at the
 * end of session call @ref alcp_cipher_finish</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, ctx to be
 * considered valid.
 * @param [in]   pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    datalen           Length of cipher/plain text
 * @return   &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_encrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pPlainText,
                    Uint8*                    pCipherText,
                    Uint64                    datalen);

/**
 * @brief    Decryption of cipher text and write it to plain text with
 * provided handle.
 * @parblock <br> &nbsp;
 * <b>This API should be called only after @ref alcp_cipher_request.
 * API is meant to be used with CBC,CTR,CFB,OFB,XTS mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, pCipherHandle
 *           is valid.
 * @param[in]    pCipherHandle    Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    datalen           Length of cipher/plain text
 * @return   &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_decrypt(const alc_cipher_handle_p pCipherHandle,
                    const Uint8*              pCipherText,
                    Uint8*                    pPlainText,
                    Uint64                    datalen);

/**
 * @brief    Encrypt plain text and write it to cipher text with provided
 * handle.
 * @parblock <br> &nbsp;
 * <b>This XTS specific API should be called only after @ref
 * alcp_cipher_request and alcp_cipher_init . API is meant to be used with XTS
 * mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, ctx to be
 * considered valid.
 * @note    XTS: Argument currCipherTextLen should be multiple of 16bytes unless
 * it's the last call. Also last call if there is a paritial block, both partial
 * and a complete block has to be included in the last call to this function.
 * @param [in]   pCipherHandle Session handle for future encrypt decrypt
 *                         operation
 * @param[in]    pPlainText    Pointer to Plain Text
 * @param[out]   pCipherText   Pointer to Cipher Text
 * @param[in]    currPlainTextLen Length of the given plaintext
 * @param[in]    startBlockNum Start block number of given plaintext
 * @return   &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_blocks_encrypt_xts(const alc_cipher_handle_p pCipherHandle,
                               const Uint8*              pPlainText,
                               Uint8*                    pCipherText,
                               Uint64                    currPlainTextLen,
                               Uint64                    startBlockNum);

/**
 * @brief    Decryption of cipher text and write it to plain text with
 * provided handle.
 * @parblock <br> &nbsp;
 * <b>This XTS specific API should be called only after @ref
 * alcp_cipher_request and alcp_cipher_init. API is meant to be used with XTS
 * mode.</b>
 * @endparblock
 * @note    Error needs to be checked for each call,
 *           valid only if @ref alcp_is_error (ret) is false, pCipherHandle
 *           is valid.
 * @note    XTS: Argument currCipherTextLen should be multiple of 16bytes unless
 * it's the last call. Also last call if there is a partial block, both partial
 * and a complete block has to be included in the last call to this function.
 * @param[in]    pCipherHandle    Session handle for future encrypt decrypt
 * operation
 * @param[out]    pPlainText    Pointer to Plain Text
 * @param[in]    pCipherText   Pointer to Cipher Text
 * @param[in]    startBlockNum    Start block number of given plaintext
 * @param[in]    currCipherTextLen    Length of the given Cipher Text
 * @return   &nbsp; Error Code for the API called.
 */
ALCP_API_EXPORT alc_error_t
alcp_cipher_blocks_decrypt_xts(const alc_cipher_handle_p pCipherHandle,
                               const Uint8*              pCipherText,
                               Uint8*                    pPlainText,
                               Uint64                    currCipherTextLen,
                               Uint64                    startBlockNum);

/**
 * FIXME: Need to fix return type of API
 * @brief       Release resources allocated by alcp_cipher_request.
 * @parblock <br> &nbsp;
 * <b>This API is called to free resources so should be called to free the
 * session</b>
 * @endparblock
 * @note       alcp_cipher_finish to be called at the end of the transaction,
 * context will be unusable after this call.
 *
 * @param[in]    pCipherHandle    Session handle for future encrypt decrypt
 *                         operation
 * @return            None
 */
ALCP_API_EXPORT void
alcp_cipher_finish(const alc_cipher_handle_p pCipherHandle);

EXTERN_C_END

#endif /* _ALCP_CIPHER_H_ */

/**
 * @}
 */
