/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "alc_base.hh"
#include "base.hh"

namespace alcp::testing {

// AlcpCipherBase class functions
AlcpCipherBase::AlcpCipherBase(alc_aes_mode_t mode, uint8_t* iv)
    : m_mode{ mode }
    , m_iv{ iv }
{}

AlcpCipherBase::AlcpCipherBase(alc_aes_mode_t mode,
                               uint8_t*       iv,
                               uint8_t*       key,
                               const uint32_t key_len)
    : m_mode{ mode }
    , m_iv{ iv }
{
    alcpInit(iv, key, key_len);
}

AlcpCipherBase::~AlcpCipherBase()
{
    if (m_handle != nullptr) {
        alcp_cipher_finish(m_handle);
        if (m_handle->ch_context != NULL) {
            free(m_handle->ch_context);
        }
        delete m_handle;
    }
}

bool
AlcpCipherBase::alcpInit(const uint8_t* iv,
                         const uint8_t* key,
                         const uint32_t key_len)
{
    this->m_iv = reinterpret_cast<const uint8_t*>(iv);
    return alcpInit(key, key_len);
}

bool
AlcpCipherBase::alcpInit(const uint8_t* key, const uint32_t key_len)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    if (m_handle != nullptr) {
        alcp_cipher_finish(m_handle);
        free(m_handle->ch_context);
        delete m_handle; // Free old handle
    }
    m_handle = new alc_cipher_handle_t;
    if (m_handle == nullptr) {
        std::cout << "alcp_base.c: Memory allocation for handle failure!"
                  << std::endl;
        goto out;
    }
    m_handle->ch_context = malloc(alcp_cipher_context_size(&m_cinfo));
    if (m_handle->ch_context == NULL) {
        std::cout << "alcp_base.c: Memory allocation for context failure!"
                  << std::endl;
        goto out;
    }

    /* Initialize keyinfo */
    m_keyinfo.type = ALC_KEY_TYPE_SYMMETRIC;
    m_keyinfo.fmt  = ALC_KEY_FMT_RAW;
    m_keyinfo.len  = key_len;
    m_keyinfo.key  = key;
    /* Initialize cinfo */
    m_cinfo.ci_mode_data.cm_aes.ai_mode = m_mode;
    m_cinfo.ci_mode_data.cm_aes.ai_iv   = m_iv;
    m_cinfo.ci_type                     = ALC_CIPHER_TYPE_AES;
    m_cinfo.ci_key_info                 = m_keyinfo;

    /* Check support */
    err = alcp_cipher_supported(&m_cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        goto out;
    }

    /* Request Handle */
    err = alcp_cipher_request(&m_cinfo, m_handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        goto out;
    }
    return true;
out:
    if (m_handle != nullptr) {
        if (m_handle->ch_context != NULL)
            free(m_handle->ch_context);
        delete m_handle; // Free old handle
    }
    return false;
}

bool
AlcpCipherBase::encrypt(const uint8_t* plaintxt, int len, uint8_t* ciphertxt)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    /* Encrypt Data */
    err = alcp_cipher_encrypt(m_handle, plaintxt, ciphertxt, len, m_iv);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }
    return true;
}

bool
AlcpCipherBase::decrypt(const uint8_t* ciphertxt, int len, uint8_t* plaintxt)
{
    alc_error_t err;
    const int   err_size = 256;
    uint8_t     err_buf[err_size];

    /* Decrypt Data */
    err = alcp_cipher_decrypt(m_handle, ciphertxt, plaintxt, len, m_iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return false;
    }
    return true;
}

// AlcpCipherTesting class functions
AlcpCipherTesting::AlcpCipherTesting(alc_aes_mode_t mode, uint8_t* iv)
    : AlcpCipherBase(mode, iv)
{}

std::vector<uint8_t>
AlcpCipherTesting::testingEncrypt(std::vector<uint8_t> plaintext,
                                  std::vector<uint8_t> key,
                                  std::vector<uint8_t> iv)
{
    if (alcpInit(&iv[0], &key[0], key.size() * 8)) {
        uint8_t* ciphertext = new uint8_t[plaintext.size()];
        encrypt(&plaintext[0], plaintext.size(), ciphertext);
        std::vector<uint8_t> vt;
        return std::vector<uint8_t>(ciphertext, ciphertext + plaintext.size());
    }
    return {};
}
std::vector<uint8_t>
AlcpCipherTesting::testingDecrypt(std::vector<uint8_t> ciphertext,
                                  std::vector<uint8_t> key,
                                  std::vector<uint8_t> iv)
{
    if (alcpInit(&iv[0], &key[0], key.size() * 8)) {
        uint8_t* plaintext = new uint8_t[ciphertext.size()];
        decrypt(&ciphertext[0], ciphertext.size(), plaintext);
        return std::vector<uint8_t>(plaintext, plaintext + ciphertext.size());
    }
    return {};
}

// Legacy warning, depreciated!, future pure classes
void
alcp_encrypt_data(
    const uint8_t* plaintxt,
    const uint32_t len, /* Describes both 'plaintxt' and 'ciphertxt' */
    uint8_t*       key,
    const uint32_t key_len,
    uint8_t*       iv,
    uint8_t*       ciphertxt,
    alc_aes_mode_t mode)
{
    static alc_cipher_handle_t handle;
    alc_error_t                err;
    const int                  err_size = 256;
    uint8_t                    err_buf[err_size];

    alc_aes_info_t aes_data = {
        .ai_mode = mode,
        .ai_iv   = iv,
    };

    /*
    const alc_key_info_t kinfo = {
        .type    = ALC_KEY_TYPE_SYMMETRIC,
        .fmt     = ALC_KEY_FMT_RAW,
        .key     = key,
        .len     = key_len,
    };
    */
    alc_cipher_info_t cinfo = {
      .ci_type = ALC_CIPHER_TYPE_AES,
      .ci_mode_data =
          {
              .cm_aes = aes_data,
          },
      /* No padding, Not Implemented yet*/
      //.pad     = ALC_CIPHER_PADDING_NONE,
  };
    alc_key_info_t key_info = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .len  = key_len,
        .key  = key,
    };
    cinfo.ci_key_info = key_info;

    /*
     * Check if the current cipher is supported,
     * optional call, alcp_cipher_request() will anyway return
     * ALC_ERR_NOSUPPORT error.
     *
     * This query call is provided to support fallback mode for applications
     */
    err = alcp_cipher_supported(&cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
    //   printf("supported succeeded\n");
    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_context_size(&cinfo));
    // if (!ctx)
    //    return;

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
    //   printf("request succeeded\n");

    err = alcp_cipher_encrypt(&handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable to encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    //   printf("encrypt succeeded\n");
}

int
encrypt(unsigned char* plaintext,
        int            plaintext_len,
        unsigned char* key,
        int            keylen,
        unsigned char* iv,
        unsigned char* ciphertext)
{
    alcp_encrypt_data(plaintext,
                      plaintext_len,
                      key,
                      keylen,
                      iv,
                      ciphertext,
                      ALC_AES_MODE_CBC);
    return plaintext_len;
}

void
alcp_decrypt_data(
    const uint8_t* ciphertxt,
    const uint32_t len, /* Describes both 'plaintxt' and 'ciphertxt' */
    uint8_t*       key,
    const uint32_t key_len,
    uint8_t*       iv,
    uint8_t*       plaintxt,
    alc_aes_mode_t mode)
{
    static alc_cipher_handle_t handle;
    alc_error_t                err;
    const int                  err_size = 256;
    uint8_t                    err_buf[err_size];

    alc_aes_info_t aes_data = {
        .ai_mode = mode,
        .ai_iv   = iv,
    };

    /*
    const alc_key_info_t kinfo = {
        .type    = ALC_KEY_TYPE_SYMMETRIC,
        .fmt     = ALC_KEY_FMT_RAW,
        .key     = key,
        .len     = key_len,
    };
    */
    alc_cipher_info_t cinfo = {
      .ci_type = ALC_CIPHER_TYPE_AES,
      .ci_mode_data =
          {
              .cm_aes = aes_data,
          },
      /* No padding, Not Implemented yet*/
      //.pad     = ALC_CIPHER_PADDING_NONE,
  };
    alc_key_info_t key_info = {
        .type = ALC_KEY_TYPE_SYMMETRIC,
        .fmt  = ALC_KEY_FMT_RAW,
        .len  = key_len,
        .key  = key,
    };
    cinfo.ci_key_info = key_info;

    /*
     * Check if the current cipher is supported,
     * optional call, alcp_cipher_request() will anyway return
     * ALC_ERR_NOSUPPORT error.
     *
     * This query call is provided to support fallback mode for applications
     */
    err = alcp_cipher_supported(&cinfo);
    if (alcp_is_error(err)) {
        printf("Error: not supported \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
    //   printf("supported succeeded\n");
    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_context_size(&cinfo));
    // if (!ctx)
    //    return;

    /* Request a context with cinfo */
    err = alcp_cipher_request(&cinfo, &handle);
    if (alcp_is_error(err)) {
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }
    //   printf("request succeeded\n");

    err = alcp_cipher_decrypt(&handle, ciphertxt, plaintxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return;
    }

    //   printf("decrypt succeeded\n");
}

int
decrypt(unsigned char* ciphertext,
        int            ciphertext_len,
        unsigned char* key,
        int            keylen,
        unsigned char* iv,
        unsigned char* plaintext)
{
    alcp_decrypt_data(ciphertext,
                      ciphertext_len,
                      key,
                      keylen,
                      iv,
                      plaintext,
                      ALC_AES_MODE_CBC);
    return ciphertext_len;
}

} // namespace alcp::testing