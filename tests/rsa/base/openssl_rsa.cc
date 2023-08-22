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

#include "rsa/openssl_rsa.hh"
#include <cstddef>
#include <cstring>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <ostream>

namespace alcp::testing {

OpenSSLRsaBase::OpenSSLRsaBase() {}

OpenSSLRsaBase::~OpenSSLRsaBase()
{
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
    }
    if (m_pkey != nullptr) {
        EVP_PKEY_free(m_pkey);
        m_pkey = nullptr;
    }
    if (m_pkey_pvt != nullptr) {
        EVP_PKEY_free(m_pkey_pvt);
        m_pkey_pvt = nullptr;
    }
}

bool
OpenSSLRsaBase::init()
{
    if (m_rsa_handle_keyctx_pub != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pub);
        m_rsa_handle_keyctx_pub = nullptr;
    }
    if (m_rsa_handle_keyctx_pvt != nullptr) {
        EVP_PKEY_CTX_free(m_rsa_handle_keyctx_pvt);
        m_rsa_handle_keyctx_pvt = nullptr;
    }
    return true;
}

bool
OpenSSLRsaBase::SetPublicKey(const alcp_rsa_data_t& data)
{
    std::string strPublicKey = "";
    if (m_key_len * 8 == KEY_SIZE_1024) {
        strPublicKey =
            "-----BEGIN PUBLIC KEY-----\n"
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDxiJ0nHJBUK15SY2NNgyNtm0hr\n"
            "a52HbdoWsBnN8d0QtMU1vKoAjEBB4aBXkUkP2TyJtLyyR+d9JLIvmrlqpSDm1N7T\n"
            "Dijcrz+IEU+lAkaR5/GTskcRW3u72ulHf+ul1xeWUwmmar6O5EXf5xKAeIZlR/lK\n"
            "5ZDW3AwNWlrOEsobCQIDAQAB\n"
            "-----END PUBLIC KEY-----\n";
    } else if (m_key_len * 8 == KEY_SIZE_2048) {
        strPublicKey =
            "-----BEGIN RSA PUBLIC KEY-----\n"
            "MIIBCgKCAQEAriDoH3gBbJo+SojeL5j+4yQumXgnjhrt5+FChBxOfvTcyczzp5ql\n"
            "UNqLzQQcQ/a+XR5qUhaA4l97DgNseFNyoYHIxrB5t+BQw27Q+UuUYYaIwJqZ6r2P\n"
            "VCnQF9WPqqWdzBN6+13IlreH2XX4qy47kuLI3lcPlP5qhYaDogpZCl7lN7OeQj2F\n"
            "APZ1nkV+PL4RYfWZbBymUz0C105ytT7PWgLAZVvag8kHiNXRYv4Ksc9SJ3AEZriZ\n"
            "1tzpJ6/ZkI3vfJZqCeclELQ8zGxb8CbfSd4mHoHCVY7t1h+BNM4zUxSjN8d7bctY\n"
            "JwnfBtztRFN2uTotDJs6njsoxfmh4/SzAQIDAQAB\n"
            "-----END RSA PUBLIC KEY-----\n";
    }

    BIO* bioPublic =
        BIO_new_mem_buf((char*)strPublicKey.data(), strPublicKey.size());
    m_pkey = PEM_read_bio_PUBKEY(bioPublic, &m_pkey, nullptr, nullptr);
    BIO_free_all(bioPublic);
    m_rsa_handle_keyctx_pub = EVP_PKEY_CTX_new(m_pkey, nullptr);
    if (m_rsa_handle_keyctx_pub == nullptr) {
        std::cout << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }

    return true;
}

bool
OpenSSLRsaBase::SetPrivateKey(const alcp_rsa_data_t& data)
{
    std::string strPrivateKey = "";
    if (m_key_len * 8 == KEY_SIZE_1024) {
        strPrivateKey =
            "-----BEGIN PRIVATE KEY-----\n"
            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAPGInScckFQrXlJj\n"
            "Y02DI22bSGtrnYdt2hawGc3x3RC0xTW8qgCMQEHhoFeRSQ/ZPIm0vLJH530ksi+a\n"
            "uWqlIObU3tMOKNyvP4gRT6UCRpHn8ZOyRxFbe7va6Ud/66XXF5ZTCaZqvo7kRd/n\n"
            "EoB4hmVH+UrlkNbcDA1aWs4SyhsJAgMBAAECgYAFvAyfJRp4JR90LU/qQzbQH2O0\n"
            "yTVQRddrunqiXR+2idQ01mni4XGVHtpDuftWGP5K9rOUOAjS+9APOUk1sv348T1x\n"
            "EKxYLQvXLPJcVtYE8sJgJIO6PX0ZpO0upMocX08U8naQUwNPeMC2jr9OzwZmK9BL\n"
            "RW6E6rVSyZNro9bBUQJBAP35x2lsO2CP7CfHUEIp8IGbqet758FYBFLAB4Qy0/Jy\n"
            "QZyWXIQUnmO6CpjNVqtHC9WnQzAM9WLRO6INft84mksCQQDzdXKd7IgSI2XRlpj+\n"
            "5rOyyULNZVy7z5+BxfKpVeoCWZuIdsdWmbyAhAysurTvRRNS+/hJ817338Fy1qbZ\n"
            "rEt7AkEAlpYlIGLmCekL8sIA2loXmiF77H34+fCAD7iAPGgOty/7qyaUEFRRXXwP\n"
            "kG4ft0pWwAV+ltz4GfFJVFqAIUZkZQJAVI6UMnl2gSY+NN8jYFTsUMpKI2BzJt/j\n"
            "vITt1RZ74jkRJgJrFY7rw48Zf9yQ/xF0trvA7p5Se7EBVUtsQ+nthQJAZZXXeu6C\n"
            "94JyNMuRvyVlRwMeW+koxp705xsklQRyMAeapwmYsRtXw6jRGHXKXwKN15lj3zQf\n"
            "UmR8Qxe3QXnFQg==\n"
            "-----END PRIVATE KEY-----\n";
    } else if (m_key_len * 8 == KEY_SIZE_2048) {
        strPrivateKey =
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEogIBAAKCAQEAriDoH3gBbJo+SojeL5j+4yQumXgnjhrt5+FChBxOfvTcyczz\n"
            "p5qlUNqLzQQcQ/a+XR5qUhaA4l97DgNseFNyoYHIxrB5t+BQw27Q+UuUYYaIwJqZ\n"
            "6r2PVCnQF9WPqqWdzBN6+13IlreH2XX4qy47kuLI3lcPlP5qhYaDogpZCl7lN7Oe\n"
            "Qj2FAPZ1nkV+PL4RYfWZbBymUz0C105ytT7PWgLAZVvag8kHiNXRYv4Ksc9SJ3AE\n"
            "ZriZ1tzpJ6/ZkI3vfJZqCeclELQ8zGxb8CbfSd4mHoHCVY7t1h+BNM4zUxSjN8d7\n"
            "bctYJwnfBtztRFN2uTotDJs6njsoxfmh4/SzAQIDAQABAoIBAAGTWKZYPqMN7jxc\n"
            "aq5BkyTZAfbviGQXyElN1308iFVLv+evjBDbLF3D7HnpbJwM0oIjMVEW1Qm3VXS2\n"
            "AThBgQsHEpsBo8hPJkvuZ8OptGkBf6FGhNgD6RUY38Inc4pWv0vGbVly6sq6VGda\n"
            "Uuqxm2Zj2O9yGDj/6FTW97/ymgWm/FfKczg/zGtjdog67W8LvvtmAj5ynSuimOP8\n"
            "mOINPjewIbcl7rKvxcMNrOXKsRWwVxTNXdMNMsXd1Figw022KTqdiazQ/DPIXU6M\n"
            "f8H+U/gS5QZRIAF8i0r3cvq6ai26dX0OFtsoizqG4qlRNwtQ+wyRsilZKiKnFuMY\n"
            "bt1pRBUCgYEA1TlAT/Ui4TBdgGmm0Rlj7JKJENnpDKIFE8bP6Vy8SwBmp5MiRofE\n"
            "TMne4BBKLcFcslCJrFvjl7+v4B9a2de7hJYqtevrXjM91vwFhc6z0m27vv6MKStQ\n"
            "3uKX8+0RGHQ3j53kAvLxFSuAqYQ+gf9IAuyG0gpMABRvj0/8HY3T7tMCgYEA0Q/O\n"
            "0og9UbXh8y3yI94ztczWdIQERyEhQiGNRUnHCqO2QbZQ9Nm190Jx/8yew03xpPVb\n"
            "fyWWfKqO8Kjg5np0w37porI0UmfLZ5QMC+GFMq0jOUXidsvkyoWOe4D8LII0L98k\n"
            "sjihHBlGNrfFjEgOUQaoreB+8F07m/iofRCROlsCgYAPUUGRfOa4jqTo6K4XL1/C\n"
            "SvSVxVG8mpcKyKl+9i6ApNK7DxLTRkWPzqC4L/NkPhPOq4J4Y1GCQT79NsNsCtdp\n"
            "uu/uibgq2DuFCi3LYwIAB+oI2nhvLLFukZCg8VLdEtw68PjETXeMMcfYZaun4xLl\n"
            "QuCcjijPiKhK/0/5P4sOCQKBgHsi7XXRqxRapdg/ArUfpqN5IAOG0qI2oEk8S+I4\n"
            "v1TD8pCn2u0s4mHdsBmzovt0CFVZ8udj80xAhWq4facjD20qbmBWyDyVSBgc+i9x\n"
            "SKv9kJamU+oW1A55NeAGrAFnO2fK7elPM43CUTnfairjMhOFcYrghMP8liSbBFqN\n"
            "jIyrAoGAVGZQVZgicmSppbBuZYJPOuegPVYhncq3XtBZCtEGGlMtQpKgz+GRhyvT\n"
            "Ar/HC7xnS5Gjfyjj6eGHsBAjTsE4t38qD4nxQXzBmAQQ1/7/iq3WNu63OV2q4GRh\n"
            "wChOO0pcJPOZfWtvKiy7hbN09e0nt5blX1yqe6LdO7mACWli/Ss=\n"
            "-----END RSA PRIVATE KEY-----\n";
    }

    BIO* bioPrivate =
        BIO_new_mem_buf((char*)strPrivateKey.data(), strPrivateKey.size());
    m_pkey_pvt =
        PEM_read_bio_PrivateKey(bioPrivate, &m_pkey_pvt, nullptr, nullptr);
    BIO_free_all(bioPrivate);
    m_rsa_handle_keyctx_pvt = EVP_PKEY_CTX_new(m_pkey_pvt, nullptr);
    if (m_rsa_handle_keyctx_pvt == nullptr) {
        std::cout << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    return true;
}

int
OpenSSLRsaBase::EncryptPubKey(const alcp_rsa_data_t& data)
{
    int           ret_val = 0;
    size_t        outlen;
    const EVP_MD* digest;

    if (1 != EVP_PKEY_encrypt_init(m_rsa_handle_keyctx_pub)) {
        std::cout << "EVP_PKEY_encrypt_init failed" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    /* FIXME: parameterize the padding scheme */
    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                            RSA_NO_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING) {
        digest = EVP_get_digestbyname("sha256");
        /* set padding mode parameters */
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                            RSA_PKCS1_OAEP_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
        /* FIXME: MD scheme should be parameterized in future */
        if (1
            != EVP_PKEY_CTX_set_rsa_oaep_md(m_rsa_handle_keyctx_pub, digest)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_oaep_md failed:" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_mgf1_md(m_rsa_handle_keyctx_pub, digest)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_mgf1_md failed:" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
    } else {
        std::cout << "Error: Invalid padding mode!" << std::endl;
        return 1;
    }

    /* call encrypt */
    if (1
        != EVP_PKEY_encrypt(m_rsa_handle_keyctx_pub,
                            NULL,
                            &outlen,
                            data.m_msg,
                            data.m_msg_len)) {
        std::cout << "EVP_PKEY_encrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    if (1
        != EVP_PKEY_encrypt(m_rsa_handle_keyctx_pub,
                            data.m_encrypted_data,
                            &outlen,
                            data.m_msg,
                            data.m_msg_len)) {
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    return 0;
}

int
OpenSSLRsaBase::DecryptPvtKey(const alcp_rsa_data_t& data)
{
    int           ret_val = 0;
    size_t        outlen;
    const EVP_MD* digest;

    if (1 != EVP_PKEY_decrypt_init(m_rsa_handle_keyctx_pvt)) {
        std::cout << "EVP_PKEY_decrypt_init failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }

    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                            RSA_NO_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING) {
        digest = EVP_get_digestbyname("sha256");
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                            RSA_PKCS1_OAEP_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_oaep_md(m_rsa_handle_keyctx_pvt, digest)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_oaep_md failed: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_mgf1_md(m_rsa_handle_keyctx_pvt, digest)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_mgf1_md failed: Error:"
                      << ERR_GET_REASON(ERR_get_error()) << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
    } else {
        std::cout << "Error: Invalid padding mode!" << std::endl;
        return 1;
    }
    /* now call decrypt */
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle_keyctx_pvt,
                            NULL,
                            &outlen,
                            data.m_encrypted_data,
                            data.m_msg_len)) {
        std::cout << "EVP_PKEY_decrypt failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle_keyctx_pvt,
                            data.m_decrypted_data,
                            &outlen,
                            data.m_encrypted_data,
                            data.m_msg_len)) {
        std::cout << "EVP_PKEY_decrypt failed: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        return ret_val;
    }
    return 0;
}

bool
OpenSSLRsaBase::reset()
{
    return true;
}

} // namespace alcp::testing
