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
    const Uint8 Modulus_1024[] = {
        0xf1, 0x88, 0x9d, 0x27, 0x1c, 0x90, 0x54, 0x2b, 0x5e, 0x52, 0x63, 0x63,
        0x4d, 0x83, 0x23, 0x6d, 0x9b, 0x48, 0x6b, 0x6b, 0x9d, 0x87, 0x6d, 0xda,
        0x16, 0xb0, 0x19, 0xcd, 0xf1, 0xdd, 0x10, 0xb4, 0xc5, 0x35, 0xbc, 0xaa,
        0x00, 0x8c, 0x40, 0x41, 0xe1, 0xa0, 0x57, 0x91, 0x49, 0x0f, 0xd9, 0x3c,
        0x89, 0xb4, 0xbc, 0xb2, 0x47, 0xe7, 0x7d, 0x24, 0xb2, 0x2f, 0x9a, 0xb9,
        0x6a, 0xa5, 0x20, 0xe6, 0xd4, 0xde, 0xd3, 0x0e, 0x28, 0xdc, 0xaf, 0x3f,
        0x88, 0x11, 0x4f, 0xa5, 0x02, 0x46, 0x91, 0xe7, 0xf1, 0x93, 0xb2, 0x47,
        0x11, 0x5b, 0x7b, 0xbb, 0xda, 0xe9, 0x47, 0x7f, 0xeb, 0xa5, 0xd7, 0x17,
        0x96, 0x53, 0x09, 0xa6, 0x6a, 0xbe, 0x8e, 0xe4, 0x45, 0xdf, 0xe7, 0x12,
        0x80, 0x78, 0x86, 0x65, 0x47, 0xf9, 0x4a, 0xe5, 0x90, 0xd6, 0xdc, 0x0c,
        0x0d, 0x5a, 0x5a, 0xce, 0x12, 0xca, 0x1b, 0x09
    };
    /* for 2048 keysize */
    const Uint8 Modulus_2048[] = {
        0xae, 0x20, 0xe8, 0x1f, 0x78, 0x01, 0x6c, 0x9a, 0x3e, 0x4a, 0x88, 0xde,
        0x2f, 0x98, 0xfe, 0xe3, 0x24, 0x2e, 0x99, 0x78, 0x27, 0x8e, 0x1a, 0xed,
        0xe7, 0xe1, 0x42, 0x84, 0x1c, 0x4e, 0x7e, 0xf4, 0xdc, 0xc9, 0xcc, 0xf3,
        0xa7, 0x9a, 0xa5, 0x50, 0xda, 0x8b, 0xcd, 0x04, 0x1c, 0x43, 0xf6, 0xbe,
        0x5d, 0x1e, 0x6a, 0x52, 0x16, 0x80, 0xe2, 0x5f, 0x7b, 0x0e, 0x03, 0x6c,
        0x78, 0x53, 0x72, 0xa1, 0x81, 0xc8, 0xc6, 0xb0, 0x79, 0xb7, 0xe0, 0x50,
        0xc3, 0x6e, 0xd0, 0xf9, 0x4b, 0x94, 0x61, 0x86, 0x88, 0xc0, 0x9a, 0x99,
        0xea, 0xbd, 0x8f, 0x54, 0x29, 0xd0, 0x17, 0xd5, 0x8f, 0xaa, 0xa5, 0x9d,
        0xcc, 0x13, 0x7a, 0xfb, 0x5d, 0xc8, 0x96, 0xb7, 0x87, 0xd9, 0x75, 0xf8,
        0xab, 0x2e, 0x3b, 0x92, 0xe2, 0xc8, 0xde, 0x57, 0x0f, 0x94, 0xfe, 0x6a,
        0x85, 0x86, 0x83, 0xa2, 0x0a, 0x59, 0x0a, 0x5e, 0xe5, 0x37, 0xb3, 0x9e,
        0x42, 0x3d, 0x85, 0x00, 0xf6, 0x75, 0x9e, 0x45, 0x7e, 0x3c, 0xbe, 0x11,
        0x61, 0xf5, 0x99, 0x6c, 0x1c, 0xa6, 0x53, 0x3d, 0x02, 0xd7, 0x4e, 0x72,
        0xb5, 0x3e, 0xcf, 0x5a, 0x02, 0xc0, 0x65, 0x5b, 0xda, 0x83, 0xc9, 0x07,
        0x88, 0xd5, 0xd1, 0x62, 0xfe, 0x0a, 0xb1, 0xcf, 0x52, 0x27, 0x70, 0x04,
        0x66, 0xb8, 0x99, 0xd6, 0xdc, 0xe9, 0x27, 0xaf, 0xd9, 0x90, 0x8d, 0xef,
        0x7c, 0x96, 0x6a, 0x09, 0xe7, 0x25, 0x10, 0xb4, 0x3c, 0xcc, 0x6c, 0x5b,
        0xf0, 0x26, 0xdf, 0x49, 0xde, 0x26, 0x1e, 0x81, 0xc2, 0x55, 0x8e, 0xed,
        0xd6, 0x1f, 0x81, 0x34, 0xce, 0x33, 0x53, 0x14, 0xa3, 0x37, 0xc7, 0x7b,
        0x6d, 0xcb, 0x58, 0x27, 0x09, 0xdf, 0x06, 0xdc, 0xed, 0x44, 0x53, 0x76,
        0xb9, 0x3a, 0x2d, 0x0c, 0x9b, 0x3a, 0x9e, 0x3b, 0x28, 0xc5, 0xf9, 0xa1,
        0xe3, 0xf4, 0xb3, 0x01
    };
    unsigned long Exponent = 0x10001;
    int           retval;
    BIGNUM*       mod_BN;
    if (m_key_len * 8 == KEY_SIZE_1024) {
        mod_BN = BN_bin2bn(Modulus_1024, sizeof(Modulus_1024), NULL);
    } else if (m_key_len * 8 == KEY_SIZE_2048) {
        mod_BN = BN_bin2bn(Modulus_2048, sizeof(Modulus_2048), NULL);
    } else {
        std::cout << "Invalid key len value" << std::endl;
        return false;
    }

    OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM*     params    = NULL;

    retval = OSSL_PARAM_BLD_push_BN(param_bld, "n", mod_BN);
    retval = OSSL_PARAM_BLD_push_ulong(param_bld, "e", Exponent);

    params = OSSL_PARAM_BLD_to_param(param_bld);

    OSSL_PARAM_BLD_free(param_bld);

    m_rsa_handle_keyctx_pub = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    retval                  = EVP_PKEY_fromdata_init(m_rsa_handle_keyctx_pub);
    retval                  = EVP_PKEY_fromdata(
        m_rsa_handle_keyctx_pub, &m_pkey, EVP_PKEY_PUBLIC_KEY, params);
    if (m_rsa_handle_keyctx_pub == nullptr) {
        std::cout << "EVP_PKEY_CTX_new returned null: Error:"
                  << ERR_GET_REASON(ERR_get_error()) << std::endl;
        return false;
    }
    if (m_pkey == nullptr) {
        std::cout << "Null key : Error:" << ERR_GET_REASON(ERR_get_error())
                  << std::endl;
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
    const EVP_MD* digest     = nullptr;
    const char*   digest_str = "";
    m_rsa_handle_keyctx_pub  = EVP_PKEY_CTX_new(m_pkey, NULL);
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
        switch (m_digest_info.dt_len) {
            /* FIXME: add more cases here */
            case ALC_DIGEST_LEN_256:
                digest_str = "sha256";
                break;
            case ALC_DIGEST_LEN_512:
                digest_str = "sha512";
                break;
            default:
                std::cout << "Invalid digest length" << std::endl;
                return 1;
        }
        digest = EVP_get_digestbyname((const char*)digest_str);
        if (digest == nullptr) {
            std::cout << "Digest type is invalid" << std::endl;
            return 1;
        }
        /* set padding mode parameters */
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pub,
                                            RSA_PKCS1_OAEP_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed" << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            return ret_val;
        }
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
    const EVP_MD* digest     = nullptr;
    const char*   digest_str = "";

    if (1 != EVP_PKEY_decrypt_init(m_rsa_handle_keyctx_pvt)) {
        std::cout << "EVP_PKEY_decrypt_init failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << ret_val << std::endl;
        return ret_val;
    }

    if (m_padding_mode == ALCP_TEST_RSA_NO_PADDING) {
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                            RSA_NO_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
            return ret_val;
        }
    } else if (m_padding_mode == ALCP_TEST_RSA_PADDING) {
        switch (m_digest_info.dt_len) {
            /* FIXME: add more cases here */
            case ALC_DIGEST_LEN_256:
                digest_str = "sha256";
                break;
            case ALC_DIGEST_LEN_512:
                digest_str = "sha512";
                break;
            default:
                std::cout << "Invalid digest length" << std::endl;
                return 1;
        }
        digest = EVP_get_digestbyname(digest_str);
        if (digest == nullptr) {
            std::cout << "Digest type is invalid" << std::endl;
            return 1;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_padding(m_rsa_handle_keyctx_pvt,
                                            RSA_PKCS1_OAEP_PADDING)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_padding failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_oaep_md(m_rsa_handle_keyctx_pvt, digest)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_oaep_md failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
            return ret_val;
        }
        if (1
            != EVP_PKEY_CTX_set_rsa_mgf1_md(m_rsa_handle_keyctx_pvt, digest)) {
            std::cout << "EVP_PKEY_CTX_set_rsa_mgf1_md failed: Error:"
                      << std::endl;
            ret_val = ERR_GET_REASON(ERR_get_error());
            std::cout << ret_val << std::endl;
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
                            outlen)) {
        std::cout << "EVP_PKEY_decrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << ret_val << std::endl;
        return ret_val;
    }
    if (1
        != EVP_PKEY_decrypt(m_rsa_handle_keyctx_pvt,
                            data.m_decrypted_data,
                            &outlen,
                            data.m_encrypted_data,
                            outlen)) {
        std::cout << "EVP_PKEY_decrypt failed: Error:" << std::endl;
        ret_val = ERR_GET_REASON(ERR_get_error());
        std::cout << ret_val << std::endl;
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
