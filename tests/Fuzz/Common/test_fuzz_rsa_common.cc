/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

#include "Fuzz/alcp_fuzz_test.hh"
// FIXME: alc_digest_info_t Should be removed from testing
typedef struct _alc_digest_info
{
    alc_digest_len_t dt_len;
    /* valid when dgst_len == ALC_DIGEST_LEN_CUSTOM */
    /* length is bits */
    Uint32            dt_custom_len;
    alc_digest_mode_t dt_mode;
} alc_digest_info_t, *alc_digest_info_p;

alc_digest_info_t dinfo = {
    .dt_len  = ALC_DIGEST_LEN_256,
    .dt_mode = ALC_SHA2_256,
};
alc_digest_info_t mgf_info = {
    .dt_len  = ALC_DIGEST_LEN_256,
    .dt_mode = ALC_SHA2_256,
};

static inline void
convert_to_bignum(const Uint8* bytes, Uint64* bigNum, Uint64 size)
{
    Uint8* p_res = (Uint8*)(bigNum);
    std::reverse_copy(bytes, bytes + size, p_res);
}

void
TestRsaEncryptLifecycle_0(alc_rsa_handle_p handle,
                          Uint64           PublicKeyExponent,
                          Uint8*           Modulus,
                          Uint64           ModulusSize,
                          Uint8*           Input,
                          Uint8*           EncryptedOutput)
{
    /* try to call encrypt on a finished handle */
    alcp_rsa_set_publickey(handle, PublicKeyExponent, Modulus, ModulusSize);
    Uint64 KeySize = alcp_rsa_get_key_size(handle);
    alcp_rsa_publickey_encrypt(handle, &Input[0], KeySize, &EncryptedOutput[0]);
    alcp_rsa_finish(handle);
    alcp_rsa_publickey_encrypt(handle, &Input[0], KeySize, &EncryptedOutput[0]);
    return;
}

/* try to call encrypt on a finished handle */
void
TestRsaDecryptLifecycle_0(alc_rsa_handle_p handle,
                          Uint8*           dp_exp,
                          Uint8*           dq_exp,
                          Uint8*           p_mod,
                          Uint8*           q_mod,
                          Uint8*           q_mod_inv,
                          Uint8*           mod,
                          Uint64           size_p_mod,
                          Uint8*           encrypted_text,
                          Uint8*           decrypted_text)
{
    alcp_rsa_set_privatekey(handle,
                            &dp_exp[0],
                            &dq_exp[0],
                            &p_mod[0],
                            &q_mod[0],
                            &q_mod_inv[0],
                            mod,
                            size_p_mod);
    Uint64 size_key = alcp_rsa_get_key_size(handle);
    alcp_rsa_privatekey_decrypt(handle,
                                ALCP_RSA_PADDING_NONE,
                                &encrypted_text[0],
                                size_key,
                                &decrypted_text[0]);
    alcp_rsa_finish(handle);
    return;
}

/* try to call OAEP encrypt on a finished handle */
void
TestRsaOAEPEncryptLifecycle_0(alc_rsa_handle_p handle,
                              Uint64           PublicKeyExponent,
                              Uint8*           Modulus,
                              Uint64           ModulusSize,
                              Uint8*           Input,
                              Uint64           InputSize,
                              Uint8*           Label,
                              Uint64           LabelSize,
                              Uint8*           Seed,
                              Uint8*           EncryptedOutput)
{
    alcp_rsa_set_publickey(handle, PublicKeyExponent, Modulus, ModulusSize);
    alcp_rsa_add_digest(handle, ALC_SHA2_256);
    alcp_rsa_add_mgf(handle, ALC_SHA2_256);
    alcp_rsa_publickey_encrypt_oaep(
        handle, Input, InputSize, Label, LabelSize, Seed, EncryptedOutput);
    alcp_rsa_finish(handle);
    alcp_rsa_publickey_encrypt_oaep(
        handle, Input, InputSize, Label, LabelSize, Seed, EncryptedOutput);
    return;
}
/* call decrypt OAEP on a finished handle */
void
TestRsaOAEPDecryptLifecycle_0(alc_rsa_handle_p handle,
                              Uint8*           dp_exp,
                              Uint8*           dq_exp,
                              Uint8*           p_mod,
                              Uint8*           q_mod,
                              Uint8*           q_mod_inv,
                              Uint8*           mod,
                              Uint64           size_p_mod,
                              Uint64           size_modulus,
                              Uint8*           EncryptedOutput,
                              Uint8*           Label,
                              Uint64           LabelSize,
                              Uint8*           DecryptedOutput,
                              Uint64*          DecryptedOutSize)
{
    alcp_rsa_set_privatekey(
        handle, dp_exp, dq_exp, p_mod, q_mod, q_mod_inv, mod, size_p_mod);
    alcp_rsa_add_digest(handle, ALC_SHA2_256);
    alcp_rsa_add_mgf(handle, ALC_SHA2_256);
    alcp_rsa_privatekey_decrypt_oaep(handle,
                                     EncryptedOutput,
                                     size_modulus,
                                     Label,
                                     LabelSize,
                                     DecryptedOutput,
                                     DecryptedOutSize);
    alcp_rsa_finish(handle);
    alcp_rsa_privatekey_decrypt_oaep(handle,
                                     EncryptedOutput,
                                     size_modulus,
                                     Label,
                                     LabelSize,
                                     DecryptedOutput,
                                     DecryptedOutSize);
    return;
}

/* call sign again on a finished handle */
void
TestRsaSignLifecycle_0(alc_rsa_handle_p handle,
                       int              PaddingMode,
                       Uint8*           Input,
                       Uint64           InputSize,
                       Uint8*           Salt,
                       Uint64           SaltSize,
                       Uint8*           SignatureOutput)
{
    if (PaddingMode == ALCP_TEST_RSA_PADDING_PSS)
        alcp_rsa_privatekey_sign_pss(
            handle, true, Input, InputSize, Salt, SaltSize, SignatureOutput);
    else if (PaddingMode == ALCP_TEST_RSA_PADDING_PKCS)
        alcp_rsa_privatekey_sign_pkcs1v15(
            handle, true, Input, InputSize, SignatureOutput);
    alcp_rsa_finish(handle);
    if (PaddingMode == ALCP_TEST_RSA_PADDING_PSS)
        alcp_rsa_privatekey_sign_pss(
            handle, true, Input, InputSize, Salt, SaltSize, SignatureOutput);
    else if (PaddingMode == ALCP_TEST_RSA_PADDING_PKCS)
        alcp_rsa_privatekey_sign_pkcs1v15(
            handle, true, Input, InputSize, SignatureOutput);
    return;
}
/* call verify again on a finished handle */
void
TestRsaVerifyLifecycle_0(alc_rsa_handle_p handle,
                         int              PaddingMode,
                         Uint8*           Input,
                         Uint64           InputSize,
                         Uint8*           Salt,
                         Uint64           SaltSize,
                         Uint8*           SignatureOutput)
{
    if (PaddingMode == ALCP_TEST_RSA_PADDING_PSS) {
        alcp_rsa_privatekey_sign_pss(
            handle, true, Input, InputSize, Salt, SaltSize, SignatureOutput);
        alcp_rsa_publickey_verify_pss(
            handle, Input, InputSize, SignatureOutput);
    } else if (PaddingMode == ALCP_TEST_RSA_PADDING_PKCS) {
        alcp_rsa_privatekey_sign_pkcs1v15(
            handle, true, Input, InputSize, SignatureOutput);
        alcp_rsa_publickey_verify_pkcs1v15(
            handle, Input, InputSize, SignatureOutput);
    }
    alcp_rsa_finish(handle);
    if (PaddingMode == ALCP_TEST_RSA_PADDING_PSS) {
        alcp_rsa_privatekey_sign_pss(
            handle, true, Input, InputSize, Salt, SaltSize, SignatureOutput);
        alcp_rsa_publickey_verify_pss(
            handle, Input, InputSize, SignatureOutput);
    } else if (PaddingMode == ALCP_TEST_RSA_PADDING_PKCS) {
        alcp_rsa_privatekey_sign_pkcs1v15(
            handle, true, Input, InputSize, SignatureOutput);
        alcp_rsa_publickey_verify_pkcs1v15(
            handle, Input, InputSize, SignatureOutput);
    }
    return;
}

/* Test functions */
int
ALCP_Fuzz_Rsa_OAEP(const Uint8* buf,
                   size_t       len,
                   int          EncDec,
                   bool         TestNegLifeCycle)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);
    Uint64             decrypted_output_size;
    size_t             size_encrypted_data = 256;
    std::vector<Uint8> fuzz_input =
        stream.ConsumeBytes<Uint8>(size_encrypted_data);

    /* key component sizes */
    size_t size_modulus = 256, size_p_modulus = 128;
    size_t size_label = stream.ConsumeIntegral<Uint16>();

    Uint64             PublicKeyExponent = pub_key_exp;
    Uint64             hash_len          = dinfo.dt_len / 8;
    std::vector<Uint8> fuzz_seed         = stream.ConsumeBytes<Uint8>(hash_len);

    std::vector<Uint8> fuzz_label = stream.ConsumeBytes<Uint8>(size_label);

    std::vector<Uint8> encrypted_text(size_encrypted_data, 0);
    std::vector<Uint8> decrypted_text(size_encrypted_data, 0);

    std::cout << "Running Rsa OAEP for Input size: " << size_encrypted_data
              << " and Modulus size " << size_modulus << std::endl;

    alc_rsa_handle_p handle = new alc_rsa_handle_t;

    Uint64 size     = alcp_rsa_context_size();
    handle->context = malloc(size);
    err             = alcp_rsa_request(handle);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_rsa_request" << std::endl;
        goto dealloc;
    }

    if (TestNegLifeCycle) {
        if (EncDec == ALCP_TEST_FUZZ_RSA_ENCRYPT)
            TestRsaOAEPEncryptLifecycle_0(handle,
                                          PublicKeyExponent,
                                          fuzz_modulus,
                                          size_modulus,
                                          &fuzz_input[0],
                                          fuzz_input.size(),
                                          &fuzz_label[0],
                                          fuzz_label.size(),
                                          &fuzz_seed[0],
                                          &encrypted_text[0]);
        else {
            TestRsaOAEPDecryptLifecycle_0(handle,
                                          fuzz_dp_exp,
                                          fuzz_dq_exp,
                                          fuzz_p_modulus,
                                          fuzz_q_modulus,
                                          fuzz_q_mod_inv,
                                          fuzz_modulus,
                                          size_p_modulus,
                                          size_modulus,
                                          &encrypted_text[0],
                                          &fuzz_label[0],
                                          fuzz_label.size(),
                                          &decrypted_text[0],
                                          &decrypted_output_size);
        }
    } else {
        /* generate keys */
        err = alcp_rsa_set_publickey(
            handle, PublicKeyExponent, fuzz_modulus, size_modulus);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_set_publickey" << std::endl;
            goto dealloc;
        }
        err = alcp_rsa_set_privatekey(handle,
                                      fuzz_dp_exp,
                                      fuzz_dq_exp,
                                      fuzz_p_modulus,
                                      fuzz_q_modulus,
                                      fuzz_q_mod_inv,
                                      fuzz_modulus,
                                      size_p_modulus);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_set_privatekey" << std::endl;
            goto dealloc;
        }
        err = alcp_rsa_add_digest(handle, ALC_SHA2_256);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_add_digest" << std::endl;
            goto dealloc;
        }
        err = alcp_rsa_add_mgf(handle, ALC_SHA2_256);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_add_mgf" << std::endl;
            goto dealloc;
        }

        /* input buffer */
        fuzz_input.resize(size - 2 * hash_len - 2);
        encrypted_text.resize(size_modulus);
        decrypted_text.resize(size_modulus);

        /* encrypt and decrypt */
        if (EncDec == ALCP_TEST_FUZZ_RSA_ENCRYPT) {
            err = alcp_rsa_publickey_encrypt_oaep(handle,
                                                  &fuzz_input[0],
                                                  size_encrypted_data,
                                                  &fuzz_label[0],
                                                  fuzz_label.size(),
                                                  &fuzz_seed[0],
                                                  &encrypted_text[0]);
            if (alcp_is_error(err)) {
                std::cout << "Error: alcp_rsa_publickey_encrypt_oaep"
                          << std::endl;
                goto dealloc;
            }
        } else if (EncDec == ALCP_TEST_FUZZ_RSA_DECRYPT) {
            err = alcp_rsa_publickey_encrypt_oaep(handle,
                                                  &fuzz_input[0],
                                                  size_encrypted_data,
                                                  &fuzz_label[0],
                                                  fuzz_label.size(),
                                                  &fuzz_seed[0],
                                                  &encrypted_text[0]);
            if (alcp_is_error(err)) {
                std::cout << "Error: alcp_rsa_publickey_encrypt_oaep"
                          << std::endl;
                goto dealloc;
            }
            err = alcp_rsa_privatekey_decrypt_oaep(handle,
                                                   &encrypted_text[0],
                                                   size_modulus,
                                                   &fuzz_label[0],
                                                   fuzz_label.size(),
                                                   &decrypted_text[0],
                                                   &decrypted_output_size);
            if (alcp_is_error(err)) {
                std::cout << "Error: alcp_rsa_privatekey_decrypt_oaep after "
                             "encrypt call"
                          << std::endl;
                goto dealloc;
            }
        } else {
            std::cout << "Invalid operation" << std::endl;
            goto dealloc;
        }
    }
    goto exit;

dealloc:
    alcp_rsa_finish(handle);
    free(handle->context);
    delete handle;
    return -1;

exit:
    alcp_rsa_finish(handle);
    free(handle->context);
    delete handle;
    std::cout << "Completed Rsa OAEP for Input size: " << size_encrypted_data
              << " and Modulus size " << size_modulus << std::endl;
    return 0;
}

int
ALCP_Fuzz_Rsa_SignVerify(int          PaddingMode,
                         const Uint8* buf,
                         size_t       len,
                         int          SignVerify,
                         bool         TestNegLifeCycle)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    std::vector<Uint8> fuzz_input = stream.ConsumeRemainingBytes<Uint8>();
    std::vector<Uint8> fuzz_salt  = stream.ConsumeRemainingBytes<Uint8>();

    /* key component sizes */
    size_t size_modulus = 256, size_p_modulus = 128;

    Uint64 PublicKeyExponent = pub_key_exp;

    /* signature output */
    std::vector<Uint8> signature_output(size_modulus, 0);

    alc_rsa_handle_p handle = new alc_rsa_handle_t;

    Uint64 size     = alcp_rsa_context_size();
    handle->context = malloc(size);

    err = alcp_rsa_request(handle);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_rsa_request" << std::endl;
        goto dealloc;
    }
    err = alcp_rsa_set_publickey(
        handle, PublicKeyExponent, fuzz_modulus, size_modulus);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_rsa_set_publickey" << std::endl;
        goto dealloc;
    }

    err = alcp_rsa_set_privatekey(handle,
                                  fuzz_dp_exp,
                                  fuzz_dq_exp,
                                  fuzz_p_modulus,
                                  fuzz_q_modulus,
                                  fuzz_q_mod_inv,
                                  fuzz_modulus,
                                  size_p_modulus);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_rsa_set_privatekey" << std::endl;
        goto dealloc;
    }

    err = alcp_rsa_add_digest(handle, ALC_SHA2_256);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_rsa_add_digest" << std::endl;
        goto dealloc;
    }
    err = alcp_rsa_add_mgf(handle, ALC_SHA2_256);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_rsa_add_mgf" << std::endl;
        goto dealloc;
    }

    if (TestNegLifeCycle) {
        if (SignVerify == ALCP_TEST_FUZZ_RSA_SIGN) {
            TestRsaSignLifecycle_0(handle,
                                   PaddingMode,
                                   &fuzz_input[0],
                                   fuzz_input.size(),
                                   &fuzz_salt[0],
                                   fuzz_salt.size(),
                                   &signature_output[0]);
        } else {
            TestRsaVerifyLifecycle_0(handle,
                                     PaddingMode,
                                     &fuzz_input[0],
                                     fuzz_input.size(),
                                     &fuzz_salt[0],
                                     fuzz_salt.size(),
                                     &signature_output[0]);
        }
    } else {
        if (PaddingMode == ALCP_TEST_RSA_PADDING_PSS) {
            err = alcp_rsa_privatekey_sign_pss(handle,
                                               true,
                                               &fuzz_input[0],
                                               fuzz_input.size(),
                                               &fuzz_salt[0],
                                               fuzz_salt.size(),
                                               &signature_output[0]);
            if (alcp_is_error(err)) {
                std::cout << "Error: alcp_rsa_privatekey_sign_pss" << std::endl;
                goto dealloc;
            }
            err = alcp_rsa_publickey_verify_pss(handle,
                                                &fuzz_input[0],
                                                fuzz_input.size(),
                                                &signature_output[0]);
            if (alcp_is_error(err)) {
                std::cout << "Error: alcp_rsa_publickey_verify_pss"
                          << std::endl;
                goto dealloc;
            }
        } else if (PaddingMode == ALCP_TEST_RSA_PADDING_PKCS) {
            err = alcp_rsa_privatekey_sign_pkcs1v15(handle,
                                                    true,
                                                    &fuzz_input[0],
                                                    fuzz_input.size(),
                                                    &signature_output[0]);
            if (alcp_is_error(err)) {
                std::cout << "Error: alcp_rsa_privatekey_sign_pkcs1v15"
                          << std::endl;
                goto dealloc;
            }
            err = alcp_rsa_publickey_verify_pkcs1v15(handle,
                                                     &fuzz_input[0],
                                                     fuzz_input.size(),
                                                     &signature_output[0]);
            if (alcp_is_error(err)) {
                std::cout << "Error: alcp_rsa_publickey_verify_pkcs1v15"
                          << std::endl;
                goto dealloc;
            }
        } else {
            std::cout << "Error: Invalid/Unsupported padding scheme for RSA "
                         "Sign/Verify"
                      << std::endl;
            goto dealloc;
        }
    }
    goto exit;

dealloc:
    alcp_rsa_finish(handle);
    free(handle->context);
    delete handle;
    return -1;

exit:
    alcp_rsa_finish(handle);
    free(handle->context);
    delete handle;
    return 0;
}

int
ALCP_Fuzz_Rsa_EncryptPubKey(const Uint8* buf, size_t len, bool TestNegLifeCycle)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);
    Uint64             size_key;

    size_t             size_input   = 256;
    std::vector<Uint8> fuzz_input   = stream.ConsumeBytes<Uint8>(size_input);
    size_t             size_modulus = 256;

    std::vector<Uint8> input(size_input, 0);
    std::vector<Uint8> encrypted_text(size_modulus, 0);

    Uint64 PublicKeyExponent = pub_key_exp;

    std::cout << "Running for Input size: " << size_input
              << " and Modulus size " << size_modulus << std::endl;

    alc_rsa_handle_p handle_encrypt = new alc_rsa_handle_t;

    Uint64 size             = alcp_rsa_context_size();
    handle_encrypt->context = malloc(size);
    err                     = alcp_rsa_request(handle_encrypt);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_rsa_request" << std::endl;
        goto out_enc;
    }

    if (TestNegLifeCycle) {
        TestRsaEncryptLifecycle_0(handle_encrypt,
                                  PublicKeyExponent,
                                  fuzz_modulus,
                                  size_modulus,
                                  &input[0],
                                  &encrypted_text[0]);
    } else {
        err = alcp_rsa_set_publickey(
            handle_encrypt, PublicKeyExponent, fuzz_modulus, size_modulus);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_set_publickey" << std::endl;
            goto free_enc;
        }
        size_key = alcp_rsa_get_key_size(handle_encrypt);
        if (size_key == 0) {
            std::cout << "Error: alcp_rsa_get_key_size" << std::endl;
            goto free_enc;
        }
        /* input buffer */
        input.resize(size_key);

        /* encrypted output */
        encrypted_text.resize(size_key);
        err = alcp_rsa_publickey_encrypt(
            handle_encrypt, &input[0], size_key, &encrypted_text[0]);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_publickey_encrypt" << std::endl;
            goto free_enc;
        }
    }
    goto out_enc;

free_enc:
    alcp_rsa_finish(handle_encrypt);
    if (handle_encrypt->context != nullptr)
        free(handle_encrypt->context);
    delete handle_encrypt;
    return -1;

out_enc:
    alcp_rsa_finish(handle_encrypt);
    if (handle_encrypt->context != nullptr)
        free(handle_encrypt->context);
    delete handle_encrypt;
    std::cout << "Rsa fuzz test passed for input " << size_input << std::endl;
    return 0;
}

int
ALCP_Fuzz_Rsa_DecryptPvtKey(const Uint8* buf, size_t len, bool TestNegLifeCycle)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);
    Uint64             size_key;
    size_t             size_encrypted_data = 256;
    std::vector<Uint8> fuzz_input =
        stream.ConsumeBytes<Uint8>(size_encrypted_data);

    /* key component sizes */
    size_t             size_modulus = 256, size_p_modulus = 128;
    size_t             size_label = stream.ConsumeIntegral<Uint16>();
    std::vector<Uint8> fuzz_label = stream.ConsumeBytes<Uint8>(size_label);

    std::vector<Uint8> encrypted_text(size_encrypted_data, 0);
    std::vector<Uint8> decrypted_text(size_encrypted_data, 0);

    std::cout << "Running decrypt for Input size: " << size_encrypted_data
              << " and Modulus size " << size_modulus << std::endl;

    alc_rsa_handle_p handle_decrypt = new alc_rsa_handle_t;

    Uint64 size             = alcp_rsa_context_size();
    handle_decrypt->context = malloc(size);
    err                     = alcp_rsa_request(handle_decrypt);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_rsa_request" << std::endl;
        goto free_decrypt;
    }

    if (TestNegLifeCycle) {
        TestRsaDecryptLifecycle_0(handle_decrypt,
                                  fuzz_dp_exp,
                                  fuzz_dq_exp,
                                  fuzz_p_modulus,
                                  fuzz_q_modulus,
                                  fuzz_q_mod_inv,
                                  fuzz_modulus,
                                  size_p_modulus,
                                  &encrypted_text[0],
                                  &decrypted_text[0]);
    } else {
        err = alcp_rsa_set_privatekey(handle_decrypt,
                                      fuzz_dp_exp,
                                      fuzz_dq_exp,
                                      fuzz_p_modulus,
                                      fuzz_q_modulus,
                                      fuzz_q_mod_inv,
                                      fuzz_modulus,
                                      size_p_modulus);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_set_privatekey" << std::endl;
            goto free_decrypt;
        }
        size_key = alcp_rsa_get_key_size(handle_decrypt);
        if (size_key == 0) {
            std::cout << "Error: alcp_rsa_get_key_size" << std::endl;
            goto free_decrypt;
        }
        /* encrypted text len is size of key */
        encrypted_text.resize(size_key);
        decrypted_text.resize(size_key);

        err = alcp_rsa_privatekey_decrypt(handle_decrypt,
                                          ALCP_RSA_PADDING_NONE,
                                          &encrypted_text[0],
                                          size_key,
                                          &decrypted_text[0]);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_privatekey_decrypt" << std::endl;
            goto free_decrypt;
        }
    }
    goto out_dec;

free_decrypt:
    alcp_rsa_finish(handle_decrypt);
    free(handle_decrypt->context);
    delete handle_decrypt;
    return -1;

out_dec:
    alcp_rsa_finish(handle_decrypt);
    free(handle_decrypt->context);
    delete handle_decrypt;
    std::cout << "Completed decrypt for Input size: " << size_encrypted_data
              << " and Modulus size " << size_modulus << std::endl;
    return 0;
}

/* RSA PKCS and PSS Encrypt/Decrypt */
int
ALCP_Fuzz_Rsa_EncryptDecrypt_PKCS(const Uint8* buf, size_t len, int EncDec)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);
    Uint64             size                = 0;
    size_t             random_pad_len      = stream.ConsumeIntegral<Uint16>();
    size_t             size_encrypted_data = stream.ConsumeIntegral<Uint16>();
    Uint64             dec_text_size       = 0;
    Uint8*             dec_text            = nullptr;
    Uint64             size_modulus        = 256;
    Uint64             PublicKeyExponent   = pub_key_exp;
    std::vector<Uint8> fuzz_input =
        stream.ConsumeBytes<Uint8>(size_encrypted_data);
    std::vector<Uint8> fuzz_random_pad =
        stream.ConsumeBytes<Uint8>(random_pad_len);
    /* key parameters */
    std::vector<Uint8> encrypted_text(size_encrypted_data, 0);
    std::vector<Uint8> decrypted_text(size_encrypted_data, 0);

    Uint64 Modulus_BigNum[sizeof(fuzz_modulus) / 8];
    BigNum modulus{};
    BigNum public_key{};

    /* Pvt key params */
    Uint64 size_dp = 128, size_dq = 128, size_p_mod = 128, size_q_mod = 128,
           size_qinv = 128;
    std::vector<Uint8> dp(size_dp);
    std::vector<Uint8> dq(size_dq);
    std::vector<Uint8> p_mod(size_p_mod);
    std::vector<Uint8> q_mod(size_q_mod);
    std::vector<Uint8> qinv(size_qinv);

    Uint64 DP_BigNum[size_dp / 8];
    Uint64 DQ_BigNum[size_dp / 8];
    Uint64 P_BigNum[size_dp / 8];
    Uint64 Q_BigNum[size_dp / 8];
    Uint64 QINV_BigNum[size_dp / 8];

    convert_to_bignum(&dp[0], DP_BigNum, size);
    convert_to_bignum(&dq[0], DQ_BigNum, size);
    convert_to_bignum(&p_mod[0], P_BigNum, size);
    convert_to_bignum(&q_mod[0], Q_BigNum, size);
    convert_to_bignum(&qinv[0], QINV_BigNum, size);

    BigNum dp_bn   = { DP_BigNum, size / 8 };
    BigNum dq_bn   = { DQ_BigNum, size / 8 };
    BigNum p_bn    = { P_BigNum, size / 8 };
    BigNum q_bn    = { Q_BigNum, size / 8 };
    BigNum qinv_bn = { QINV_BigNum, size / 8 };

    size                            = alcp_rsa_context_size();
    alc_rsa_handle_p handle_encrypt = new alc_rsa_handle_t;
    handle_encrypt->context         = malloc(size);
    err                             = alcp_rsa_request(handle_encrypt);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_rsa_privatekey_decrypt" << std::endl;
        goto dealloc_exit;
    }
    size = sizeof(size_modulus);
    /* FIXME: if we dont provide a proper sizes Modulus, this function will
     * fail, so for now not fuzzing the modulus length*/
    convert_to_bignum(fuzz_modulus, Modulus_BigNum, size);
    modulus    = { Modulus_BigNum, size / 8 };
    public_key = { &PublicKeyExponent, 1 };

    if (EncDec == ALCP_TEST_FUZZ_RSA_ENCRYPT) {
        err = alcp_rsa_set_bignum_public_key(
            handle_encrypt, &public_key, &modulus);
        if (alcp_is_error(err)) {
            std::cout << "alcp_rsa_set_bignum_public_key failed" << std::endl;
            goto dealloc_exit;
        }
        err = alcp_rsa_publickey_encrypt_pkcs1v15(handle_encrypt,
                                                  &fuzz_input[0],
                                                  size_encrypted_data,
                                                  &encrypted_text[0],
                                                  &fuzz_random_pad[0]);
        if (alcp_is_error(err)) {
            std::cout << "alcp_rsa_publickey_encrypt_pkcs1v15 failed"
                      << std::endl;
            goto dealloc_exit;
        }
    } else if (EncDec == ALCP_TEST_FUZZ_RSA_DECRYPT) {
        err = alcp_rsa_set_bignum_private_key(
            handle_encrypt, &dp_bn, &dq_bn, &p_bn, &q_bn, &qinv_bn, &modulus);
        if (alcp_is_error(err)) {
            std::cout << "alcp_rsa_set_bignum_private_key failed" << std::endl;
            goto dealloc_exit;
        }
        err = alcp_rsa_privatekey_decrypt_pkcs1v15(
            handle_encrypt, &encrypted_text[0], dec_text, &dec_text_size);
        if (alcp_is_error(err)) {
            std::cout << "alcp_rsa_privatekey_decrypt_pkcs1v15 failed"
                      << std::endl;
            goto dealloc_exit;
        }
    }
    goto exit;

dealloc_exit:
    alcp_rsa_finish(handle_encrypt);
    free(handle_encrypt->context);
    delete handle_encrypt;
    std::cout << "Failed decrypt for Input size: " << size_encrypted_data
              << std::endl;
    return -1;

exit:
    alcp_rsa_finish(handle_encrypt);
    free(handle_encrypt->context);
    delete handle_encrypt;
    std::cout << "Completed decrypt for Input size: " << size_encrypted_data
              << std::endl;
    return 0;
}

/* RSA DigestSign */
int
ALCP_Fuzz_Rsa_DigestSign(const Uint8* buf, size_t len, int PaddingMode)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);
    Uint64             size              = 0;
    Uint64             size_modulus      = 256;
    Uint64             PublicKeyExponent = pub_key_exp;

    /* Fuzz the hash to be signed */
    size_t             HashSize = stream.ConsumeIntegralInRange<Uint16>(32, 64);
    std::vector<Uint8> Hash(HashSize);

    /* key parameters */
    std::vector<Uint8> Signature(size_modulus, 0);

    Uint64 Modulus_BigNum[sizeof(fuzz_modulus) / 8];
    BigNum modulus{};
    BigNum public_key{};

    Uint64             salt_size = 256 - HashSize - 2;
    std::vector<Uint8> salt(salt_size);

    int index = 0, digest_info_size = 0;

    /* Pvt key params */
    Uint64 size_dp = 128, size_dq = 128, size_p_mod = 128, size_q_mod = 128,
           size_qinv = 128;
    std::vector<Uint8> dp(size_dp);
    std::vector<Uint8> dq(size_dq);
    std::vector<Uint8> p_mod(size_p_mod);
    std::vector<Uint8> q_mod(size_q_mod);
    std::vector<Uint8> qinv(size_qinv);

    Uint64 DP_BigNum[size_dp / 8];
    Uint64 DQ_BigNum[size_dp / 8];
    Uint64 P_BigNum[size_dp / 8];
    Uint64 Q_BigNum[size_dp / 8];
    Uint64 QINV_BigNum[size_dp / 8];

    convert_to_bignum(&dp[0], DP_BigNum, size);
    convert_to_bignum(&dq[0], DQ_BigNum, size);
    convert_to_bignum(&p_mod[0], P_BigNum, size);
    convert_to_bignum(&q_mod[0], Q_BigNum, size);
    convert_to_bignum(&qinv[0], QINV_BigNum, size);

    BigNum dp_bn   = { DP_BigNum, size / 8 };
    BigNum dq_bn   = { DQ_BigNum, size / 8 };
    BigNum p_bn    = { P_BigNum, size / 8 };
    BigNum q_bn    = { Q_BigNum, size / 8 };
    BigNum qinv_bn = { QINV_BigNum, size / 8 };

    /* for PKCS*/
    index            = alcp_rsa_get_digest_info_index(ALC_SHA2_256);
    digest_info_size = alcp_rsa_get_digest_info_size(ALC_SHA2_256);
    std::vector<Uint8> HashWithInfo(digest_info_size + HashSize, 0);
    memcpy(&HashWithInfo[0], DigestInfo[index], digest_info_size);
    memcpy(&HashWithInfo[0] + digest_info_size, &Hash[0], HashSize);

    size                    = alcp_rsa_context_size();
    alc_rsa_handle_p handle = new alc_rsa_handle_t;
    handle->context         = malloc(size);
    err                     = alcp_rsa_request(handle);
    if (alcp_is_error(err)) {
        std::cout << "Error: alcp_rsa_request" << std::endl;
        goto dealloc_exit;
    }
    size = sizeof(size_modulus);
    /* FIXME: if we dont provide a proper sizes Modulus, this function will
     * fail, so for now not fuzzing the modulus length*/
    convert_to_bignum(fuzz_modulus, Modulus_BigNum, size);
    modulus    = { Modulus_BigNum, size / 8 };
    public_key = { &PublicKeyExponent, 1 };

    err = alcp_rsa_set_bignum_public_key(handle, &public_key, &modulus);
    if (alcp_is_error(err)) {
        std::cout << "alcp_rsa_set_bignum_public_key failed" << std::endl;
        goto dealloc_exit;
    }
    err = alcp_rsa_set_bignum_private_key(
        handle, &dp_bn, &dq_bn, &p_bn, &q_bn, &qinv_bn, &modulus);
    if (alcp_is_error(err)) {
        std::cout << "alcp_rsa_set_bignum_private_key failed" << std::endl;
        goto dealloc_exit;
    }
    if (PaddingMode == ALCP_TEST_RSA_PADDING_PKCS) {
        err =
            alcp_rsa_privatekey_sign_hash_pkcs1v15(handle,
                                                   &HashWithInfo[0],
                                                   digest_info_size + HashSize,
                                                   &Signature[0]);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_privatekey_sign_hash_pkcs1v15"
                      << std::endl;
            goto dealloc_exit;
        }
        err =
            alcp_rsa_publickey_verify_hash_pkcs1v15(handle,
                                                    &HashWithInfo[0],
                                                    digest_info_size + HashSize,
                                                    &Signature[0]);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_publickey_verify_hash_pkcs1v15"
                      << std::endl;
            goto dealloc_exit;
        }
    } else if (PaddingMode == ALCP_TEST_RSA_PADDING_PSS) {
        err = alcp_rsa_add_digest(handle, ALC_SHA2_256);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_add_digest" << std::endl;
            goto dealloc_exit;
        }
        err = alcp_rsa_add_mgf(handle, ALC_SHA2_256);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_add_mgf" << std::endl;
            goto dealloc_exit;
        }
        err = alcp_rsa_privatekey_sign_hash_pss(handle,
                                                &Hash[0],
                                                Hash.size(),
                                                &salt[0],
                                                salt.size(),
                                                &Signature[0]);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_privatekey_sign_hash_pss"
                      << std::endl;
            goto dealloc_exit;
        }
        err = alcp_rsa_publickey_verify_hash_pss(
            handle, &Hash[0], HashSize, &Signature[0]);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_rsa_publickey_verify_hash_pss"
                      << std::endl;
            goto dealloc_exit;
        }
    }

    goto exit;

dealloc_exit:
    alcp_rsa_finish(handle);
    free(handle->context);
    delete handle;
    std::cout << "Failed DigestSignVerify" << std::endl;
    return -1;

exit:
    alcp_rsa_finish(handle);
    free(handle->context);
    delete handle;
    std::cout << "Completed DigestSignVerify" << std::endl;
    return 0;
}