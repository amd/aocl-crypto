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

alc_cipher_mode_t AES_Modes[5] = {
    ALC_AES_MODE_CFB,
    ALC_AES_MODE_CBC,
    ALC_AES_MODE_OFB,
    ALC_AES_MODE_CTR,
};
std::map<alc_cipher_mode_t, std::string> aes_mode_string_map = {
    { ALC_AES_MODE_CFB, "AES_CFB" },
    { ALC_AES_MODE_CBC, "AES_CBC" },
    { ALC_AES_MODE_OFB, "AES_OFB" },
    { ALC_AES_MODE_CTR, "AES_CTR" },
};

std::map<alc_cipher_mode_t, std::string> aes_aead_mode_string_map = {
    { ALC_AES_MODE_GCM, "AES_GCM" },
    { ALC_AES_MODE_CCM, "AES_CCM" },
    { ALC_AES_MODE_SIV, "AES_SIV" },
    { ALC_AES_MODE_XTS, "AES_XTS" },
};

bool
TestAEADCipherLifecycle_0(alc_cipher_handle_p handle,
                          Uint8*              key,
                          Uint64              keylen,
                          const Uint8*        plaintxt,
                          Uint8*              ciphertxt,
                          Uint64              pt_len,
                          const Uint8*        iv,
                          Uint64              ivl,
                          const Uint8*        ad,
                          Uint64              adl,
                          Uint8*              tag,
                          Uint64              tagl)
{
    if (alcp_is_error(alcp_cipher_aead_init(handle, key, keylen, iv, ivl))
        || alcp_is_error(alcp_cipher_aead_set_aad(handle, ad, adl))
        || alcp_is_error(
            alcp_cipher_aead_encrypt(handle, plaintxt, &ciphertxt[0], pt_len))
        || alcp_is_error(alcp_cipher_aead_get_tag(handle, &tag[0], tagl))) {
        std::cout << "Neg lifecycle Test FAIL! AEAD init->SetAD->Enc->GetTag"
                  << std::endl;
        return false;
    }
    return true;
}
bool
TestAEADCipherLifecycle_0_dec(alc_cipher_handle_p handle,
                              Uint8*              key,
                              Uint64              keylen,
                              const Uint8*        ciphertxt,
                              Uint8*              plaintxt,
                              Uint64              pt_len,
                              const Uint8*        iv,
                              Uint64              ivl,
                              const Uint8*        ad,
                              Uint64              adl,
                              Uint8*              tag,
                              Uint64              tagl)
{
    if (alcp_is_error(alcp_cipher_aead_init(handle, key, keylen, iv, ivl))
        || alcp_is_error(alcp_cipher_aead_set_aad(handle, ad, adl))
        || alcp_is_error(
            alcp_cipher_aead_decrypt(handle, ciphertxt, plaintxt, pt_len))
        || alcp_is_error(alcp_cipher_aead_get_tag(handle, &tag[0], tagl))) {
        std::cout << "Neg lifecycle Test FAIL! AEAD init->SetAD->Dec->GetTag"
                  << std::endl;
        return false;
    }
    return true;
}
bool
TestAEADCipherLifecycle_1(alc_cipher_handle_p handle,
                          Uint8*              key,
                          Uint64              keylen,
                          const Uint8*        plaintxt,
                          Uint8*              ciphertxt,
                          Uint64              pt_len,
                          const Uint8*        iv,
                          Uint64              ivl,
                          const Uint8*        ad,
                          Uint64              adl,
                          Uint8*              tag,
                          Uint64              tagl)
{
    if (alcp_is_error(alcp_cipher_aead_set_aad(handle, ad, adl))
        || alcp_is_error(
            alcp_cipher_aead_encrypt(handle, plaintxt, &ciphertxt[0], pt_len))
        || alcp_is_error(alcp_cipher_aead_get_tag(handle, &tag[0], tagl))) {
        std::cout << "Neg lifecycle Test FAIL! AEAD SetAD->Enc->GetTag on an "
                     "uninitialized handle"
                  << std::endl;
        return false;
    }
    return true;
}
bool
TestAEADCipherLifecycle_1_dec(alc_cipher_handle_p handle,
                              Uint8*              key,
                              Uint64              keylen,
                              const Uint8*        ciphertxt,
                              Uint8*              plaintxt,
                              Uint64              pt_len,
                              const Uint8*        iv,
                              Uint64              ivl,
                              const Uint8*        ad,
                              Uint64              adl,
                              Uint8*              tag,
                              Uint64              tagl)
{
    if (alcp_is_error(alcp_cipher_aead_set_aad(handle, ad, adl))
        || alcp_is_error(
            alcp_cipher_aead_encrypt(handle, ciphertxt, plaintxt, pt_len))
        || alcp_is_error(alcp_cipher_aead_get_tag(handle, &tag[0], tagl))) {
        std::cout << "Neg lifecycle Test FAIL! AEAD SetAD->Dec->GetTag on an "
                     "uninitialized handle"
                  << std::endl;
        return false;
    }
    return true;
}

bool
TestAEADCipherLifecycle_2(alc_cipher_handle_p handle,
                          Uint8*              key,
                          Uint64              keylen,
                          const Uint8*        ciphertxt,
                          Uint8*              plaintxt,
                          Uint64              pt_len,
                          const Uint8*        iv,
                          Uint64              ivl,
                          const Uint8*        ad,
                          Uint64              adl,
                          Uint8*              tag,
                          Uint64              tagl)
{
    /* try to call encrypt on a finished handle */
    alcp_cipher_aead_init(handle, key, keylen, iv, ivl);
    alcp_cipher_aead_set_aad(handle, ad, adl);
    alcp_cipher_aead_encrypt(handle, ciphertxt, plaintxt, pt_len);
    alcp_cipher_finish(handle);
    alcp_cipher_aead_encrypt(handle, ciphertxt, plaintxt, pt_len);
    return true;
}
bool
TestAEADCipherLifecycle_2_dec(alc_cipher_handle_p handle,
                              Uint8*              key,
                              Uint64              keylen,
                              const Uint8*        ciphertxt,
                              Uint8*              plaintxt,
                              Uint64              pt_len,
                              const Uint8*        iv,
                              Uint64              ivl,
                              const Uint8*        ad,
                              Uint64              adl,
                              Uint8*              tag,
                              Uint64              tagl)
{
    /* try to call encrypt on a finished handle */
    alcp_cipher_aead_init(handle, key, keylen, iv, ivl);
    alcp_cipher_aead_set_aad(handle, ad, adl);
    alcp_cipher_aead_encrypt(handle, ciphertxt, plaintxt, pt_len);
    alcp_cipher_finish(handle);
    alcp_cipher_aead_encrypt(handle, ciphertxt, plaintxt, pt_len);
    return true;
}

bool
TestCipherLifecycle_0(alc_cipher_handle_p handle,
                      Uint8*              key,
                      Uint64              keylen,
                      const Uint8*        plaintxt,
                      Uint8*              ciphertxt,
                      Uint64              pt_len,
                      const Uint8*        iv,
                      Uint64              ivl)
{
    if (alcp_is_error(alcp_cipher_encrypt(handle, plaintxt, ciphertxt, pt_len))
        || alcp_is_error(alcp_cipher_init(handle, key, keylen, iv, ivl))) {
        std::cout << "Neg lifecycle Test FAIL! Encrypt without init->Init"
                  << std::endl;
        return false;
    }
    return true;
}
bool
TestCipherLifecycle_0_dec(alc_cipher_handle_p handle,
                          Uint8*              key,
                          Uint64              keylen,
                          Uint8*              plaintxt,
                          const Uint8*        ciphertxt,
                          Uint64              pt_len,
                          const Uint8*        iv,
                          Uint64              ivl)
{
    if (alcp_is_error(alcp_cipher_decrypt(handle, ciphertxt, plaintxt, pt_len))
        || alcp_is_error(alcp_cipher_init(handle, key, keylen, iv, ivl))) {
        std::cout << "Neg lifecycle Test FAIL! Decrypt without init->Init"
                  << std::endl;
        return false;
    }
    return true;
}

bool
TestCipherLifecycle_1(alc_cipher_handle_p handle,
                      Uint8*              key,
                      Uint64              keylen,
                      const Uint8*        plaintxt,
                      Uint8*              ciphertxt,
                      Uint64              pt_len,
                      const Uint8*        iv,
                      Uint64              ivl)
{
    if (alcp_is_error(alcp_cipher_init(handle, key, keylen, iv, ivl))
        || alcp_is_error(
            alcp_cipher_encrypt(handle, plaintxt, ciphertxt, pt_len))
        || alcp_is_error(alcp_cipher_init(handle, key, keylen, iv, ivl))) {
        std::cout << "Neg lifecycle Test FAIL! Init->Encrypt->Init"
                  << std::endl;
        return false;
    }
    return true;
}
bool
TestCipherLifecycle_1_dec(alc_cipher_handle_p handle,
                          Uint8*              key,
                          Uint64              keylen,
                          Uint8*              plaintxt,
                          const Uint8*        ciphertxt,
                          Uint64              pt_len,
                          const Uint8*        iv,
                          Uint64              ivl)
{
    if (alcp_is_error(alcp_cipher_init(handle, key, keylen, iv, ivl))
        || alcp_is_error(
            alcp_cipher_decrypt(handle, ciphertxt, plaintxt, pt_len))
        || alcp_is_error(alcp_cipher_init(handle, key, keylen, iv, ivl))) {
        std::cout << "Neg lifecycle Test FAIL! Init->Decrypt->Init"
                  << std::endl;
        return false;
    }
    return true;
}

bool
TestCipherLifecycle_2(alc_cipher_handle_p handle,
                      Uint8*              key,
                      Uint64              keylen,
                      const Uint8*        plaintxt,
                      Uint8*              ciphertxt,
                      Uint64              pt_len,
                      const Uint8*        iv,
                      Uint64              ivl)
{
    /* try to call encrypt on a finished handle */
    alcp_cipher_init(handle, key, keylen, iv, ivl);
    alcp_cipher_encrypt(handle, plaintxt, ciphertxt, pt_len);
    alcp_cipher_finish(handle);
    alcp_cipher_encrypt(handle, plaintxt, ciphertxt, pt_len);
    return true;
}
bool
TestCipherLifecycle_2_dec(alc_cipher_handle_p handle,
                          Uint8*              key,
                          Uint64              keylen,
                          Uint8*              plaintxt,
                          const Uint8*        ciphertxt,
                          Uint64              pt_len,
                          const Uint8*        iv,
                          Uint64              ivl)
{
    /* try to call encrypt on a finished handle */
    alcp_cipher_init(handle, key, keylen, iv, ivl);
    alcp_cipher_decrypt(handle, ciphertxt, plaintxt, pt_len);
    alcp_cipher_finish(handle);
    alcp_cipher_encrypt(handle, ciphertxt, plaintxt, pt_len);
    return true;
}

int
ALCP_Fuzz_Cipher_Decrypt(alc_cipher_mode_t Mode,
                         const Uint8*      buf,
                         size_t            len,
                         bool              TestNeglifecycle)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t size_key = stream.ConsumeIntegralInRange<Uint16>(128, 256);
    size_t size_ct  = stream.ConsumeIntegral<Uint16>();
    size_t size_iv  = stream.ConsumeIntegral<Uint16>();

    std::vector<Uint8> fuzz_key = stream.ConsumeBytes<Uint8>(size_key);
    std::vector<Uint8> fuzz_ct  = stream.ConsumeBytes<Uint8>(size_ct);
    std::vector<Uint8> fuzz_iv  = stream.ConsumeBytes<Uint8>(size_iv);

    std::vector<Uint8> plaintxt(size_ct, 0);

    alc_cipher_handle_p handle_decrypt = new alc_cipher_handle_t;

    /* for decrypt */
    if (handle_decrypt == nullptr) {
        std::cout << "handle_decrypt is null" << std::endl;
        return -1;
    }
    handle_decrypt->ch_context = malloc(alcp_cipher_context_size());

    if (handle_decrypt->ch_context == NULL) {
        std::cout << "Error: Memory Allocation Failed" << std::endl;
        return -1;
    }

    std::cout << "Running for InputSize:" << fuzz_ct.size()
              << ",KeySize:" << fuzz_key.size() << ",IVLen:" << fuzz_iv.size()
              << std::endl;

    err = alcp_cipher_request(Mode, fuzz_key.size(), handle_decrypt);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_request failed for decrypt" << std::endl;
        goto DEC_ERROR_EXIT;
    }

    if (TestNeglifecycle) {
        if (!TestCipherLifecycle_1_dec(handle_decrypt,
                                       &fuzz_key[0],
                                       fuzz_key.size(),
                                       &plaintxt[0],
                                       &fuzz_ct[0],
                                       fuzz_ct.size(),
                                       &fuzz_iv[0],
                                       fuzz_iv.size()))
            goto DEC_ERROR_EXIT;
        if (!TestCipherLifecycle_1_dec(handle_decrypt,
                                       &fuzz_key[0],
                                       fuzz_key.size(),
                                       &plaintxt[0],
                                       &fuzz_ct[0],
                                       fuzz_ct.size(),
                                       &fuzz_iv[0],
                                       fuzz_iv.size()))
            goto DEC_ERROR_EXIT;
        if (!TestCipherLifecycle_0_dec(handle_decrypt,
                                       &fuzz_key[0],
                                       fuzz_key.size(),
                                       &plaintxt[0],
                                       &fuzz_ct[0],
                                       fuzz_ct.size(),
                                       &fuzz_iv[0],
                                       fuzz_iv.size()))
            goto DEC_ERROR_EXIT;
    } else {
        err = alcp_cipher_init(handle_decrypt,
                               &fuzz_key[0],
                               fuzz_key.size(),
                               &fuzz_iv[0],
                               fuzz_iv.size());
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_init failed for decrypt" << std::endl;
            goto DEC_ERROR_EXIT;
        }
        err = alcp_cipher_decrypt(
            handle_decrypt, &fuzz_ct[0], &plaintxt[0], fuzz_ct.size());
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_decrypt failed for decrypt" << std::endl;
            goto DEC_ERROR_EXIT;
        }
    }
    goto DEC_EXIT;

DEC_ERROR_EXIT:
    if (handle_decrypt != nullptr) {
        alcp_cipher_finish(handle_decrypt);
        if (handle_decrypt->ch_context != nullptr) {
            free(handle_decrypt->ch_context);
        }
        delete handle_decrypt;
    }
    return -1;

DEC_EXIT:
    if (handle_decrypt != nullptr) {
        alcp_cipher_finish(handle_decrypt);
        if (handle_decrypt->ch_context != nullptr) {
            free(handle_decrypt->ch_context);
        }
        delete handle_decrypt;
    }
    std::cout << "PASSED for decrypt for keylen " << fuzz_key.size()
              << std::endl;
    return 0;
}

int
ALCP_Fuzz_Cipher_Encrypt(alc_cipher_mode_t Mode,
                         const Uint8*      buf,
                         size_t            len,
                         bool              TestNeglifecycle)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t size_key = stream.ConsumeIntegralInRange<Uint16>(128, 256);
    size_t size_pt  = stream.ConsumeIntegral<Uint16>();
    size_t size_iv  = stream.ConsumeIntegral<Uint16>();

    std::vector<Uint8> fuzz_key = stream.ConsumeBytes<Uint8>(size_key);
    std::vector<Uint8> fuzz_pt  = stream.ConsumeBytes<Uint8>(size_pt);
    std::vector<Uint8> fuzz_iv  = stream.ConsumeBytes<Uint8>(size_iv);

    std::vector<Uint8> ciphertxt(size_pt, 0);

    const Uint8* plaintxt = fuzz_pt.data();

    alc_cipher_handle_p handle_encrypt = new alc_cipher_handle_t;

    if (handle_encrypt == nullptr) {
        std::cout << "handle_encrypt is null" << std::endl;
        return -1;
    }
    handle_encrypt->ch_context = malloc(alcp_cipher_context_size());
    if (handle_encrypt->ch_context == NULL) {
        std::cout << "Error: Memory Allocation Failed" << std::endl;
        return -1;
    }

    std::cout << "Running for Inputsize:" << fuzz_pt.size()
              << ",Keysize:" << fuzz_key.size() << ",IVLen:" << fuzz_iv.size()
              << std::endl;

    err = alcp_cipher_request(Mode, fuzz_key.size(), handle_encrypt);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_request failed for encrypt" << std::endl;
        goto ENC_ERROR_EXIT;
    }

    if (TestNeglifecycle) {
        if (!TestCipherLifecycle_2(handle_encrypt,
                                   &fuzz_key[0],
                                   fuzz_key.size(),
                                   plaintxt,
                                   &ciphertxt[0],
                                   fuzz_pt.size(),
                                   &fuzz_iv[0],
                                   fuzz_iv.size()))
            goto ENC_ERROR_EXIT;
        if (!TestCipherLifecycle_1(handle_encrypt,
                                   &fuzz_key[0],
                                   fuzz_key.size(),
                                   plaintxt,
                                   &ciphertxt[0],
                                   fuzz_pt.size(),
                                   &fuzz_iv[0],
                                   fuzz_iv.size()))
            goto ENC_ERROR_EXIT;
        if (!TestCipherLifecycle_0(handle_encrypt,
                                   &fuzz_key[0],
                                   fuzz_key.size(),
                                   plaintxt,
                                   &ciphertxt[0],
                                   fuzz_pt.size(),
                                   &fuzz_iv[0],
                                   fuzz_iv.size()))
            goto ENC_ERROR_EXIT;
    } else {
        err = alcp_cipher_init(handle_encrypt,
                               &fuzz_key[0],
                               fuzz_key.size(),
                               &fuzz_iv[0],
                               fuzz_iv.size());
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_init failed" << std::endl;
            goto ENC_ERROR_EXIT;
        }
        err = alcp_cipher_encrypt(
            handle_encrypt, plaintxt, &ciphertxt[0], fuzz_pt.size());
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_encrypt failed" << std::endl;
            goto ENC_ERROR_EXIT;
        }
    }
    goto ENC_EXIT;

ENC_ERROR_EXIT:
    if (handle_encrypt != nullptr) {
        alcp_cipher_finish(handle_encrypt);
        if (handle_encrypt->ch_context != nullptr) {
            free(handle_encrypt->ch_context);
        }
        delete handle_encrypt;
    }
    return -1;

ENC_EXIT:
    if (handle_encrypt != nullptr) {
        alcp_cipher_finish(handle_encrypt);
        if (handle_encrypt->ch_context != nullptr) {
            free(handle_encrypt->ch_context);
        }
        delete handle_encrypt;
    }
    return 0;
}

/* For all AEAD Ciphers */
int
ALCP_Fuzz_AEAD_Cipher_Encrypt(alc_cipher_mode_t Mode,
                              const Uint8*      buf,
                              size_t            len,
                              bool              TestNeglifecycle)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t size_key = stream.ConsumeIntegralInRange<Uint16>(128, 256);
    size_t size_pt  = stream.ConsumeIntegralInRange<Uint16>(1, 1024);
    size_t size_ad  = stream.ConsumeIntegralInRange<Uint16>(128, 256);

    size_t size_iv  = stream.ConsumeIntegral<Uint16>();
    size_t size_tag = 16;

    std::vector<Uint8> fuzz_key = stream.ConsumeBytes<Uint8>(size_key);
    std::vector<Uint8> fuzz_pt  = stream.ConsumeBytes<Uint8>(size_pt);
    std::vector<Uint8> fuzz_iv  = stream.ConsumeBytes<Uint8>(size_iv);
    std::vector<Uint8> fuzz_ad  = stream.ConsumeBytes<Uint8>(size_ad);

    std::vector<Uint8> tag(size_tag, 0);
    std::vector<Uint8> ciphertxt(size_pt, 0);

    /* Initializing the fuzz seeds  */
    const Uint32 keySize  = fuzz_key.size();
    const Uint8* plaintxt = fuzz_pt.data();
    const Uint32 pt_len   = fuzz_pt.size();

    Uint32       ivl  = fuzz_iv.size();
    const Uint8* ad   = fuzz_ad.data();
    Uint32       adl  = fuzz_ad.size();
    Uint32       tagl = tag.size();

    alc_cipher_handle_p handle_encrypt = new alc_cipher_handle_t;

    if (handle_encrypt == nullptr) {
        std::cout << "handle_encrypt is null" << std::endl;
        return -1;
    }
    handle_encrypt->ch_context = malloc(alcp_cipher_aead_context_size());
    if (handle_encrypt->ch_context == NULL) {
        std::cout << "Error: Memory Allocation Failed" << std::endl;
        return -1;
    }

    std::cout << "Running for Input size: " << pt_len << " and Key size "
              << keySize << " and IV Len " << ivl << " And ADL: " << adl
              << std::endl;

    err = alcp_cipher_aead_request(Mode, fuzz_key.size(), handle_encrypt);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_request failed for encrypt "
                  << std::endl;
        goto AEAD_ENC_ERROR_EXIT;
    }

    if (TestNeglifecycle) {
        if (!TestAEADCipherLifecycle_2(handle_encrypt,
                                       &fuzz_key[0],
                                       fuzz_key.size(),
                                       plaintxt,
                                       &ciphertxt[0],
                                       fuzz_pt.size(),
                                       &fuzz_iv[0],
                                       fuzz_iv.size(),
                                       ad,
                                       adl,
                                       &tag[0],
                                       tagl))
            goto AEAD_ENC_ERROR_EXIT;
        if (!TestAEADCipherLifecycle_1(handle_encrypt,
                                       &fuzz_key[0],
                                       fuzz_key.size(),
                                       plaintxt,
                                       &ciphertxt[0],
                                       fuzz_pt.size(),
                                       &fuzz_iv[0],
                                       fuzz_iv.size(),
                                       ad,
                                       adl,
                                       &tag[0],
                                       tagl))
            goto AEAD_ENC_ERROR_EXIT;
        if (!TestAEADCipherLifecycle_0(handle_encrypt,
                                       &fuzz_key[0],
                                       fuzz_key.size(),
                                       plaintxt,
                                       &ciphertxt[0],
                                       fuzz_pt.size(),
                                       &fuzz_iv[0],
                                       fuzz_iv.size(),
                                       ad,
                                       adl,
                                       &tag[0],
                                       tagl))
            goto AEAD_ENC_ERROR_EXIT;
    } else {
        err = alcp_cipher_aead_init(handle_encrypt,
                                    &fuzz_key[0],
                                    fuzz_key.size(),
                                    &fuzz_iv[0],
                                    fuzz_iv.size());
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_aead_init failed" << std::endl;
            goto AEAD_ENC_ERROR_EXIT;
        }
        err = alcp_cipher_aead_set_aad(handle_encrypt, ad, adl);
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_aead_set_aad failed" << std::endl;
            goto AEAD_ENC_ERROR_EXIT;
        }
        err = alcp_cipher_aead_encrypt(
            handle_encrypt, plaintxt, &ciphertxt[0], len);
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_aead_encrypt failed" << std::endl;
            goto AEAD_ENC_ERROR_EXIT;
        }
        err = alcp_cipher_aead_get_tag(handle_encrypt, &tag[0], tagl);
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_aead_get_tag failed" << std::endl;
            goto AEAD_ENC_ERROR_EXIT;
        }
    }
    goto AEAD_ENC_EXIT;

AEAD_ENC_ERROR_EXIT:
    if (handle_encrypt != nullptr) {
        // alcp_cipher_finish(handle_encrypt); --> FIXME: this should be a neg
        // lifecycle test
        if (handle_encrypt->ch_context != nullptr) {
            free(handle_encrypt->ch_context);
        }
        delete handle_encrypt;
    }
    return -1;

AEAD_ENC_EXIT:
    if (handle_encrypt != nullptr) {
        alcp_cipher_aead_finish(handle_encrypt);
        if (handle_encrypt->ch_context != nullptr) {
            free(handle_encrypt->ch_context);
        }
        delete handle_encrypt;
    }
    return 0;
}

int
ALCP_Fuzz_AEAD_Cipher_Decrypt(alc_cipher_mode_t Mode,
                              const Uint8*      buf,
                              size_t            len,
                              bool              TestNeglifecycle)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    size_t size_key = stream.ConsumeIntegralInRange<Uint16>(128, 256);
    size_t size_ct  = stream.ConsumeIntegralInRange<Uint16>(1, 1024);
    size_t size_iv  = stream.ConsumeIntegral<Uint16>();
    size_t size_ad  = stream.ConsumeIntegral<Uint16>();
    size_t size_tag = 16;

    std::vector<Uint8> fuzz_ct  = stream.ConsumeBytes<Uint8>(size_ct);
    std::vector<Uint8> fuzz_key = stream.ConsumeBytes<Uint8>(size_key);
    std::vector<Uint8> fuzz_iv  = stream.ConsumeBytes<Uint8>(size_iv);
    std::vector<Uint8> fuzz_ad  = stream.ConsumeBytes<Uint8>(size_ad);

    std::vector<Uint8> decrypted_tag(size_tag, 0);
    std::vector<Uint8> plaintxt(size_ct, 0);

    /* Initializing the fuzz seeds  */
    const Uint32 keySize   = fuzz_key.size();
    Uint8*       ciphertxt = fuzz_ct.data();
    const Uint32 ct_len    = fuzz_ct.size();
    const Uint8* ad        = fuzz_ad.data();
    const Uint32 adl       = fuzz_ad.size();

    alc_cipher_handle_p handle_decrypt = new alc_cipher_handle_t;

    /* for decrypt */
    if (handle_decrypt == nullptr) {
        std::cout << "handle_decrypt is null" << std::endl;
        return -1;
    }
    handle_decrypt->ch_context = malloc(alcp_cipher_aead_context_size());

    if (handle_decrypt->ch_context == NULL) {
        std::cout << "Error: Memory Allocation Failed" << std::endl;
        return -1;
    }

    std::cout << "Running for Input size:" << ct_len << ",Key size:" << keySize
              << ",IV Len:" << fuzz_iv.size() << ",ADL:" << adl << std::endl;

    err = alcp_cipher_aead_request(Mode, fuzz_key.size(), handle_decrypt);
    if (alcp_is_error(err)) {
        std::cout << "alcp_cipher_aead_request failed for decrypt" << std::endl;
        goto AEAD_DEC_ERROR_EXIT;
    }

    if (TestNeglifecycle) {
        if (!TestAEADCipherLifecycle_2(handle_decrypt,
                                       &fuzz_key[0],
                                       fuzz_key.size(),
                                       &plaintxt[0],
                                       ciphertxt,
                                       fuzz_ct.size(),
                                       &fuzz_iv[0],
                                       fuzz_iv.size(),
                                       ad,
                                       adl,
                                       &decrypted_tag[0],
                                       size_tag))
            goto AEAD_DEC_ERROR_EXIT;
        if (!TestAEADCipherLifecycle_1(handle_decrypt,
                                       &fuzz_key[0],
                                       fuzz_key.size(),
                                       &plaintxt[0],
                                       ciphertxt,
                                       fuzz_ct.size(),
                                       &fuzz_iv[0],
                                       fuzz_iv.size(),
                                       ad,
                                       adl,
                                       &decrypted_tag[0],
                                       size_tag))
            goto AEAD_DEC_ERROR_EXIT;
        if (!TestAEADCipherLifecycle_0(handle_decrypt,
                                       &fuzz_key[0],
                                       fuzz_key.size(),
                                       &plaintxt[0],
                                       ciphertxt,
                                       fuzz_ct.size(),
                                       &fuzz_iv[0],
                                       fuzz_iv.size(),
                                       ad,
                                       adl,
                                       &decrypted_tag[0],
                                       size_tag))
            goto AEAD_DEC_ERROR_EXIT;
    } else {
        err = alcp_cipher_aead_init(handle_decrypt,
                                    &fuzz_key[0],
                                    fuzz_key.size(),
                                    &fuzz_iv[0],
                                    fuzz_iv.size());
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_aead_init failed for decrypt"
                      << std::endl;
            goto AEAD_DEC_ERROR_EXIT;
        }
        err = alcp_cipher_aead_set_aad(handle_decrypt, &ad[0], adl);
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_aead_set_aad failed for decrypt"
                      << std::endl;
            goto AEAD_DEC_ERROR_EXIT;
        }
        err = alcp_cipher_aead_decrypt(
            handle_decrypt, ciphertxt, &plaintxt[0], ct_len);
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_aead_decrypt failed" << std::endl;
            goto AEAD_DEC_ERROR_EXIT;
        }
        err = alcp_cipher_aead_get_tag(
            handle_decrypt, &decrypted_tag[0], size_tag);
        if (alcp_is_error(err)) {
            std::cout << "alcp_cipher_aead_get_tag failed for decrypt"
                      << std::endl;
            goto AEAD_DEC_ERROR_EXIT;
        }
    }
    goto AEAD_DEC_EXIT;

AEAD_DEC_ERROR_EXIT:
    if (handle_decrypt != nullptr) {
        alcp_cipher_aead_finish(handle_decrypt);
        if (handle_decrypt->ch_context != nullptr) {
            free(handle_decrypt->ch_context);
        }
        delete handle_decrypt;
    }
    return -1;

AEAD_DEC_EXIT:
    if (handle_decrypt != nullptr) {
        alcp_cipher_aead_finish(handle_decrypt);
        if (handle_decrypt->ch_context != nullptr) {
            free(handle_decrypt->ch_context);
        }
        delete handle_decrypt;
    }
    std::cout << "Operation passed for AEAD decrypt for keylen "
              << fuzz_key.size() << std::endl;
    return 0;
}
