
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

bool
TestEcLifecycle(alc_ec_handle_p handle_peer1,
                alc_ec_handle_p handle_peer2,
                Uint8*          fuzz_pvtkey_data_peer1,
                Uint8*          fuzz_pvtkey_data_peer2,
                Uint8*          fuzz_pubkey_data_peer1,
                Uint8*          fuzz_pubkey_data_peer2,
                Uint8*          secret_key_peer1,
                Uint8*          secret_key_peer2,
                Uint64          key_size)
{
    Uint64 secret_key_len_peer1, secret_key_len_peer2;
    /* FIXME: this has to be changed once existing bugs are fixed */
    if (alcp_is_error(
            alcp_ec_set_privatekey(handle_peer1, &fuzz_pvtkey_data_peer1[0]))
        || alcp_is_error(
            alcp_ec_set_privatekey(handle_peer2, &fuzz_pvtkey_data_peer2[0]))
        || alcp_is_error(alcp_ec_get_publickey(handle_peer1,
                                               &fuzz_pubkey_data_peer1[0],
                                               &fuzz_pvtkey_data_peer1[0]))
        || alcp_is_error(alcp_ec_get_publickey(handle_peer2,
                                               &fuzz_pubkey_data_peer2[0],
                                               &fuzz_pvtkey_data_peer2[0]))
        || alcp_is_error(alcp_ec_get_secretkey(handle_peer1,
                                               secret_key_peer1,
                                               &fuzz_pubkey_data_peer2[0],
                                               &secret_key_len_peer1))
        || alcp_is_error(alcp_ec_get_secretkey(handle_peer2,
                                               secret_key_peer2,
                                               &fuzz_pubkey_data_peer1[0],
                                               &secret_key_len_peer2))) {
        std::cout << "EC Neg lifecycle Test FAIL!" << std::endl;
        return false;
    }
    return true;
}

int
ALCP_Fuzz_Ec_x25519(const Uint8* buf, size_t len, bool TestNegLifecycle)
{
    alc_error_t        err;
    FuzzedDataProvider stream(buf, len);

    /* supported key size is 32, still this should not cause a crash */
    size_t key_size = stream.ConsumeIntegral<Uint16>();
    Uint64 size;
    Uint8  secret_key_peer1[key_size];
    Uint64 key_len_peer1;
    Uint8  secret_key_peer2[key_size];
    Uint64 key_len_peer2;

    std::vector<Uint8> fuzz_pubkey_data_peer1 =
        stream.ConsumeBytes<Uint8>(key_size);
    std::vector<Uint8> fuzz_pvtkey_data_peer1 =
        stream.ConsumeBytes<Uint8>(key_size);

    /* Peer 2 */
    std::vector<Uint8> fuzz_pubkey_data_peer2 =
        stream.ConsumeBytes<Uint8>(key_size);
    std::vector<Uint8> fuzz_pvtkey_data_peer2 =
        stream.ConsumeBytes<Uint8>(key_size);

    std::cout << "Generating for Key size: " << key_size << std::endl;

    /* handles for peers */
    alc_ec_handle_p handle_peer1 = new alc_ec_handle_t;
    alc_ec_handle_p handle_peer2 = new alc_ec_handle_t;

    alc_ec_info_t ecinfo = {
        .ecCurveId     = ALCP_EC_CURVE25519,
        .ecCurveType   = ALCP_EC_CURVE_TYPE_MONTGOMERY,
        .ecPointFormat = ALCP_EC_POINT_FORMAT_UNCOMPRESSED,
    };

    size                  = alcp_ec_context_size(&ecinfo);
    handle_peer1->context = malloc(size);
    if (handle_peer1->context == nullptr) {
        std::cout << "Handle1 allocation failed" << std::endl;
        goto dealloc_exit;
    }

    handle_peer2->context = malloc(size);
    if (handle_peer2->context == nullptr) {
        std::cout << "Handle2 allocation failed" << std::endl;
        goto dealloc_exit;
    }

    if (TestNegLifecycle) {
        if (!TestEcLifecycle(handle_peer1,
                             handle_peer2,
                             &fuzz_pvtkey_data_peer1[0],
                             &fuzz_pvtkey_data_peer2[0],
                             &fuzz_pubkey_data_peer1[0],
                             &fuzz_pubkey_data_peer2[0],
                             secret_key_peer1,
                             secret_key_peer2,
                             key_size)) {
            goto dealloc_exit;
        }
    } else {
        /* set keys for peer1 */
        err = alcp_ec_set_privatekey(handle_peer1, &fuzz_pvtkey_data_peer1[0]);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_ec_set_privatekey for peer1" << std::endl;
            goto dealloc_exit;
        }

        err = alcp_ec_get_publickey(handle_peer1,
                                    &fuzz_pubkey_data_peer1[0],
                                    &fuzz_pvtkey_data_peer1[0]);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_ec_get_publickey for peer1" << std::endl;
            goto dealloc_exit;
        }

        /* Peer 2*/
        err = alcp_ec_set_privatekey(handle_peer2, &fuzz_pvtkey_data_peer2[0]);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_ec_set_privatekey for peer2" << std::endl;
            goto dealloc_exit;
        }

        err = alcp_ec_get_publickey(handle_peer2,
                                    &fuzz_pubkey_data_peer2[0],
                                    &fuzz_pvtkey_data_peer2[0]);
        if (alcp_is_error(err)) {
            std::cout << "Error: alcp_ec_get_publickey for peer2" << std::endl;
            goto dealloc_exit;
        }

        /* compute secret key */
        err = alcp_ec_get_secretkey(handle_peer1,
                                    secret_key_peer1,
                                    &fuzz_pubkey_data_peer2[0],
                                    &key_len_peer1);
        if (alcp_is_error(err)) {
            std::cout << "peer1 secretkey computation failed" << std::endl;
            goto dealloc_exit;
        }

        err = alcp_ec_get_secretkey(handle_peer2,
                                    secret_key_peer2,
                                    &fuzz_pubkey_data_peer1[0],
                                    &key_len_peer2);
        if (alcp_is_error(err)) {
            std::cout << "peer2 secretkey computation failed" << std::endl;
            goto dealloc_exit;
        }
    }
    goto out;

dealloc_exit:
    if (handle_peer1->context != nullptr) {
        alcp_ec_finish(handle_peer1);
        free(handle_peer1->context);
    }
    if (handle_peer2->context != nullptr) {
        alcp_ec_finish(handle_peer2);
        free(handle_peer2->context);
    }
    std::cout << "Failed fuzz test for Key size: " << key_size << std::endl;
    return -1;

out:
    if (handle_peer1->context != nullptr) {
        alcp_ec_finish(handle_peer1);
        free(handle_peer1->context);
    }
    if (handle_peer2->context != nullptr) {
        alcp_ec_finish(handle_peer2);
        free(handle_peer2->context);
    }
    std::cout << "Passed case for Key size: " << key_size << std::endl;
    return 0;
}