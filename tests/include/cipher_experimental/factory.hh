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

#pragma once

#include <memory>

// ALCP Implementations for UAI
#include "cipher_experimental/alc_cipher_gcm.hh"
#include "cipher_experimental/alc_cipher_xts.hh"

// OpenSSL Implementations for UAI
#if USE_OSSL
#include "cipher_experimental/openssl_cipher_gcm.hh"
#endif

// IPP-CP Implementations for UAI
#if USE_IPP
#include "cipher_experimental/ipp_cipher_gcm.hh"
#endif

namespace alcp::testing::cipher {

enum class LibrarySelect
{
    ALCP    = 0,
    OPENSSL = 1,
    IPP     = 2,
};

template<typename C1, typename C2, typename C3>
std::unique_ptr<ITestCipher>
CipherFactory(LibrarySelect selection)
{
    switch (selection) {
        case LibrarySelect::ALCP:
            return std::make_unique<C1>();
        case LibrarySelect::OPENSSL:
#if USE_OSSL
            return std::make_unique<C2>();
#else
            return nullptr;
#endif
        case LibrarySelect::IPP:
#if USE_IPP
            return std::make_unique<C3>();
#else
            return nullptr;
#endif
        default:
            return nullptr;
    }
}

namespace gcm {
    template<bool encryptor>
    std::unique_ptr<ITestCipher> GcmCipherFactory(LibrarySelect selection)
    {
        return CipherFactory<AlcpGcmCipher<encryptor>,
#if USE_OSSL
                             OpenSSLGcmCipher<encryptor>,
#else
                             AlcpGcmCipher<encryptor>,
#endif
#if USE_IPP
                             IppGcmCipher<encryptor>>(selection);
#else
                             AlcpGcmCipher<encryptor>>(selection);
#endif
    }
} // namespace gcm

namespace xts {
    template<bool encryptor>
    std::unique_ptr<ITestCipher> XtsCipherFactory(LibrarySelect selection)
    {
        return CipherFactory<
            AlcpXtsCipher<encryptor>,

            // #if USE_OSSL
            //                              OpenSSLXtsCipher<encryptor>,
            // #else
            AlcpXtsCipher<encryptor>,
            // #endif
            // #if USE_IPP
            //                              IppXtsCipher<encryptor>>(selection);
            // #else
            AlcpXtsCipher<encryptor>>(selection);
        // #endif
    }
} // namespace xts

} // namespace alcp::testing::cipher