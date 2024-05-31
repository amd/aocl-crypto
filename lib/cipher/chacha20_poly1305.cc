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
 *-
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/cipher/chacha20_poly1305.hh"
#include "alcp/base.hh"
#include <openssl/bio.h>

// #define DEBUG

namespace alcp::cipher::chacha20 {

using mac::poly1305::Poly1305;

namespace vaes512 {
#include "chacha20_poly1305.cc.inc"

    alc_error_t ChaCha20Poly1305AEAD::encrypt(alc_cipher_data_t* cipher_data,
                                              const Uint8*       pInput,
                                              Uint8*             pOutput,
                                              Uint64             len)
    {
        return ChaCha20Poly1305::processInput<true>(pInput, len, pOutput);
    }
    alc_error_t ChaCha20Poly1305AEAD::decrypt(alc_cipher_data_t* cipher_data,
                                              const Uint8*       pInput,
                                              Uint8*             pOutput,
                                              Uint64             len)
    {
        return ChaCha20Poly1305::processInput<false>(pInput, len, pOutput);
    }
} // namespace vaes512

namespace ref {
#include "chacha20_poly1305.cc.inc"

    alc_error_t ChaCha20Poly1305AEAD::encrypt(alc_cipher_data_t* cipher_data,
                                              const Uint8*       pInput,
                                              Uint8*             pOutput,
                                              Uint64             len)
    {
        return ChaCha20Poly1305::processInput<true>(pInput, len, pOutput);
    }
    alc_error_t ChaCha20Poly1305AEAD::decrypt(alc_cipher_data_t* cipher_data,
                                              const Uint8*       pInput,
                                              Uint8*             pOutput,
                                              Uint64             len)
    {
        return ChaCha20Poly1305::processInput<false>(pInput, len, pOutput);
    }
} // namespace ref

} // namespace alcp::cipher::chacha20
