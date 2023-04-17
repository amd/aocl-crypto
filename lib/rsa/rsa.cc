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
#include "alcp/rsa.hh"
#include "alcp/rsa/rsaerror.hh"
#include "alcp/utils/copy.hh"
#include "config.h"
#include <string.h>

namespace alcp::rsa {

static const Uint8 Modulus[] = {
    0xdb, 0xa4, 0x2f, 0x17, 0xde, 0x7d, 0x1e, 0xc9, 0x06, 0x8c, 0xbd, 0x49,
    0x64, 0xdb, 0xf4, 0xd3, 0x48, 0x0d, 0x50, 0xaf, 0x95, 0xeb, 0x30, 0x9c,
    0x71, 0x21, 0xc5, 0xbf, 0xf4, 0x1a, 0xca, 0xdf, 0x30, 0xa2, 0x04, 0x62,
    0xd5, 0xd5, 0x9c, 0xbd, 0x59, 0xeb, 0x8e, 0x1c, 0x96, 0xe3, 0x77, 0x09,
    0x18, 0x30, 0xe0, 0xac, 0xd3, 0xa1, 0x06, 0xfe, 0xda, 0xf7, 0x7d, 0xaa,
    0xd3, 0x01, 0xcd, 0xa7, 0x45, 0xbd, 0x1c, 0xac, 0x80, 0x8c, 0xb7, 0x2e,
    0x52, 0xfc, 0x93, 0x88, 0x02, 0x87, 0xeb, 0xb3, 0xdc, 0x61, 0x27, 0xc5,
    0xea, 0x89, 0xa7, 0x2d, 0x82, 0xc2, 0xed, 0xf5, 0x23, 0xe2, 0xd6, 0xc0,
    0x9c, 0x1a, 0x3f, 0xc6, 0x64, 0xda, 0xe0, 0x49, 0x08, 0xdd, 0x7e, 0x3e,
    0xd9, 0x0e, 0x42, 0xee, 0x49, 0x49, 0xf7, 0x8c, 0xe0, 0xcc, 0xaf, 0x4d,
    0x8d, 0x6c, 0xb0, 0x52, 0xb3, 0x50, 0xec, 0x8f
};

static const Uint8 PrivateKeyExponent[] = {
    0x7c, 0xb4, 0xb9, 0xb0, 0x59, 0xb8, 0xbc, 0xb3, 0xf2, 0xae, 0x12, 0x03,
    0x0b, 0xea, 0xff, 0x14, 0xbf, 0x02, 0x20, 0x5f, 0xb1, 0x45, 0x39, 0xf2,
    0x79, 0x21, 0x6d, 0xbf, 0xd0, 0xff, 0x2d, 0x54, 0x8f, 0xae, 0x4d, 0xc3,
    0x38, 0x19, 0xf2, 0xc6, 0x67, 0xb9, 0xa0, 0x94, 0x86, 0xef, 0x5b, 0x74,
    0xa4, 0x71, 0x8b, 0xff, 0x54, 0xa1, 0x46, 0xf1, 0x88, 0xad, 0xa0, 0x82,
    0x4f, 0x0f, 0xe5, 0x0d, 0x18, 0xcc, 0xf8, 0xae, 0x81, 0x81, 0xb6, 0x41,
    0x51, 0xb9, 0x01, 0xc5, 0x7b, 0x8b, 0xfa, 0x04, 0xd5, 0x60, 0xca, 0xc6,
    0xb5, 0x65, 0x08, 0x92, 0x02, 0xf4, 0xde, 0xff, 0x3f, 0xd6, 0x05, 0x1c,
    0xdd, 0x3d, 0x0b, 0x8a, 0xef, 0x72, 0xb1, 0x62, 0xd2, 0xd0, 0x35, 0x27,
    0x63, 0x9c, 0x99, 0x07, 0xe8, 0x3b, 0x66, 0x19, 0x0e, 0x81, 0xc5, 0xa4,
    0x80, 0xf0, 0x00, 0xfc, 0x67, 0x77, 0x46, 0xa1
};

static const Uint64 PublicKeyExponent = 65537;

Rsa::Rsa()
{
    m_pub_key.fromUint64(PublicKeyExponent);
    m_mod.fromUint8Ptr(Modulus, sizeof(Modulus));
    m_priv_key.fromUint8Ptr(PrivateKeyExponent, sizeof(PrivateKeyExponent));
    m_key_size = sizeof(PrivateKeyExponent);
}

Rsa::~Rsa()
{
    reset();
}

Status
Rsa::encrBufWithPub(alc_rsa_encr_dcr_padding pad,
                    const RsaPublicKey&      pubKey,
                    const Uint8*             pText,
                    Uint64                   textSize,
                    Uint8*                   pEncText)
{
    // For non padded output
    if (textSize > pubKey.size) {
        return status::NotPermitted("Text size should be equal to modulus");
    }

    BigNum raw_buff;
    raw_buff.fromUint8Ptr(pText, textSize);

    BigNum pub_key_exponent;
    pub_key_exponent.fromUint64(pubKey.public_exponent);

    BigNum pub_key_modulus;
    pub_key_modulus.fromUint8Ptr(pubKey.modulus, pubKey.size);

    BigNum res;
    res.exp_mod(raw_buff, pub_key_exponent, pub_key_modulus);

    res.toUint8Ptr(pEncText, textSize);

    return StatusOk();
}

Status
Rsa::decrBufWithPriv(alc_rsa_encr_dcr_padding pad,
                     const Uint8*             pEncText,
                     Uint64                   encSize,
                     Uint8*                   pText)
{

    // For non padded output
    if (encSize > m_mod.size()) {
        return status::NotPermitted("Text size should be equal modulous");
    }

    BigNum raw_buff;
    raw_buff.fromUint8Ptr(pEncText, encSize);

    BigNum res;
    res.exp_mod(raw_buff, m_priv_key, m_mod);

    res.toUint8Ptr(pText, encSize);

    return StatusOk();
}

Status
Rsa::getPublickey(RsaPublicKey& pPublicKey)
{

    if (pPublicKey.size != m_key_size) {
        return status::NotPermitted("keyize should match");
    }

    pPublicKey.public_exponent = PublicKeyExponent;

    m_mod.toUint8Ptr(pPublicKey.modulus, pPublicKey.size);

    return StatusOk();
}

void
Rsa::reset()
{
    // Todo rest the big num here
}

Uint64
Rsa::getKeySize()
{
    return m_key_size;
}

} // namespace alcp::rsa
