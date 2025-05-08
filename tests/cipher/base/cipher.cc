/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include "cipher/cipher.hh"
#include "alcp/alcp.h"
#include <sstream>
#ifdef USE_IPP
#include "cipher/ipp_cipher.hh"
#endif
#ifdef WIN32
#include <direct.h>
#endif

namespace alcp::testing {

/* to check if cipher type is non-AES
 TO DO: Update this when we have more non-AES types */
bool
isNonAESCipherType(alc_cipher_mode_t mode)
{
    switch (mode) {
        case ALC_CHACHA20:
        case ALC_CHACHA20_POLY1305:
            return true;
        default:
            return false;
    }
}

/**
 * returns respective string based on AES modes
 */
std::string
GetModeSTR(alc_cipher_mode_t mode)
{
    switch (mode) {
        case ALC_AES_MODE_ECB:
            return "ECB";
        case ALC_AES_MODE_CBC:
            return "CBC";
        case ALC_AES_MODE_OFB:
            return "OFB";
        case ALC_AES_MODE_CTR:
            return "CTR";
        case ALC_AES_MODE_CFB:
            return "CFB";
        case ALC_AES_MODE_XTS:
            return "XTS";
        case ALC_AES_MODE_GCM:
            return "GCM";
        case ALC_AES_MODE_CCM:
            return "CCM";
        case ALC_AES_MODE_SIV:
            return "SIV";
        case ALC_CHACHA20:
            return "Chacha20";
        case ALC_CHACHA20_POLY1305:
            return "chacha20-poly1305";
        default:
            return "";
    }
}

/** check if cipher mode is AEAD **/
bool
CheckCipherIsAEAD(alc_cipher_mode_t mode)
{
    switch (mode) {
        case ALC_AES_MODE_ECB:
        case ALC_AES_MODE_CBC:
        case ALC_AES_MODE_OFB:
        case ALC_AES_MODE_CTR:
        case ALC_AES_MODE_CFB:
        case ALC_AES_MODE_XTS:
        case ALC_CHACHA20:
            return false;
        case ALC_AES_MODE_GCM:
        case ALC_AES_MODE_CCM:
        case ALC_AES_MODE_SIV:
        case ALC_CHACHA20_POLY1305:
            return true;
        default:
            return false;
    }
    return false;
}

// CipherTesting class functions
CipherTesting::CipherTesting(CipherBase* impl)
{
    setcb(impl);
}

bool
CipherTesting::testingEncrypt(alcp_dc_ex_t& data, const std::vector<Uint8> key)
{
    if (cb != nullptr) {
        if (cb->init(data.m_iv,
                     data.m_ivl,
                     &(key[0]),
                     key.size() * 8,
                     data.m_tkey,
                     data.m_block_size)) {
            // For very large sizes, dynamic is better.
            return cb->encrypt(data);
        } else {
            std::cout << "Test: Cipher: Encrypt: Failure in Init" << std::endl;
        }
    } else {
        std::cout << "base.hh: CipherTesting: Implementation missing!"
                  << std::endl;
    }
    return false;
}

bool
CipherTesting::testingDecrypt(alcp_dc_ex_t& data, const std::vector<Uint8> key)
{
    if (cb != nullptr) {
        if (cb->init(data.m_iv,
                     data.m_ivl,
                     &(key[0]),
                     key.size() * 8,
                     data.m_tkey,
                     data.m_block_size)) {
            return cb->decrypt(data);
        }
    } else {
        std::cout << "base.hh: CipherTesting: Implementation missing!"
                  << std::endl;
    }
    return false;
}

void
CipherTesting::setcb(CipherBase* impl)
{
    cb = impl;
}

bool
CipherAeadBase::isAead(const alc_cipher_mode_t& mode)
{
    switch (mode) {
        case ALC_AES_MODE_GCM:
        case ALC_AES_MODE_SIV:
        case ALC_AES_MODE_CCM:
        case ALC_CHACHA20_POLY1305:
            return true;
        default:
            return false;
    }
}

} // namespace alcp::testing
