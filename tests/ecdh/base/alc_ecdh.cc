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

#include "ecdh/alc_ecdh.hh"
#include "alcp/ec.h"
#include "alcp/ecdh.h"
#include "ecdh/ecdh.hh"
#include <cstring>

namespace alcp::testing {

AlcpEcdhBase::AlcpEcdhBase(const alc_ec_info_t& info)
    : m_info{ info }
{}

bool
AlcpEcdhBase::init(const alc_ec_info_t& info)
{
    Uint8       err_buff[256];
    alc_error_t err;
    m_info              = info;
    alc_ec_info_t dinfo = m_info;
    Uint64        size  = alcp_ec_context_size(&dinfo);
    /* for peer1 */
    if (m_ec_handle == nullptr) {
        m_ec_handle          = new alc_ec_handle_t;
        m_ec_handle->context = malloc(size);
    } else if (m_ec_handle->context == nullptr) {
        m_ec_handle->context = malloc(size);
    }

    err = alcp_ec_request(&dinfo, m_ec_handle);
    if (alcp_is_error(err)) {
        /*FIXME: get a peerID to indicate which peer*/
        std::cout << "Error in alcp_ec_request:Peer1 " << err_buff << std::endl;
        return false;
    }
    return true;
}

AlcpEcdhBase::~AlcpEcdhBase()
{
    if (m_ec_handle != nullptr) {
        alcp_ec_finish(m_ec_handle);
        if (m_ec_handle->context != nullptr) {
            free(m_ec_handle->context);
            m_ec_handle->context = nullptr;
        }
        delete m_ec_handle;
    }
}

bool
AlcpEcdhBase::GeneratePublicKey(const alcp_ecdh_data_t& data)
{
    alc_error_t err;
    Uint8       err_buff[256];

    err = alcp_ec_get_publickey(
        m_ec_handle, data.m_Peer_PubKey, data.m_Peer_PvtKey);
    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_ec_get_publickey peer: " << err_buff
                  << std::endl;
        return false;
    }
    return true;
}

bool
AlcpEcdhBase::SetPrivateKey(Uint8 private_key[], Uint64 len)
{
    if (m_info.ecCurveId == ALCP_EC_CURVE25519) {
        // FIXME: Implement
        // FIXME: SetPrivKey method missing of X25519 ECC Curve
    } else {
        alc_error_t err;
        Uint8       err_buff[256];
        err = alcp_ec_set_privatekey(m_ec_handle, private_key);
        if (alcp_is_error(err)) {
            std::cout << "Error in alcp_ec_set_privatekey : " << err_buff
                      << std::endl;
            return err;
        }
    }
    return true;
    UNREF(len);
}

bool
AlcpEcdhBase::ComputeSecretKey(const alcp_ecdh_data_t& data_peer1,
                               const alcp_ecdh_data_t& data_peer2)
{
    alc_error_t err;
    Uint64      keyLength;
    Uint8       err_buff[256];

    err = alcp_ec_get_secretkey(m_ec_handle,
                                data_peer1.m_Peer_SecretKey,
                                data_peer2.m_Peer_PubKey,
                                &keyLength);

    if (alcp_is_error(err)) {
        std::cout << "Error in alcp_ec_get_secretkey : " << err_buff
                  << std::endl;
        return false;
    }

    if (m_info.ecCurveId == ALCP_EC_SECP256R1) {
        alcp_ec_finish(m_ec_handle);
        if (alcp_is_error(err)) {
            std::cout << "Error in alcp_ec_finish : " << err_buff << std::endl;
            return false;
        }
        free(m_ec_handle->context);
        delete m_ec_handle;
        m_ec_handle = nullptr;
    }

    return true;
}

bool
AlcpEcdhBase::reset()
{
    return true;
}

} // namespace alcp::testing
