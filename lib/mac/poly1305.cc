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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <algorithm>
#include <array>
#include <iostream>
#include <tuple>

#include <openssl/bio.h>
#include <openssl/bn.h>

#include "alcp/base.hh"
#include "alcp/mac/poly1305.hh"

// #define DEBUG

namespace alcp::mac::poly1305 {

#ifdef DEBUG
void
debug_dump(std::string str, BIGNUM* z)
{
    std::cout << str << "\t";
    BN_print_fp(stdout, z);
    std::cout << std::endl;
}
#else
void
debug_dump(std::string str, BIGNUM* z)
{
}
#endif

void
Poly1305::clamp(Uint8 in[16])
{
    constexpr std::array<std::tuple<int, int>, 7> index = {
        std::tuple<int, int>({ 3, 15 }),  std::tuple<int, int>({ 7, 15 }),
        std::tuple<int, int>({ 11, 15 }), std::tuple<int, int>({ 15, 15 }),
        std::tuple<int, int>({ 4, 252 }), std::tuple<int, int>({ 8, 252 }),
        std::tuple<int, int>({ 12, 252 })
    };

    for (const auto& i : index) {
        in[15 - std::get<0>(i)] &= std::get<1>(i);
    }
}

/**
 * @brief Sets the Key and Initializes the state of Poly1305
 * @param key - Key to use for Poly1305
 * @param len - Key Length 256 Bits, anything else wont work
 * @return Status
 */
Status
Poly1305::setKey(const Uint8 key[], Uint64 len)
{
    Status s = StatusOk();
    if (m_finalized) {
        s.update(status::InternalError("Cannot setKey after finalized!"));
        return s;
    }
    len = len / 8;
    if (len != 32) {
        s.update(status::InvalidArgument("Length does not match"));
        return s;
    }

    // Reverse bytes to make it a big number represntation
    std::reverse_copy(key, key + 16, m_key);
    std::reverse_copy(key + 16, key + 32, m_key + 16);
    clamp(m_key); // Clamp to ploynomial

    // Continue with initialization

    if (m_r_bn != nullptr) {
        BN_free(m_r_bn);
        m_r_bn = nullptr;
    }
    // r = k[0..16];
    m_r_bn = BN_bin2bn(m_key, 16, m_r_bn);

    debug_dump("R KE2:", m_r_bn);
    if (m_s_bn != nullptr) {
        BN_free(m_s_bn);
        m_s_bn = nullptr;
    }
    // s = k[17..32];
    m_s_bn = BN_bin2bn(m_key + 16, 16, m_s_bn);

    if (m_a_bn != nullptr) {
        BN_free(m_a_bn);
        m_a_bn = nullptr;
    }
    // a = 0;
    m_a_bn = BN_bin2bn(m_accumulator, 16, m_a_bn);

    debug_dump("A CRT:", m_a_bn);
    if (m_p_bn != nullptr) {
        BN_free(m_p_bn);
        m_p_bn = nullptr;
    }
    // p = (1<<130)-5
    m_p_bn = BN_bin2bn(m_p, sizeof(m_p), m_p_bn);

    debug_dump("P SHL:", m_p_bn);
    if (m_bn_temp_ctx != nullptr) {
        BN_CTX_free(m_bn_temp_ctx);
        m_bn_temp_ctx = nullptr;
    }

    // Create a temporary BigNumber context
    m_bn_temp_ctx = BN_CTX_new();

    return s;
}

Status
Poly1305::blk(const Uint8 pMsg[], Uint64 msgLen)
{
    Status       s           = StatusOk();
    const Uint8* msg_ptr_cpy = pMsg;
    BIGNUM*      n           = BN_new();
    for (Uint64 i = 0; i < ((msgLen + (16 - 1)) / 16); i++) {
        Uint8 n_buff[17] = {};

        // Find if we are in the last block, if we are, then only do left bytes
        Uint64 curr_blocklen = msgLen < ((i + 1) * 16) ? msgLen - ((i) * 16)
                                                       : 16;
#ifdef DEBUG
        std::cout << "Current Block Length:" << curr_blocklen << std::endl;
#endif
        std::reverse_copy(msg_ptr_cpy, msg_ptr_cpy + curr_blocklen, n_buff + 1);
        n_buff[0] = 0x01;
        n         = BN_bin2bn(n_buff, curr_blocklen + 1, n);
        debug_dump("N BLK:", n);

        // We select the next block
        msg_ptr_cpy += curr_blocklen;
        // a+=n
        BN_add(m_a_bn, m_a_bn, n);
        debug_dump("A ADD:", m_a_bn);
        // a = (a * r) % p
        BN_mod_mul(m_a_bn, m_a_bn, m_r_bn, m_p_bn, m_bn_temp_ctx);
        debug_dump("A END:", m_a_bn);
    }
    BN_free(n);
    return s;
}

Status
Poly1305::update(const Uint8 pMsg[], Uint64 msgLen)
{
    Status s = StatusOk();
    if (pMsg == nullptr || msgLen == 0) {
        return s;
    }

    if (m_finalized) {
        s.update(status::InternalError("Cannot update after finalized!"));
        return s;
    }

    if (m_msg_buffer_len != 0) {
        // We need to process the m_msg_buffer first
        Uint64 msg_buffer_left = (16 - m_msg_buffer_len);
        if (msgLen < msg_buffer_left) {
            std::copy(pMsg, pMsg + msgLen, m_msg_buffer + m_msg_buffer_len);
            m_msg_buffer_len += msgLen;
            // We ran out of the buffer to read
            return s;
        }
        std::copy(
            pMsg, pMsg + msg_buffer_left, m_msg_buffer + m_msg_buffer_len);

        pMsg += msg_buffer_left;
        msgLen -= msg_buffer_left;

        m_msg_buffer_len = 0;
        blk(m_msg_buffer, 16);
    }

    Uint64 overflow = msgLen % 16;
    blk(pMsg, msgLen - overflow);

    // If there is something left then put it into msg buffer
    pMsg   = pMsg + msgLen - overflow;
    msgLen = overflow;
    if (msgLen) {
        std::copy(pMsg, pMsg + msgLen, m_msg_buffer);
        m_msg_buffer_len = msgLen;
    }

    return s;
}

Status
Poly1305::reset()
{
    Status s = StatusOk();
    std::fill(m_accumulator, m_accumulator + 18, 0);
    // Wipe the accumulator
    m_a_bn           = BN_bin2bn(m_accumulator, 16, m_a_bn);
    m_msg_buffer_len = 0;
    m_finalized      = false;
    return s;
}

Status
Poly1305::finalize(const Uint8 pMsg[], Uint64 msgLen)
{
    Status s = StatusOk();
    if (m_finalized) {
        s.update(status::InternalError("Already finalized!"));
        return s;
    }
    s.update(update(pMsg, msgLen));
    if (!s.ok()) {
        return s;
    }
    blk(m_msg_buffer, m_msg_buffer_len);

    // a+=s;
    BN_add(m_a_bn, m_a_bn, m_s_bn);
    debug_dump("A FIN:", m_a_bn);
    BN_bn2bin(m_a_bn, m_accumulator);
    m_finalized = true;
    return s;
}

void
Poly1305::finish()
{
    if (m_key_bn != nullptr) {
        BN_free(m_key_bn);
        m_key_bn = nullptr;
    }
    if (m_a_bn != nullptr) {
        BN_free(m_a_bn);
        m_a_bn = nullptr;
    }
    if (m_r_bn != nullptr) {
        BN_free(m_r_bn);
        m_r_bn = nullptr;
    }
    if (m_s_bn != nullptr) {
        BN_free(m_s_bn);
        m_s_bn = nullptr;
    }
    if (m_p_bn != nullptr) {
        BN_free(m_p_bn);
        m_p_bn = nullptr;
    }
    if (m_bn_temp_ctx) {
        BN_CTX_free(m_bn_temp_ctx);
        m_bn_temp_ctx = nullptr;
    }
}

Status
Poly1305::copy(Uint8 digest[], Uint64 length)
{
    Status s = StatusOk();
    if (!m_finalized) {
        s.update(status::InternalError("Not finalized yet!"));
        return s;
    }
    if (length != 16) {
        s.update(status::InvalidArgument("Invalid Size for Poly1305"));
        return s;
    }
    std::reverse_copy(m_accumulator + 1, m_accumulator + 17, digest);
    return s;
}

Poly1305::~Poly1305()
{
    if (m_key_bn != nullptr) {
        BN_free(m_key_bn);
        m_key_bn = nullptr;
    }
    if (m_a_bn != nullptr) {
        BN_free(m_a_bn);
        m_a_bn = nullptr;
    }
    if (m_r_bn != nullptr) {
        BN_free(m_r_bn);
        m_r_bn = nullptr;
    }
    if (m_s_bn != nullptr) {
        BN_free(m_s_bn);
        m_s_bn = nullptr;
    }
    if (m_p_bn != nullptr) {
        BN_free(m_p_bn);
        m_p_bn = nullptr;
    }
    if (m_bn_temp_ctx) {
        BN_CTX_free(m_bn_temp_ctx);
        m_bn_temp_ctx = nullptr;
    }
}

} // namespace alcp::mac::poly1305
