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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <algorithm>
#include <array>
#include <tuple>

#include "mac/poly1305-ref.hh"

namespace alcp::mac::poly1305::reference {

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

/*
    Class Poly1305Common Functions
*/

void
Poly1305Common::clamp_rev(Uint8 in[16])
{
    constexpr std::array<std::tuple<int, int>, 7> cIndex = {
        std::tuple<int, int>({ 3, 15 }),  std::tuple<int, int>({ 7, 15 }),
        std::tuple<int, int>({ 11, 15 }), std::tuple<int, int>({ 15, 15 }),
        std::tuple<int, int>({ 4, 252 }), std::tuple<int, int>({ 8, 252 }),
        std::tuple<int, int>({ 12, 252 })
    };

    for (const auto& i : cIndex) {
        in[15 - std::get<0>(i)] &= std::get<1>(i);
    }
}

void
Poly1305Common::clamp(Uint8 in[16])
{
    constexpr std::array<std::tuple<int, int>, 7> cIndex = {
        std::tuple<int, int>({ 3, 15 }),  std::tuple<int, int>({ 7, 15 }),
        std::tuple<int, int>({ 11, 15 }), std::tuple<int, int>({ 15, 15 }),
        std::tuple<int, int>({ 4, 252 }), std::tuple<int, int>({ 8, 252 }),
        std::tuple<int, int>({ 12, 252 })
    };

    for (const auto& i : cIndex) {
        in[std::get<0>(i)] &= std::get<1>(i);
    }
}

/*
    Class Poly1305BNRef Functions

    Some insights into the implementation
        Implemented directly from RFC-8439 ChaCha20-Poly1305 for IETF Protocols
        OpenSSL bignum is used to implement the core algorithm on as it is basis
*/

Status
Poly1305BNRef::init(const Uint8 key[], Uint64 keyLen)
{
    Status s = StatusOk();
    if (m_finalized) {
        s.update(status::InternalError("Cannot setKey after finalized!"));
        return s;
    }
    keyLen = keyLen / 8;
    if (keyLen != 32) {
        s.update(status::InvalidArgument("Length does not match"));
        return s;
    }

    // Reverse bytes to make it a big number represntation
    std::reverse_copy(key, key + 16, m_key);
    std::reverse_copy(key + 16, key + 32, m_key + 16);
    clamp_rev(m_key); // Clamp to ploynomial

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
    m_p_bn = BN_bin2bn(cP, sizeof(cP), m_p_bn);

    debug_dump("P SHL:", m_p_bn);
    if (m_bn_temp_ctx != nullptr) {
        BN_CTX_free(m_bn_temp_ctx);
        m_bn_temp_ctx = nullptr;
    }

    // Create a temporary BigNumber context
    m_bn_temp_ctx = BN_CTX_new();

    return s;
}

// This blk can handle partial blocks also
Status
Poly1305BNRef::blk(const Uint8 pMsg[], Uint64 msgLen)
{
    Status       s             = StatusOk();
    const Uint8* p_msg_ptr_cpy = pMsg;
    BIGNUM*      p_n           = BN_new();

    // For loop until ceil of msgLen/16
    for (Uint64 i = 0; i < ((msgLen + (16 - 1)) / 16); i++) {
        Uint8 n_buff[17] = {};

        // Find if we are in the last block, if we are, then only do left
        // bytes
        Uint64 curr_blocklen = msgLen < ((i + 1) * 16) ? msgLen - ((i) * 16)
                                                       : 16;
#ifdef DEBUG
        std::cout << "Current Block Length:" << curr_blocklen << std::endl;
#endif
        std::reverse_copy(
            p_msg_ptr_cpy, p_msg_ptr_cpy + curr_blocklen, n_buff + 1);
        n_buff[0] = 0x01;
        p_n       = BN_bin2bn(n_buff, curr_blocklen + 1, p_n);
        debug_dump("N BLK:", p_n);

        // We select the next block
        p_msg_ptr_cpy += curr_blocklen;
        // a+=n
        BN_add(m_a_bn, m_a_bn, p_n);
        debug_dump("A ADD:", m_a_bn);
        // a = (a * r) % p
        BN_mod_mul(m_a_bn, m_a_bn, m_r_bn, m_p_bn, m_bn_temp_ctx);
        debug_dump("A END:", m_a_bn);
    }
    BN_free(p_n);
    return s;
}

Status
Poly1305BNRef::update(const Uint8 pMsg[], Uint64 msgLen)
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
Poly1305BNRef::finish(const Uint8 pMsg[], Uint64 msgLen)
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
    // Erasing will be taken care by the "State" destructor
}

Status
Poly1305BNRef::copy(Uint8 digest[], Uint64 length)
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

    int offset = 0;
    if (BN_num_bytes(m_a_bn) > static_cast<int>(length)) {
        offset = BN_num_bytes(m_a_bn) - static_cast<int>(length);
    }
    std::reverse_copy(
        m_accumulator + offset, m_accumulator + BN_num_bytes(m_a_bn), digest);

    return s;
}

Status
Poly1305BNRef::reset()
{
    Status s = StatusOk();
    std::fill(m_accumulator, m_accumulator + 18, 0);
    // Wipe the accumulator
    m_a_bn           = BN_bin2bn(m_accumulator, 16, m_a_bn);
    m_msg_buffer_len = 0;
    m_finalized      = false;
    return s;
}

/*
    Class Poly1305Ref Functions

    Poly1305 native C++ implementation.
        Based on https://github.com/floodyberry/poly1305-donna

    Helpful links in understanding Poly1305
            [1] https://loup-vaillant.fr/tutorials/poly1305-design
            [2] https://en.wikipedia.org/wiki/Poly1305
            [3] https://www.mdpi.com/2410-387X/6/2/30

    Modulo Trick described in [1] is used to compute multiply and modulo

    Key, Message, Accumulator are all processed in Radix(Base) 26 format
*/

Status
Poly1305Ref::init(const Uint8 key[], Uint64 keyLen)
{
    Uint8* p_m_key_8 = reinterpret_cast<Uint8*>(m_key);
    // Uint8* m_acc_8 = reinterpret_cast<Uint8*>(m_accumulator);
    Status s = StatusOk();
    if (m_finalized) {
        s.update(status::InternalError("Cannot setKey after finalized!"));
        return s;
    }
    keyLen = keyLen / 8;
    if (keyLen != 32) {
        s.update(status::InvalidArgument("Length does not match"));
        return s;
    }

    // r = k[0..16]
    std::copy(key, key + 16, p_m_key_8);

    // s = k[17..32]
    std::copy(key + 16, key + 32, p_m_key_8 + 16);

    // r = clamp(r)
    clamp(p_m_key_8); // Clamp to polynomial

    // a = 0
    std::fill(m_accumulator, m_accumulator + 5, 0);

    // P is already loaded

    // Copy key into 5 limbs
    {
        const Uint8* p_key_8 = reinterpret_cast<const Uint8*>(m_key);
        // FIXME: Optimize more
        for (int i = 0; i < 5; i++) {
            Uint8* p_r_8 = reinterpret_cast<Uint8*>(&m_r[i]);
            std::copy(p_key_8, p_key_8 + 4, p_r_8);
            m_r[i] = m_r[i] >> (2 * i);
            m_r[i] &= 0x3ffffff;
            p_key_8 += 3;
        }
    }

    // Precompute the r*5 value
    for (int i = 0; i < 4; i++) {
        m_s[i] = m_r[i + 1] * 5;
    }

    return s;
}

inline Uint64
poly1305_block(const Uint8 pMsg[],
               Uint64      msgLen,
               Uint64      accumulator[],
               Uint64      r[10],
               Uint64      s[8])
{
    Uint32       msg_temp[5] = {};
    const Uint8* p_msg_8     = pMsg;
    Uint64       d[5]        = {};
    Uint64       carry       = 0;
    const Uint64 cPadding    = (msgLen >= 16) << 24;

    // As long as there is poly block size amount of text to process
    while (msgLen > 0) {
        for (int i = 0; i < 5; i += 1) {
            Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp[i]);
            std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
            msg_temp[i] = (msg_temp[i] >> (2 * i));
            if (i != 4)
                msg_temp[i] &= 0x3ffffff;
            else {
                msg_temp[i] |= cPadding;
            }
            p_msg_8 += 3;
        }
        accumulator[0] += msg_temp[0];
        accumulator[1] += msg_temp[1];
        accumulator[2] += msg_temp[2];
        accumulator[3] += msg_temp[3];
        accumulator[4] += msg_temp[4];

        // a = a * r
        // clang-format off
            d[0] = (accumulator[0] * r[0]) + (accumulator[1] * s[3]) + (accumulator[2] * s[2]) + (accumulator[3] * s[1]) + (accumulator[4] * s[0]);
            d[1] = (accumulator[0] * r[1]) + (accumulator[1] * r[0]) + (accumulator[2] * s[3]) + (accumulator[3] * s[2]) + (accumulator[4] * s[1]);
            d[2] = (accumulator[0] * r[2]) + (accumulator[1] * r[1]) + (accumulator[2] * r[0]) + (accumulator[3] * s[3]) + (accumulator[4] * s[2]);
            d[3] = (accumulator[0] * r[3]) + (accumulator[1] * r[2]) + (accumulator[2] * r[1]) + (accumulator[3] * r[0]) + (accumulator[4] * s[3]);
            d[4] = (accumulator[0] * r[4]) + (accumulator[1] * r[3]) + (accumulator[2] * r[2]) + (accumulator[3] * r[1]) + (accumulator[4] * r[0]);
        // clang-format on

        // Carry Propagation
        carry          = (unsigned long)(d[0] >> 26);
        accumulator[0] = (unsigned long)d[0] & 0x3ffffff;
        d[1] += carry;
        carry          = (unsigned long)(d[1] >> 26);
        accumulator[1] = (unsigned long)d[1] & 0x3ffffff;
        d[2] += carry;
        carry          = (unsigned long)(d[2] >> 26);
        accumulator[2] = (unsigned long)d[2] & 0x3ffffff;
        d[3] += carry;
        carry          = (unsigned long)(d[3] >> 26);
        accumulator[3] = (unsigned long)d[3] & 0x3ffffff;
        d[4] += carry;
        carry          = (unsigned long)(d[4] >> 26);
        accumulator[4] = (unsigned long)d[4] & 0x3ffffff;
        accumulator[0] += carry * 5;
        carry          = (accumulator[0] >> 26);
        accumulator[0] = accumulator[0] & 0x3ffffff;
        accumulator[1] += carry;

        /* Padding is enabled only if message is bigger than 16 bytes, otherwise
         *   padding is expected from outside.
         * If messageLength is less than 16 bytes then a 16byte redable buffer
         * is expected. 16 bytes is taken inside with padding if msg len is less
         * than 16 bytes.
         */
        msgLen = msgLen >= 16 ? msgLen - 16 : 0;
        p_msg_8 += 1;
    }

    return msgLen;
}

Status
Poly1305Ref::update(const Uint8 pMsg[], Uint64 msgLen)
{
    Status status = StatusOk();

    if (m_finalized) {
        status.update(status::InternalError("Cannot update after finalized!"));
        return status;
    }

    if (m_msg_buffer_len != 0) {
        // We need to process the m_msg_buffer first
        Uint64 msg_buffer_left = (16 - m_msg_buffer_len);
        if (msgLen < msg_buffer_left) {
            std::copy(pMsg, pMsg + msgLen, m_msg_buffer + m_msg_buffer_len);
            m_msg_buffer_len += msgLen;
            // We ran out of the buffer to read
            return status;
        }
        std::copy(
            pMsg, pMsg + msg_buffer_left, m_msg_buffer + m_msg_buffer_len);

        pMsg += msg_buffer_left;
        msgLen -= msg_buffer_left;

        m_msg_buffer_len = 0;
        poly1305_block(m_msg_buffer, 16, m_accumulator, m_r, m_s);
    }

    Uint64 overflow = msgLen % 16;

    poly1305_block(pMsg, msgLen - overflow, m_accumulator, m_r, m_s);
    if (overflow) {
        std::copy(pMsg + msgLen - overflow, pMsg + msgLen, m_msg_buffer);
        m_msg_buffer_len = overflow;
    }

    return status;
}

Status
Poly1305Ref::finish(const Uint8 pMsg[], Uint64 msgLen)
{
    Status s = StatusOk();
    if (m_finalized) {
        s.update(status::InternalError("Cannot update after finalized!"));
        return s;
    }

    if (msgLen) {
        s.update(update(pMsg, msgLen));
    }

    if (m_msg_buffer_len) {
        m_msg_buffer[m_msg_buffer_len] = 0x01;
        std::fill(m_msg_buffer + m_msg_buffer_len + 1, m_msg_buffer + 16, 0);
        poly1305_block(m_msg_buffer, m_msg_buffer_len, m_accumulator, m_r, m_s);
        // update(m_msg_buffer, m_msg_buffer_len);
    }

    Uint64        acc[5]  = {};
    Uint64        temp[5] = {};
    Uint64        f;
    Uint64        carry;
    const Uint32* p_key_32 = reinterpret_cast<Uint32*>(m_key);

    for (int i = 0; i < 5; i++) {
        acc[i] = m_accumulator[i];
    }

    // Propagate carry from 1 to finish carry propation of addition
    carry  = acc[1] >> 26;
    acc[1] = acc[1] & 0x3ffffff;
    acc[2] += carry;
    carry  = acc[2] >> 26;
    acc[2] = acc[2] & 0x3ffffff;
    acc[3] += carry;
    carry  = acc[3] >> 26;
    acc[3] = acc[3] & 0x3ffffff;
    acc[4] += carry;
    carry  = acc[4] >> 26;
    acc[4] = acc[4] & 0x3ffffff;
    acc[0] += carry * 5;
    carry  = acc[0] >> 26;
    acc[0] = acc[0] & 0x3ffffff;
    acc[1] += carry;

    // acc -= (1<<130 -5) -> acc = acc - 1<<130 + 5
    // (1<<130-5) + 5 => (1<<130)
    temp[0] = acc[0] + 5;
    carry   = temp[0] >> 26;
    temp[0] &= 0x3ffffff;
    temp[1] = acc[1] + carry;
    carry   = temp[1] >> 26;
    temp[1] &= 0x3ffffff;
    temp[2] = acc[2] + carry;
    carry   = temp[2] >> 26;
    temp[2] &= 0x3ffffff;
    temp[3] = acc[3] + carry;
    carry   = temp[3] >> 26;
    temp[3] &= 0x3ffffff;
    // acc-(1<<130)
    temp[4] = acc[4] + carry - (1UL << 26);

    if ((temp[4] >> 63) == 0) {
        for (int i = 0; i < 5; i++) {
            acc[i] = temp[i];
        }
    }

    acc[0] = ((acc[0]) | (acc[1] << 26)) & 0xffffffff;
    acc[1] = ((acc[1] >> 6) | (acc[2] << 20)) & 0xffffffff;
    acc[2] = ((acc[2] >> 12) | (acc[3] << 14)) & 0xffffffff;
    acc[3] = ((acc[3] >> 18) | (acc[4] << 8)) & 0xffffffff;

    // digest = acc + s;
    f      = acc[0] + p_key_32[4];
    acc[0] = f;
    f      = acc[1] + p_key_32[5] + (f >> 32);
    acc[1] = f;
    f      = acc[2] + p_key_32[6] + (f >> 32);
    acc[2] = f;
    f      = acc[3] + p_key_32[7] + (f >> 32);
    acc[3] = f;

    for (int i = 0; i < 5; i++) {
        m_accumulator[i] = acc[i];
    }

    m_finalized = true;

    return s;
}

Status
Poly1305Ref::copy(Uint8 digest[], Uint64 len)
{
    Status s = StatusOk();
    if (!m_finalized) {
        s.update(status::InternalError("Not finalized yet!"));
        return s;
    }
    if (len != 16) {
        s.update(status::InvalidArgument("Invalid Size for Poly1305"));
        return s;
    }

    const Uint8* p_accumulator_8 = reinterpret_cast<Uint8*>(m_accumulator);

    std::copy(p_accumulator_8, p_accumulator_8 + 4, digest);
    std::copy(p_accumulator_8 + 8, p_accumulator_8 + 12, digest + 4);
    std::copy(p_accumulator_8 + 16, p_accumulator_8 + 20, digest + 8);
    std::copy(p_accumulator_8 + 24, p_accumulator_8 + 28, digest + 12);

    return s;
}

Status
Poly1305Ref::reset()
{
    Status s = StatusOk();
    resetState();
    return s;
}

} // namespace alcp::mac::poly1305::reference
