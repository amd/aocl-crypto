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

class Poly1305BNRefState
{
  private:
    static const Uint32 m_cAccSize = 18;
    static const Uint32 m_cKeySize = 32;
    static const Uint32 m_cMsgSize = 16;

  protected:
    Uint8  m_accumulator[m_cAccSize] = {};
    Uint8  m_key[m_cKeySize]         = {};
    Uint8  m_msg_buffer[m_cMsgSize]  = {};
    Uint64 m_msg_buffer_len          = {};
    bool   m_finalized               = false;

    // Temp Bignums
    BN_CTX* m_bn_temp_ctx = nullptr;
    BIGNUM *m_key_bn = nullptr, *m_a_bn = nullptr, *m_r_bn = nullptr,
           *m_s_bn = nullptr, *m_p_bn = nullptr;

  public:
    Poly1305BNRefState() = default;
    ~Poly1305BNRefState()
    {
        std::fill(m_accumulator, m_accumulator + m_cAccSize, 0);
        std::fill(m_key, m_key + m_cKeySize, 0);
        std::fill(m_msg_buffer, m_msg_buffer + m_cMsgSize, 0);
        if (m_key_bn != nullptr) {
            BN_free(m_key_bn);
            m_key_bn = nullptr; // Clearing memory pointer
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
        if (m_bn_temp_ctx != nullptr) {
            BN_CTX_free(m_bn_temp_ctx);
            m_bn_temp_ctx = nullptr;
        }
        m_finalized = false;
    }
};

class Poly1305RefState
{
  private:
    static const Uint32 m_cAccSize_bytes = 40;
    static const Uint32 m_cKeySize_bytes = 32;
    static const Uint32 m_cMsgSize_bytes = 16;

  protected:
    alignas(64) Uint64 m_accumulator[m_cAccSize_bytes / sizeof(Uint64)] = {};
    alignas(64) Uint64 m_key[m_cKeySize_bytes / sizeof(Uint64)]         = {};
    alignas(64) Uint8 m_msg_buffer[m_cMsgSize_bytes]                    = {};
    Uint64 m_msg_buffer_len                                             = {};
    bool   m_finalized                                                  = false;

  public:
    Poly1305RefState() = default;
    void resetState()
    {
        std::fill(m_accumulator,
                  m_accumulator + m_cAccSize_bytes / sizeof(Uint64),
                  0);
        std::fill(m_msg_buffer, m_msg_buffer + m_cMsgSize_bytes, 0);
        m_msg_buffer_len = 0;
        m_finalized      = false;
    }
    ~Poly1305RefState()
    {
        std::fill(m_key, m_key + m_cKeySize_bytes / sizeof(Uint64), 0);
        resetState();
    }
};

class Poly1305Common
{
  protected:
    alignas(64) const Uint8 cP[17] = { 0x03, 0xff, 0xff, 0xff, 0xff, 0xff,
                                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                       0xff, 0xff, 0xff, 0xff, 0xfb };

  public:
    void clamp_rev(Uint8 in[16])
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
    void clamp(Uint8 in[16])
    {
        constexpr std::array<std::tuple<int, int>, 7> index = {
            std::tuple<int, int>({ 3, 15 }),  std::tuple<int, int>({ 7, 15 }),
            std::tuple<int, int>({ 11, 15 }), std::tuple<int, int>({ 15, 15 }),
            std::tuple<int, int>({ 4, 252 }), std::tuple<int, int>({ 8, 252 }),
            std::tuple<int, int>({ 12, 252 })
        };

        for (const auto& i : index) {
            in[std::get<0>(i)] &= std::get<1>(i);
        }
    }
};

class Poly1305BNRef
    : public IPoly1305
    , public Poly1305Common
    , public Poly1305BNRefState
{
  public:
    Status init(const Uint8 key[], Uint64 keyLen)
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
    Status blk(const Uint8 pMsg[], Uint64 msgLen)
    {
        Status       s             = StatusOk();
        const Uint8* p_msg_ptr_cpy = pMsg;
        BIGNUM*      n             = BN_new();

        // For loop until ceil of msgLen/16
        for (Uint64 i = 0; i < ((msgLen + (16 - 1)) / 16); i++) {
            Uint8 n_buff[17] = {};

            // Find if we are in the last block, if we are, then only do left
            // bytes
            Uint64 curr_blocklen = msgLen < ((i + 1) * 16) ? msgLen - ((i)*16)
                                                           : 16;
#ifdef DEBUG
            std::cout << "Current Block Length:" << curr_blocklen << std::endl;
#endif
            std::reverse_copy(
                p_msg_ptr_cpy, p_msg_ptr_cpy + curr_blocklen, n_buff + 1);
            n_buff[0] = 0x01;
            n         = BN_bin2bn(n_buff, curr_blocklen + 1, n);
            debug_dump("N BLK:", n);

            // We select the next block
            p_msg_ptr_cpy += curr_blocklen;
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

    Status update(const Uint8 pMsg[], Uint64 msgLen)
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
    Status finish(const Uint8 pMsg[], Uint64 msgLen)
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

    Status copy(Uint8 digest[], Uint64 length)
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
        std::reverse_copy(m_accumulator + offset,
                          m_accumulator + BN_num_bytes(m_a_bn),
                          digest);

        return s;
    }

    Status reset()
    {
        Status s = StatusOk();
        std::fill(m_accumulator, m_accumulator + 18, 0);
        // Wipe the accumulator
        m_a_bn           = BN_bin2bn(m_accumulator, 16, m_a_bn);
        m_msg_buffer_len = 0;
        m_finalized      = false;
        return s;
    }
};

class Poly1305Ref
    : public IPoly1305
    , public Poly1305Common
    , public Poly1305RefState
{
  public:
    Status init(const Uint8 key[], Uint64 keyLen)
    {
        Uint8* m_key_8 = reinterpret_cast<Uint8*>(m_key);
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

#if 0
        std::reverse_copy(key, key + 16, m_key_8);
        std::reverse_copy(key + 16, key + 32, m_key_8 + 16);
#else
        // r = k[0..16]
        std::copy(key, key + 16, m_key_8);

        // s = k[17..32]
        std::copy(key + 16, key + 32, m_key_8 + 16);
#endif
        // r = clamp(r)
        clamp(m_key_8); // Clamp to polynomial

        // a = 0
        std::fill(m_accumulator, m_accumulator + 5, 0);

        // P is already loaded

        return s;
    }

    Uint64 blk(const Uint8 pMsg[], Uint64 msgLen)
    {
        Uint64       r[5]        = {};
        Uint64       s[4]        = {};
        Uint64       acc[5]      = {};
        Uint32       msg_temp[5] = {};
        const Uint8* p_msg_8     = pMsg;
        Uint64       d[5]        = {};
        Uint64       carry       = 0;
        const Uint64 padding     = (msgLen >= 16) << 24;

        // Copy key into 5 limbs
        {
            const Uint8* p_key_8 = reinterpret_cast<const Uint8*>(m_key);
            // FIXME: Optimize more
            for (int i = 0; i < 5; i++) {
                Uint8* p_r_8 = reinterpret_cast<Uint8*>(&r[i]);
                std::copy(p_key_8, p_key_8 + 4, p_r_8);
                r[i] = r[i] >> (2 * i);
                r[i] &= 0x3ffffff;
                p_key_8 += 3;
            }
        }

        // Precompute the r*5 value
        for (int i = 0; i < 4; i++) {
            s[i] = r[i + 1] * 5;
        }

        // Copy Accumulator into local variable
        for (int i = 0; i < 5; i++) {
            acc[i] = m_accumulator[i];
        }

        // if (msg_yet_to_be_processed) {
        // copy rest of it to m_msg
        // process m_msg
        // sub rest of it from msgLen
        // }

        // As long as there is poly block size amount of text to process
        while (msgLen > 0) {
            for (int i = 0; i < 5; i += 1) {
                Uint8* p_msg_temp_8 = reinterpret_cast<Uint8*>(&msg_temp[i]);
                std::copy(p_msg_8, p_msg_8 + 4, p_msg_temp_8);
                msg_temp[i] = (msg_temp[i] >> (2 * i));
                if (i != 4)
                    msg_temp[i] &= 0x3ffffff;
                else {
                    msg_temp[i] |= padding;
                }
                p_msg_8 += 3;
            }
            acc[0] += msg_temp[0];
            acc[1] += msg_temp[1];
            acc[2] += msg_temp[2];
            acc[3] += msg_temp[3];
            acc[4] += msg_temp[4];

            /* h *= r */
            // clang-format off
            d[0] = (acc[0] * r[0]) + (acc[1] * s[3]) + (acc[2] * s[2]) + (acc[3] * s[1]) + (acc[4] * s[0]);
            d[1] = (acc[0] * r[1]) + (acc[1] * r[0]) + (acc[2] * s[3]) + (acc[3] * s[2]) + (acc[4] * s[1]);
            d[2] = (acc[0] * r[2]) + (acc[1] * r[1]) + (acc[2] * r[0]) + (acc[3] * s[3]) + (acc[4] * s[2]);
            d[3] = (acc[0] * r[3]) + (acc[1] * r[2]) + (acc[2] * r[1]) + (acc[3] * r[0]) + (acc[4] * s[3]);
            d[4] = (acc[0] * r[4]) + (acc[1] * r[3]) + (acc[2] * r[2]) + (acc[3] * r[1]) + (acc[4] * r[0]);
            // clang-format on

            // Carry Propagation
            carry  = (unsigned long)(d[0] >> 26);
            acc[0] = (unsigned long)d[0] & 0x3ffffff;
            d[1] += carry;
            carry  = (unsigned long)(d[1] >> 26);
            acc[1] = (unsigned long)d[1] & 0x3ffffff;
            d[2] += carry;
            carry  = (unsigned long)(d[2] >> 26);
            acc[2] = (unsigned long)d[2] & 0x3ffffff;
            d[3] += carry;
            carry  = (unsigned long)(d[3] >> 26);
            acc[3] = (unsigned long)d[3] & 0x3ffffff;
            d[4] += carry;
            carry  = (unsigned long)(d[4] >> 26);
            acc[4] = (unsigned long)d[4] & 0x3ffffff;
            acc[0] += carry * 5;
            carry  = (acc[0] >> 26);
            acc[0] = acc[0] & 0x3ffffff;
            acc[1] += carry;

            msgLen = msgLen >= 16 ? msgLen - 16 : 0;
            p_msg_8 += 1;
        }

        for (int i = 0; i < 5; i++) {
            m_accumulator[i] = acc[i];
        }

        return msgLen;
    }

    Status update(const Uint8 pMsg[], Uint64 msgLen)
    {
        Status status = StatusOk();

        if (m_finalized) {
            status.update(
                status::InternalError("Cannot update after finalized!"));
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
            blk(m_msg_buffer, 16);
        }

        Uint64 overflow = msgLen % 16;

#if 1
        blk(pMsg, msgLen - overflow);
#else
        for (Uint64 i = 0; i < msgLen / 16; i++)
            blk(pMsg + i * 16, 16);
#endif

        if (overflow) {
            std::copy(pMsg + msgLen - overflow, pMsg + msgLen, m_msg_buffer);
            m_msg_buffer_len = overflow;
        }

        return status;
    }

    Status finish(const Uint8 pMsg[], Uint64 msgLen)
    {
        Status s = StatusOk();
        if (m_finalized) {
            s.update(status::InternalError("Cannot update after finalized!"));
            return s;
        }

        if (msgLen) {
            update(pMsg, msgLen);
        }

        if (m_msg_buffer_len) {
            m_msg_buffer[m_msg_buffer_len] = 0x01;
            std::fill(
                m_msg_buffer + m_msg_buffer_len + 1, m_msg_buffer + 16, 0);
            blk(m_msg_buffer, m_msg_buffer_len);
            // update(m_msg_buffer, m_msg_buffer_len);
        }

        Uint64        acc[5]  = {};
        Uint64        temp[5] = {};
        Uint64        f;
        Uint64        carry;
        const Uint32* key_32 = reinterpret_cast<Uint32*>(m_key);

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
        f      = acc[0] + key_32[4];
        acc[0] = f;
        f      = acc[1] + key_32[5] + (f >> 32);
        acc[1] = f;
        f      = acc[2] + key_32[6] + (f >> 32);
        acc[2] = f;
        f      = acc[3] + key_32[7] + (f >> 32);
        acc[3] = f;

        for (int i = 0; i < 5; i++) {
            m_accumulator[i] = acc[i];
        }

        m_finalized = true;

        return s;
    }
    Status copy(Uint8 digest[], Uint64 len)
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

        const Uint8* accumulator_8 = reinterpret_cast<Uint8*>(m_accumulator);

        std::copy(accumulator_8, accumulator_8 + 4, digest);
        std::copy(accumulator_8 + 8, accumulator_8 + 12, digest + 4);
        std::copy(accumulator_8 + 16, accumulator_8 + 20, digest + 8);
        std::copy(accumulator_8 + 24, accumulator_8 + 28, digest + 12);

        return s;
    }
    Status reset()
    {
        Status s = StatusOk();
        resetState();
        return s;
    }
};

Poly1305::Poly1305()
{
    poly1305_impl = std::make_unique<Poly1305Ref>();
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
    return poly1305_impl->init(key, len);
}

Status
Poly1305::update(const Uint8 pMsg[], Uint64 msgLen)
{
    return poly1305_impl->update(pMsg, msgLen);
}

Status
Poly1305::reset()
{
    return poly1305_impl->reset();
}

Status
Poly1305::finalize(const Uint8 pMsg[], Uint64 msgLen)
{
    return poly1305_impl->finish(pMsg, msgLen);
}

void
Poly1305::finish()
{
}

Status
Poly1305::copy(Uint8 digest[], Uint64 length)
{
    return poly1305_impl->copy(digest, length);
}

} // namespace alcp::mac::poly1305
