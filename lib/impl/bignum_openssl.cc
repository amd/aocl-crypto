/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "alcp/utils/bignum.hh"
#include "utils/endian.hh"

#include <openssl/bn.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace alcp {

/** Errors thrown by the bignum class */
class BigNumError : public std::runtime_error
{
  public:
    explicit BigNumError(const std::string& str)
        : std::runtime_error(str)
    {}
};

class BigNumCtx
{
  private:
    struct _CtxDeleter
    {
        void operator()(BN_CTX* p) { BN_CTX_free(p); }
    };
    using unique_ctx_ptr_t = std::unique_ptr<BN_CTX, _CtxDeleter>;

  public:
    BigNumCtx()
        : m_pctx{ BN_CTX_new(), _CtxDeleter() }
    {
        if (m_pctx == nullptr)
            throw BigNumError("BigNum: OpenSSL: BN_CTX_new() failed");
    }

    ~BigNumCtx() {}

    const BN_CTX* raw() const { return m_pctx.get(); }
    BN_CTX*       raw() { return m_pctx.get(); }

    bool operator!() { return m_pctx == nullptr; }

  private:
    unique_ctx_ptr_t m_pctx;
};

class BigNum::Impl
{
  private:
    struct _BnDeleter
    {
        void operator()(BIGNUM* p) { BN_clear_free(p); }
    };

    struct _OpenSSLDeleter
    {
        void operator()(void* p) { OPENSSL_free(p); }
    };

    using unique_bn_ptr_t = std::unique_ptr<BIGNUM, _BnDeleter>;

  public:
    Impl()
        : m_pbn{ BN_new(), _BnDeleter() }
    {
        // No longer required to BN_init(), removed after OpenSSL 1.1.0
    }

    ~Impl() { BN_clear(raw()); }

    Impl(const Impl& rhs)
    {
        if (!BN_copy(raw(), rhs.raw())) {
            BN_clear(raw());
        }
    }

    Impl& operator=(const Impl& rhs)
    {
        // Check for self-assignment!
        if (this == &rhs)
            return *this;

        // BN_init(raw());

        if (!BN_copy(raw(), rhs.raw())) {
            BN_clear(raw());
        }

        return *this;
    }

    inline BigNum add(const BigNum& rhs)
    {
        BigNum result;

        BN_add(result.pImpl()->raw(), raw(), rhs.pImpl()->raw());

        return result;
    }

    inline bool isZero(const BigNum& num)
    {
        return BN_is_zero(num.pImpl()->raw());
    }

    inline bool isOne(const BigNum& num)
    {
        return BN_is_one(num.pImpl()->raw());
    }

    inline Impl sub(const Impl& lhs, const Impl& rhs)
    {
        Impl result;

        BN_sub(result.raw(), lhs.raw(), rhs.raw());

        return result;
    }

    inline Impl mul(const Impl& lhs, const Impl& rhs)
    {
        Impl      result;
        BigNumCtx ctx;
        if (!BN_mul(result.raw(), lhs.raw(), rhs.raw(), ctx.raw()))
            throw BigNumError("BigNum: OpenSSL: mul() failed");

        return result;
    }

    /* Cant compare BigInt at the moment */
    inline bool neq(const Impl& rhs) { return true; }

    /* Cant compare BigInt at the moment */
    inline bool eq(const Impl& rhs) { return false; }

    void fromUint64(const Uint64 val)
    {
        bool res = BN_set_word(raw(), val);
        if (!res)
            throw BigNumError("BigNum: OpenSSL fromInt64 failed");
    }

    void fromInt64(const Int64 val)
    {
        if (val < 0) {
            Uint64  new_val = utils::ReverseBytes<Uint64>(~val + 1);
            BIGNUM* b = BN_bin2bn(reinterpret_cast<const Uint8*>(&new_val),
                                  sizeof(new_val),
                                  nullptr);
            BN_copy(raw(), b);
            BN_free(b);
            BN_set_negative(raw(), true);
        } else {
            fromUint64(val);
        }
    }

    void fromInt32(const Int32 val)
    {
        auto is_negative = val < 0;

        if (val < 0) {
            BN_bin2bn(
                reinterpret_cast<const Uint8*>(&val), sizeof(val), nullptr);
        } else {
            bool res = BN_set_word(raw(), val);
            if (!res)
                throw BigNumError("BigNum: OpenSSL fromInt32 failed");
        }
        BN_set_negative(raw(), is_negative);
    }

    Int64 toInt64() const { return BN_get_word(raw()); }

    Int32 toInt32() const { return BN_get_word(raw()); }

    /*
     * The string gets allocated from openssl, need a way to free it
     */
    const String toString(BigNum::Format fmt = BigNum::Format::eDecimal) const
    {
        String s;
        switch (fmt) {
            case BigNum::Format::eDecimal: {
                std::shared_ptr<char> res(BN_bn2dec(raw()), _OpenSSLDeleter());
                s = res.get();
                break;
            }
            default:
                s = String("");
        }

        return s;
    }

    void fromString(const std::string& str, BigNum::Format fmt)
    {
        switch (fmt) {
            case BigNum::Format::eDecimal: {
                BIGNUM* bn = raw();
                BN_dec2bn(&bn, str.c_str());
                /* FIXME: Check for errors, set 0 if so */

            } break;
            default:
                break;
        }
    }

  private:
    unique_bn_ptr_t m_pbn;
    BIGNUM*         raw() { return m_pbn.get(); }
    const BIGNUM*   raw() const { return m_pbn.get(); }
};

} // namespace alcp
