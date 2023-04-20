/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
#include "alcp/utils/endian.hh"

#include <memory>
#include <stdexcept>
#include <string>

namespace openssl {
#include <openssl/bn.h>
}

namespace alcp {

/*
 * This point onward, all openssl declarations
 *   - BIGNUM
 *   - BN_CTX
 *   - BN_* functions
 * are usable, otherwise use openssl:: prefix to resolve
 */
using namespace openssl;
using namespace alcp::base;
using namespace alcp::utils;

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

    inline BigNum minus(BigNum const& self)
    {
        BigNum result{ self };

        BN_set_negative(result.pImpl()->raw(), 1);
        return result;
    }

    inline void operator=(const BigNum& rhs)
    {
        if (!BN_copy(raw(), rhs.pImpl()->raw())) {
            BN_clear(raw());
        }
    }

    inline BigNum add(const BigNum& rhs)
    {
        BigNum result;

        BN_add(result.pImpl()->raw(), raw(), rhs.pImpl()->raw());

        return result;
    }

    inline BigNum sub(const BigNum& rhs)
    {
        BigNum result;
        BN_sub(result.pImpl()->raw(), raw(), rhs.pImpl()->raw());

        return result;
    }

    inline BigNum mul(const BigNum& rhs)
    {
        BigNum    result;
        BigNumCtx ctx;
        int       ret = 0;

        ret =
            BN_mul(result.pImpl()->raw(), raw(), rhs.pImpl()->raw(), ctx.raw());
        ALCP_ASSERT(ret == 1, "BN_mul failed");
        if (!ret)
            result.fromInt64(0);

        return result;
    }

    inline BigNum div(const BigNum& rhs)
    {
        BigNum    result;
        BigNum    rem;
        BigNumCtx ctx;
        int       ret = 0;

        ret = BN_div(result.pImpl()->raw(),
                     rem.pImpl()->raw(),
                     raw(),
                     rhs.pImpl()->raw(),
                     ctx.raw());

        ALCP_ASSERT(ret == 1, "BN_div failed");

        if (!ret)
            result.fromInt64(0);

        return result;
    }

    inline BigNum mod(const BigNum& rhs)
    {
        BigNum    result;
        BigNumCtx ctx;
        int       ret = 0;

        ret =
            BN_mod(result.pImpl()->raw(), raw(), rhs.pImpl()->raw(), ctx.raw());

        ALCP_ASSERT(ret == 1, "BN_mod failed");

        if (!ret)
            result.fromInt64(0);

        return result;
    }

    inline BigNum lshift(int shifts)
    {
        BigNum    result;
        BigNumCtx ctx;
        int       ret = 0;

        ret = BN_lshift(result.pImpl()->raw(), raw(), shifts);

        ALCP_ASSERT(ret == 1, "BN_lshift failed");

        if (!ret)
            result.fromInt64(0);

        return result;
    }

    inline BigNum rshift(int shifts)
    {
        BigNum    result;
        BigNumCtx ctx;
        int       ret = 0;

        ret = BN_rshift(result.pImpl()->raw(), raw(), shifts);

        ALCP_ASSERT(ret == 1, "BN_rshift failed");

        if (!ret)
            result.fromInt64(0);

        return result;
    }

    inline void exp_mod(const BigNum& num, const BigNum& exp, const BigNum& mod)
    {
        BigNumCtx ctx;

        int ret = BN_mod_exp_simple(raw(),
                                    num.pImpl()->raw(),
                                    exp.pImpl()->raw(),
                                    mod.pImpl()->raw(),
                                    ctx.raw());

        if (!ret)
            BN_zero(raw());
    }

    inline bool isZero(const BigNum& num) const
    {
        return BN_is_zero(num.pImpl()->raw());
    }

    inline bool isOne(const BigNum& num) const
    {
        return BN_is_one(num.pImpl()->raw());
    }

    inline bool eq(const BigNum& rhs) const
    {
        int ret = BN_cmp(raw(), rhs.pImpl()->raw());

        if (ret == 0) {
            return true;
        } else {
            return false;
        }
    }

    Status fromUint64(const Uint64 val)
    {
        Status sts = StatusOk();

        bool res = BN_set_word(raw(), val);
        ALCP_ASSERT(res == true, "fromInt64: BN_set_word failed");
        if (!res)
            sts.update(status::InternalError("BN_set_word"));

        return sts;
    }

    Status fromInt64(const Int64 val)
    {
        Status sts = StatusOk();
        if (val < 0) {
            /* create a 2's complement */
            Uint64  new_val = utils::ReverseBytes<Uint64>(~val + 1);
            BIGNUM* b = BN_bin2bn(reinterpret_cast<const Uint8*>(&new_val),
                                  sizeof(new_val),
                                  nullptr);
            if (b) {
                // FIXME: avoid extra copy
                BN_copy(raw(), b);
                BN_free(b);
                BN_set_negative(raw(), true);
            }
            sts.update(status::InternalError("BN_bin2bn"));
        } else {
            sts = fromUint64(val);
        }

        return sts;
    }

    Status fromUint32(const Uint32 val)
    {
        Status sts = StatusOk();

        bool ret = BN_set_word(raw(), val);
        ALCP_ASSERT(ret == 0, "fromInt32: BN_set_word failed");
        if (ret)
            sts.update(status::InternalError("fromInt32: BN_set_word failed"));

        return sts;
    }

    Status fromInt32(const Int32 val)
    {
        Status sts = StatusOk();

        if (val < 0) {
            /* create a 2's complement */
            Uint32 new_val = utils::ReverseBytes<Uint32>(~val + 1);
            auto   uptr    = reinterpret_cast<const Uint8*>(&new_val);

            BIGNUM* bn = BN_bin2bn(uptr, sizeof(val), nullptr);
            ALCP_ASSERT(bn == nullptr, "fromInt32: BN_bin2bn failed");
            if (bn) {
                // FIXME: avoid extra copy
                BN_copy(raw(), bn);
                BN_free(bn);
                BN_set_negative(raw(), true);
            }
        } else {
            bool ret = BN_set_word(raw(), val);
            ALCP_ASSERT(ret == true, "fromInt32: BN_set_word failed");
            if (ret)
                sts.update(
                    status::InternalError("fromInt32: BN_set_word failed"));
        }

        return sts;
    }

    Status fromBinary(const Uint8* buf, Uint64 size)
    {
        if (BN_bin2bn(buf, size, raw()) == NULL) {
            return Status(GenericError(ErrorCode::eInternal));
        }
        return StatusOk();
    }

    bool  isNegative() const { return BN_is_negative(raw()); }
    Int64 toInt64() const
    {
        Int64 res = BN_get_word(raw());
        if (isNegative())
            res = -res;

        return res;
    }

    Int32 toInt32() const
    {
        Int32 res = BN_get_word(raw());
        if (isNegative())
            res = -res;
        return res;
    }

    Status toBinary(Uint8* buf, Uint64 size)
    {
        if (BN_bn2binpad(raw(), buf, size) == 0) {
            return Status(GenericError(ErrorCode::eInternal));
        }

        return StatusOk();
    }

    const String toString(BigNum::Format fmt) const
    {
        String s;
        switch (fmt) {
            /* The string gets allocated from openssl */
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

    Status fromString(const std::string& str, BigNum::Format fmt)
    {
        Status sts = StatusOk();

        switch (fmt) {
            case BigNum::Format::eDecimal: {
                auto bn  = raw();
                int  ret = BN_dec2bn(&bn, str.c_str());
                if (ret)
                    sts.update(status::InternalError("BN_dec2bn"));
            } break;
            default:
                sts = status::InvalidArgument("Invalid Argument");
                break;
        }

        return sts;
    }

    /**
     * @brief Return underlaying pointer
     * @details In Openssl, it wont provide pointer to underlaying storage
     *            Any modyfyable data() will get nullpointer, but we still
     *            allow immutable BIGNUM*
     * @param     none
     * @returns   nullptr if the access is read-write
     *            pointer to openssl::BIGNUM otherwise
     */
    void*       data() { return nullptr; }
    const void* data() const { return raw(); }
    std::size_t size() const { return BN_num_bytes(m_pbn.get()); }

  private:
    unique_bn_ptr_t m_pbn;
    BIGNUM*         raw() { return m_pbn.get(); }
    const BIGNUM*   raw() const { return m_pbn.get(); }
};

} // namespace alcp
