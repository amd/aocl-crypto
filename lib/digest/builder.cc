/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/capi/digest/builder.hh"
#include "alcp/capi/digest/ctx.hh"

#include "alcp/digest.hh"
#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha2_384.hh"
#include "alcp/digest/sha2_512.hh"
#include "alcp/digest/sha3.hh"

namespace alcp::digest {

using Context = alcp::digest::Context;

/* FIXME: Disabling temporarily to fix a compilation error while using AOCC */
#if 0
static std::pmr::synchronized_pool_resource s_digest_pool{};

std::pmr::synchronized_pool_resource&
GetDefaultDigestPool()
{
    return s_digest_pool;
}
#endif

template<typename DIGESTTYPE>
static alc_error_t
__sha_init_wrapper(void* pDigest)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<DIGESTTYPE*>(pDigest);
    ap->init();

    return e;
}

template<typename DIGESTTYPE>
static alc_error_t
__sha_update_wrapper(void* pDigest, const Uint8* pSrc, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<DIGESTTYPE*>(pDigest);
    e       = ap->update(pSrc, len);

    return e;
}

template<typename DIGESTTYPE>
static alc_error_t
__sha_finalize_wrapper(void* pDigest, const Uint8* pBuf, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<DIGESTTYPE*>(pDigest);
    e       = ap->finalize(pBuf, len);

    return e;
}

static alc_error_t
__sha_setShakeLength_wrapper(void* pDigest, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<Sha3*>(pDigest);
    e       = ap->setShakeLength(len);

    return e;
}

template<typename DIGESTTYPE>
static alc_error_t
__sha_copy_wrapper(const void* pDigest, Uint8* pBuf, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<const DIGESTTYPE*>(pDigest);
    e       = ap->copyHash(pBuf, len);

    return e;
}

template<typename DIGESTTYPE>
static alc_error_t
__sha_reset_wrapper(void* pDigest)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<DIGESTTYPE*>(pDigest);
    ap->reset();

    return e;
}

#if 0
template<typename DIGESTTYPE,
         alc_error_t (DIGESTTYPE::*func)(void*, const Uint8*, Uint64)>
static alc_error_t
__digest_func_wrapper(void* pDigest, const Uint8* pBuf, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<DIGESTTYPE*>(pDigest);
    e       = ap->func(pBuf, len);

    return e;
}
#endif

template<typename DIGESTTYPE>
static alc_error_t
__sha_dtor(void* pDigest)
{
    alc_error_t e  = ALC_ERROR_NONE;
    auto        ap = static_cast<DIGESTTYPE*>(pDigest);
    delete ap;
    return e;
}

template<typename ALGONAME>
static alc_error_t
__build_sha(const alc_digest_info_t& sha2Info, Context& ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    auto algo    = new ALGONAME(sha2Info);
    ctx.m_digest = static_cast<void*>(algo);
    ctx.init     = __sha_init_wrapper<ALGONAME>;
    ctx.update   = __sha_update_wrapper<ALGONAME>;
    ctx.copy     = __sha_copy_wrapper<ALGONAME>;
    ctx.finalize = __sha_finalize_wrapper<ALGONAME>;
    //   ctx.finalize = __digest_func_wrapper<ALGONAME,
    //   &ALGONAME::finalize>;
    ctx.finish = __sha_dtor<ALGONAME>;
    ctx.reset  = __sha_reset_wrapper<ALGONAME>;

    // setShakeLength is not implemented for SHA2
    ctx.setShakeLength = nullptr;

    return err;
}

template<typename ALGONAME>
static alc_error_t
__build_with_copy_sha(Context& srcCtx, Context& destCtx)
{
    alc_error_t err = ALC_ERROR_NONE;

    auto algo = new ALGONAME(*reinterpret_cast<ALGONAME*>(srcCtx.m_digest));
    destCtx.m_digest = static_cast<void*>(algo);

    destCtx.init           = srcCtx.init;
    destCtx.update         = srcCtx.update;
    destCtx.copy           = srcCtx.copy;
    destCtx.finalize       = srcCtx.finalize;
    destCtx.finish         = srcCtx.finish;
    destCtx.reset          = srcCtx.reset;
    destCtx.setShakeLength = srcCtx.setShakeLength;

    return err;
}

class Sha2Builder
{
  public:
    static alc_error_t Build(const alc_digest_info_t& rDigestInfo,
                             Context&                 rCtx)
    {
        alc_error_t err = ALC_ERROR_NONE;

        switch (rDigestInfo.dt_len) {
            case ALC_DIGEST_LEN_256:
                if (rDigestInfo.dt_mode.dm_sha2 == ALC_SHA2_256) {
                    __build_sha<Sha256>(rDigestInfo, rCtx);
                } else {
                    __build_sha<Sha512>(rDigestInfo, rCtx);
                }
                break;

            case ALC_DIGEST_LEN_224:
                if (rDigestInfo.dt_mode.dm_sha2 == ALC_SHA2_224) {
                    __build_sha<Sha224>(rDigestInfo, rCtx);
                } else {
                    __build_sha<Sha512>(rDigestInfo, rCtx);
                }
                break;

            case ALC_DIGEST_LEN_512:
                __build_sha<Sha512>(rDigestInfo, rCtx);
                break;

            case ALC_DIGEST_LEN_384:
                __build_sha<Sha384>(rDigestInfo, rCtx);
                break;

            default:
                err = ALC_ERROR_NOT_SUPPORTED;
                break;
        }
        return err;
    }

    static alc_error_t BuildWithCopy(const alc_digest_info_t& rDigestInfo,
                                     Context&                 srcCtx,
                                     Context&                 destCtx)
    {
        alc_error_t err = ALC_ERROR_NONE;

        switch (rDigestInfo.dt_len) {
            case ALC_DIGEST_LEN_256:
                if (rDigestInfo.dt_mode.dm_sha2 == ALC_SHA2_256) {
                    __build_with_copy_sha<Sha256>(srcCtx, destCtx);
                } else {
                    __build_with_copy_sha<Sha512>(srcCtx, destCtx);
                }
                break;

            case ALC_DIGEST_LEN_224:
                if (rDigestInfo.dt_mode.dm_sha2 == ALC_SHA2_224) {
                    __build_with_copy_sha<Sha224>(srcCtx, destCtx);
                } else {
                    __build_with_copy_sha<Sha512>(srcCtx, destCtx);
                }
                break;

            case ALC_DIGEST_LEN_512:
                __build_with_copy_sha<Sha512>(srcCtx, destCtx);
                break;

            case ALC_DIGEST_LEN_384:
                __build_with_copy_sha<Sha384>(srcCtx, destCtx);
                break;

            default:
                err = ALC_ERROR_NOT_SUPPORTED;
                break;
        }
        return err;
    }
};

class Sha3Builder
{
  public:
    static alc_error_t Build(const alc_digest_info_t& rDigestInfo,
                             Context&                 rCtx)
    {
        alc_error_t err  = ALC_ERROR_NONE;
        auto        algo = new Sha3(rDigestInfo);
        rCtx.m_digest    = static_cast<void*>(algo);
        rCtx.init        = __sha_init_wrapper<Sha3>;
        rCtx.update      = __sha_update_wrapper<Sha3>;
        rCtx.copy        = __sha_copy_wrapper<Sha3>;
        rCtx.finalize    = __sha_finalize_wrapper<Sha3>;
        rCtx.finish      = __sha_dtor<Sha3>;
        rCtx.reset       = __sha_reset_wrapper<Sha3>;

        //  Restricting setShakeLength to SHAKE128 or SHAKE256
        if (rDigestInfo.dt_mode.dm_sha3 == ALC_SHAKE_128
            || rDigestInfo.dt_mode.dm_sha3 == ALC_SHAKE_256) {
            rCtx.setShakeLength = __sha_setShakeLength_wrapper;
        } else {
            rCtx.setShakeLength = nullptr;
        }
        return err;
    }

    static alc_error_t BuildWithCopy(Context& srcCtx, Context& destCtx)
    {
        alc_error_t err = ALC_ERROR_NONE;

        auto algo = new Sha3(*(reinterpret_cast<Sha3*>(srcCtx.m_digest)));
        destCtx.m_digest       = static_cast<void*>(algo);
        destCtx.init           = srcCtx.init;
        destCtx.update         = srcCtx.update;
        destCtx.copy           = srcCtx.copy;
        destCtx.finalize       = srcCtx.finalize;
        destCtx.finish         = srcCtx.finish;
        destCtx.reset          = srcCtx.reset;
        destCtx.setShakeLength = srcCtx.setShakeLength;
        return err;
    }
};

alc_error_t
DigestBuilder::Build(const alc_digest_info_t& rDigestInfo, Context& rCtx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (rDigestInfo.dt_type) {
        case ALC_DIGEST_TYPE_SHA2:
            err = Sha2Builder::Build(rDigestInfo, rCtx);
            break;
        case ALC_DIGEST_TYPE_SHA3:
            err = Sha3Builder::Build(rDigestInfo, rCtx);
            break;

        default:
            err = ALC_ERROR_NOT_SUPPORTED;
            break;
    }

    return err;
}

alc_error_t
DigestBuilder::BuildWithCopy(const alc_digest_info_t dInfo,
                             digest::Context&        srcCtx,
                             digest::Context&        destCtx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (dInfo.dt_type) {
        case ALC_DIGEST_TYPE_SHA2:
            err = Sha2Builder::BuildWithCopy(dInfo, srcCtx, destCtx);
            break;
        case ALC_DIGEST_TYPE_SHA3:
            err = Sha3Builder::BuildWithCopy(srcCtx, destCtx);
            break;

        default:
            err = ALC_ERROR_NOT_SUPPORTED;
            break;
    }

    return err;
}

} // namespace alcp::digest
