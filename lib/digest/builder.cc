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
#include "alcp/digest/md5.hh"
#include "alcp/digest/sha1.hh"
#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha3.hh"
#include "alcp/digest/sha512.hh"

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
__sha_finalize_wrapper(void* pDigest, Uint8* pBuf, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<DIGESTTYPE*>(pDigest);
    e       = ap->finalize(pBuf, len);

    return e;
}

template<typename DIGESTTYPE>
static alc_error_t
__sha_shakeSqueeze_wrapper(void* pDigest, Uint8* pBuff, Uint64 len)
{
    alc_error_t e = ALC_ERROR_NONE;

    auto ap = static_cast<DIGESTTYPE*>(pDigest);
    e       = ap->shakeSqueeze(pBuff, len);

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
__build_with_copy_sha(Context& srcCtx, Context& destCtx)
{
    alc_error_t err = ALC_ERROR_NONE;

    auto algo = new ALGONAME(*reinterpret_cast<ALGONAME*>(srcCtx.m_digest));
    destCtx.m_digest = static_cast<void*>(algo);

    destCtx.init         = srcCtx.init;
    destCtx.update       = srcCtx.update;
    destCtx.finalize     = srcCtx.finalize;
    destCtx.finish       = srcCtx.finish;
    destCtx.duplicate    = srcCtx.duplicate;
    destCtx.shakeSqueeze = srcCtx.shakeSqueeze;

    return err;
}

template<typename ALGONAME>
static alc_error_t
__build_sha(Context& ctx)
{
    alc_error_t err = ALC_ERROR_NONE;

    auto algo     = new ALGONAME();
    ctx.m_digest  = static_cast<void*>(algo);
    ctx.init      = __sha_init_wrapper<ALGONAME>;
    ctx.update    = __sha_update_wrapper<ALGONAME>;
    ctx.duplicate = __build_with_copy_sha<ALGONAME>;
    ctx.finalize  = __sha_finalize_wrapper<ALGONAME>;
    //   ctx.finalize = __digest_func_wrapper<ALGONAME,
    //   &ALGONAME::finalize>;
    ctx.finish = __sha_dtor<ALGONAME>;

    // shakeSqueeze are not implemented for SHA2
    ctx.shakeSqueeze = nullptr;

    return err;
}

class Sha2Builder
{
  public:
    static alc_error_t Build(alc_digest_mode_t mode, Context& rCtx)
    {
        alc_error_t err = ALC_ERROR_NONE;

        switch (mode) {
            case ALC_MD5:
                __build_sha<Md5>(rCtx);
                break;
            case ALC_SHA1:
                __build_sha<Sha1>(rCtx);
                break;
            case ALC_SHA2_224:
                __build_sha<Sha224>(rCtx);
                break;
            case ALC_SHA2_256:
                __build_sha<Sha256>(rCtx);
                break;
            case ALC_SHA2_512:
                __build_sha<Sha512>(rCtx);
                break;
            case ALC_SHA2_384:
                __build_sha<Sha384>(rCtx);
                break;
            case ALC_SHA2_512_256:
                __build_sha<Sha512_256>(rCtx);
                break;
            case ALC_SHA2_512_224:
                __build_sha<Sha512_224>(rCtx);
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
    static alc_error_t Build(alc_digest_mode_t mode, Context& rCtx)
    {
        alc_error_t err = ALC_ERROR_NONE;
        switch (mode) {
            case ALC_SHA3_224:
                __build_sha<Sha3_224>(rCtx);
                break;
            case ALC_SHA3_256:
                __build_sha<Sha3_256>(rCtx);
                break;
            case ALC_SHA3_384:
                __build_sha<Sha3_384>(rCtx);
                break;
            case ALC_SHA3_512:
                __build_sha<Sha3_512>(rCtx);
                break;
            case ALC_SHAKE_128:
                __build_sha<Shake128>(rCtx);
                rCtx.shakeSqueeze = __sha_shakeSqueeze_wrapper<Shake128>;
                break;
            case ALC_SHAKE_256:
                __build_sha<Shake256>(rCtx);
                rCtx.shakeSqueeze = __sha_shakeSqueeze_wrapper<Shake256>;
                break;
            default:
                err = ALC_ERROR_NOT_SUPPORTED;
                break;
        }
        return err;
    }
};

alc_error_t
DigestBuilder::Build(alc_digest_mode_t mode, Context& rCtx)
{
    alc_error_t err = ALC_ERROR_NONE;

    switch (mode) {
        case ALC_MD5:
        case ALC_SHA1:
        case ALC_SHA2_224:
        case ALC_SHA2_256:
        case ALC_SHA2_384:
        case ALC_SHA2_512:
        case ALC_SHA2_512_224:
        case ALC_SHA2_512_256:
            err = Sha2Builder::Build(mode, rCtx);
            break;

        case ALC_SHA3_224:
        case ALC_SHA3_256:
        case ALC_SHA3_384:
        case ALC_SHA3_512:
        case ALC_SHAKE_128:
        case ALC_SHAKE_256:
            err = Sha3Builder::Build(mode, rCtx);
            break;

        default:
            err = ALC_ERROR_NOT_SUPPORTED;
            break;
    }

    return err;
}

alc_error_t
DigestBuilder::BuildWithCopy(digest::Context& srcCtx, digest::Context& destCtx)
{
    return srcCtx.duplicate(srcCtx, destCtx);
}

} // namespace alcp::digest
