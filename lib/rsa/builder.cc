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

#include "alcp/capi/rsa/builder.hh"
#include "alcp/capi/rsa/ctx.hh"

#include "alcp/digest/md5.hh"
#include "alcp/digest/md5_sha1.hh"
#include "alcp/digest/sha1.hh"
#include "alcp/digest/sha2.hh"
#include "alcp/digest/sha3.hh"
#include "alcp/digest/sha512.hh"
#include "alcp/rsa.hh"
#include "alcp/rsa/rsaerror.hh"

namespace alcp::rsa {

using Context = alcp::rsa::Context;

alc_error_t
__rsa_encrBufWithPub_wrapper(void*        pRsaHandle,
                             const Uint8* pText,
                             Uint64       textSize,
                             Uint8*       pEncText)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->encryptPublic(pText, textSize, pEncText);
}

alc_error_t
__rsa_decrBufWithPriv_wrapper(void*        pRsaHandle,
                              const Uint8* pEncText,
                              Uint64       encSize,
                              Uint8*       pText)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->decryptPrivate(pEncText, encSize, pText);
}

alc_error_t
__rsa_oaepEncrBufWithPub_wrapper(void*        pRsaHandle,
                                 const Uint8* pText,
                                 Uint64       textSize,
                                 const Uint8* label,
                                 Uint64       labelSize,
                                 const Uint8* pSeed,
                                 Uint8*       pEncText)
{

    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->encryptPublicOaep(
        pText, textSize, label, labelSize, pSeed, pEncText);
}

alc_error_t
__rsa_oaepDecrBufWithPriv_wrapper(void*        pRsaHandle,
                                  const Uint8* pEncText,
                                  Uint64       encSize,
                                  const Uint8* label,
                                  Uint64       labelSize,
                                  Uint8*       pText,
                                  Uint64&      textSize)

{

    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->decryptPrivateOaep(
        pEncText, encSize, label, labelSize, pText, textSize);
}

alc_error_t
__rsa_pssSignBufWithPriv_wrapper(void*        pRsaHandle,
                                 bool         check,
                                 const Uint8* pText,
                                 Uint64       textSize,
                                 const Uint8* salt,
                                 Uint64       saltSize,
                                 Uint8*       pSignedBuff)

{

    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->signPrivatePss(
        check, pText, textSize, salt, saltSize, pSignedBuff);
}

alc_error_t
__rsa_pssVerifyBufWithPub_wrapper(void*        pRsaHandle,
                                  const Uint8* pText,
                                  Uint64       textSize,
                                  const Uint8* pSignedBuff)

{

    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->verifyPublicPss(pText, textSize, pSignedBuff);
}

alc_error_t
__rsa_pssSignBufWithPriv_wrapper_without_hash(void*        pRsaHandle,
                                              const Uint8* pHash,
                                              Uint64       hashSize,
                                              const Uint8* salt,
                                              Uint64       saltSize,
                                              Uint8*       pSignedBuff)

{

    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->signPrivatePssWithoutHash(
        pHash, hashSize, salt, saltSize, pSignedBuff);
}

alc_error_t
__rsa_pssVerifyBufWithPub_wrapper_without_hash(void*        pRsaHandle,
                                               const Uint8* pHash,
                                               Uint64       hashSize,
                                               const Uint8* pSignedBuff)

{

    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->verifyPublicPssWithoutHash(pHash, hashSize, pSignedBuff);
}

alc_error_t
__rsa_pkcsv15SignBufWithPriv_wrapper(void*        pRsaHandle,
                                     bool         check,
                                     const Uint8* pText,
                                     Uint64       textSize,
                                     Uint8*       pSignedBuff)

{

    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->signPrivatePkcsv15(check, pText, textSize, pSignedBuff);
}

alc_error_t
__rsa_pkcsv15VerifyBufWithPub_wrapper(void*        pRsaHandle,
                                      const Uint8* pText,
                                      Uint64       textSize,
                                      const Uint8* pSignedBuff)

{

    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->verifyPublicPkcsv15(pText, textSize, pSignedBuff);
}

alc_error_t
__rsa_pkcsv15DecyptBufWithPriv_wrapper(void*        pRsaHandle,
                                       const Uint8* encryptedText,
                                       Uint8*       decrypText,
                                       Uint64*      textSize)

{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->decryptPrivatePkcsv15(encryptedText, decrypText, textSize);
}

alc_error_t
__rsa_pkcsv15EncryptBufWithPub_wrapper(void*        pRsaHandle,
                                       const Uint8* pText,
                                       Uint64       textSize,
                                       Uint8*       encryptText,
                                       const Uint8* randomPad)

{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->encryptPublicPkcsv15(pText, textSize, encryptText, randomPad);
}

alc_error_t
__rsa_pkcsv15SignBufWithPrivWithoutHash_wrapper(void*        pRsaHandle,
                                                const Uint8* pText,
                                                Uint64       textSize,
                                                Uint8*       signedText)

{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->signPrivatePkcsv15WithoutHash(pText, textSize, signedText);
}

alc_error_t
__rsa_pkcsv15VerifyBufWithPubWithoutHash_wrapper(void*        pRsaHandle,
                                                 const Uint8* pText,
                                                 Uint64       textSize,
                                                 const Uint8* signedText)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    return ap->verifyPublicPkcsv15WithoutHash(pText, textSize, signedText);
}

static Uint64
__rsa_getKeySize_wrapper(void* pRsaHandle)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    return ap->getKeySize();
}

alc_error_t
__rsa_getPublicKey_wrapper(void* pRsaHandle, RsaPublicKey& publicKey)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    return ap->getPublickey(publicKey);
}

alc_error_t
__rsa_setPublicKey_wrapper(void*        pRsaHandle,
                           const Uint64 exponent,
                           const Uint8* mod,
                           const Uint64 size)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    return ap->setPublicKey(exponent, mod, size);
}

alc_error_t
__rsa_setPublicKeyAsBigNum_wrapper(void*         pRsaHandle,
                                   const BigNum* exponent,
                                   const BigNum* pModulus)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    return ap->setPublicKeyAsBigNum(exponent, pModulus);
}

alc_error_t
__rsa_setPrivateKey_wrapper(void*        pRsaHandle,
                            const Uint8* dp,
                            const Uint8* dq,
                            const Uint8* p,
                            const Uint8* q,
                            const Uint8* qinv,
                            const Uint8* mod,
                            const Uint64 size)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    return ap->setPrivateKey(dp, dq, p, q, qinv, mod, size);
}

alc_error_t
__rsa_setPrivateKeyAsBigNum_wrapper(void*         pRsaHandle,
                                    const BigNum* dp,
                                    const BigNum* dq,
                                    const BigNum* p,
                                    const BigNum* q,
                                    const BigNum* qinv,
                                    const BigNum* mod)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    return ap->setPrivateKeyAsBigNum(dp, dq, p, q, qinv, mod);
}

static void
__rsa_setDigest_wrapper(void* pRsaHandle, digest::IDigest* digest)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    ap->setDigest(digest);
}

static void
__rsa_setMgf_wrapper(void* pRsaHandle, digest::IDigest* digest)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);

    ap->setMgf(digest);
}

alc_error_t
__rsa_dtor(void* pRsaHandle)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    delete ap;
    return ALC_ERROR_NONE;
}

alc_error_t
__rsa_reset_wrapper(void* pRsaHandle)
{
    auto ap = static_cast<Rsa*>(pRsaHandle);
    // FIXME: Not a good idea!
    ap->reset();
    return ALC_ERROR_NONE;
}

static inline digest::IDigest*
copy_digest(digest::IDigest* src_digest)
{
    using namespace digest;

    if (src_digest == nullptr) {
        return nullptr;
    }
    IDigest* dest_digest = nullptr;
    if (dest_digest = dynamic_cast<Md5*>(src_digest); dest_digest != nullptr) {
        dest_digest = new Md5(*static_cast<Md5*>(dest_digest));
    } else if (dest_digest = dynamic_cast<Sha1*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha1(*static_cast<Sha1*>(dest_digest));
    } else if (dest_digest = dynamic_cast<Md5_Sha1*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Md5_Sha1(*static_cast<Md5_Sha1*>(dest_digest));
    } else if (dest_digest = dynamic_cast<Sha256*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha256(*static_cast<Sha256*>(dest_digest));
    } else if (dest_digest = dynamic_cast<Sha224*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha224(*static_cast<Sha224*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha384*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha384(*static_cast<Sha384*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha512*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha512(*static_cast<Sha512*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha512_224*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha512_224(*static_cast<Sha512_224*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha512_256*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha512_256(*static_cast<Sha512_256*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha3_224*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha3_224(*static_cast<Sha3_224*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha3_256*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha3_256(*static_cast<Sha3_256*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha3_384*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha3_384(*static_cast<Sha3_384*>(dest_digest));
    } else if (dest_digest = dynamic_cast<digest::Sha3_512*>(src_digest);
               dest_digest != nullptr) {
        dest_digest = new Sha3_512(*static_cast<Sha3_512*>(dest_digest));
    }
    return dest_digest;
}

alc_error_t
__build_with_copy_rsa(Context* srcCtx, Context* destCtx)
{
    using namespace digest;
    memcpy(destCtx, srcCtx, sizeof(Context));

    auto rsa_algo  = new Rsa(*reinterpret_cast<Rsa*>(srcCtx->m_rsa));
    destCtx->m_rsa = static_cast<void*>(rsa_algo);

    IDigest* src_digest  = static_cast<digest::IDigest*>(srcCtx->m_digest);
    IDigest* dest_digest = copy_digest(src_digest);

    rsa_algo->setDigest(dest_digest);
    destCtx->m_digest = dest_digest;

    src_digest  = static_cast<digest::IDigest*>(srcCtx->m_mgf);
    dest_digest = copy_digest(src_digest);
    rsa_algo->setMgf(dest_digest);
    destCtx->m_mgf = dest_digest;
    return ALC_ERROR_NONE;
}

alc_error_t
__build_rsa(Context& ctx)
{
    auto algo = new Rsa;

    ctx.m_rsa                = static_cast<void*>(algo);
    ctx.encryptPublicFn      = __rsa_encrBufWithPub_wrapper;
    ctx.decryptPrivateFn     = __rsa_decrBufWithPriv_wrapper;
    ctx.encryptPublicOaepFn  = __rsa_oaepEncrBufWithPub_wrapper;
    ctx.decryptPrivateOaepFn = __rsa_oaepDecrBufWithPriv_wrapper;
    ctx.signPrivatePssFn     = __rsa_pssSignBufWithPriv_wrapper;
    ctx.verifyPublicPssFn    = __rsa_pssVerifyBufWithPub_wrapper;
    ctx.signPrivatePssWithoutHashFn =
        __rsa_pssSignBufWithPriv_wrapper_without_hash;
    ctx.verifyPublicPssWithoutHashFn =
        __rsa_pssVerifyBufWithPub_wrapper_without_hash;
    ctx.signPrivatePkcsv15Fn  = __rsa_pkcsv15SignBufWithPriv_wrapper;
    ctx.verifyPublicPkcsv15Fn = __rsa_pkcsv15VerifyBufWithPub_wrapper;
    ctx.signPrivatePkcsv15WithoutHashFn =
        __rsa_pkcsv15SignBufWithPrivWithoutHash_wrapper;
    ctx.verifyPublicPkcsv15WithoutHashFn =
        __rsa_pkcsv15VerifyBufWithPubWithoutHash_wrapper;
    ctx.encryptPublicPkcsv15Fn  = __rsa_pkcsv15EncryptBufWithPub_wrapper;
    ctx.decryptPrivatePkcsv15Fn = __rsa_pkcsv15DecyptBufWithPriv_wrapper;
    ctx.getKeySize              = __rsa_getKeySize_wrapper;
    ctx.getPublickey            = __rsa_getPublicKey_wrapper;
    ctx.setPublicKey            = __rsa_setPublicKey_wrapper;
    ctx.setPublicKeyAsBignum    = __rsa_setPublicKeyAsBigNum_wrapper;
    ctx.setPrivateKey           = __rsa_setPrivateKey_wrapper;
    ctx.setPrivateKeyAsBignum   = __rsa_setPrivateKeyAsBigNum_wrapper;
    ctx.setDigest               = __rsa_setDigest_wrapper;
    ctx.setMgf                  = __rsa_setMgf_wrapper;
    ctx.finish                  = __rsa_dtor;
    ctx.reset                   = __rsa_reset_wrapper;
    ctx.duplicate               = __build_with_copy_rsa;
    return ALC_ERROR_NONE;
}

Uint32
RsaBuilder::getSize()
{
    return sizeof(Rsa);
}

alc_error_t
RsaBuilder::Build(Context& rCtx)
{
    return __build_rsa(rCtx);
}

} // namespace alcp::rsa
