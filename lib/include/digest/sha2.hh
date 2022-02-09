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

#include "digest.hh"

namespace alcp::digest {

class Sha2 : public Digest
{
  public:
    Sha2(const std::string& name)
        : m_name{ name }
        , m_msg_len{ 0 }
    {}

    Sha2(const char* name)
        : Sha2(std::string(name))
    {}

  protected:
    Sha2() {}
    virtual ~Sha2();

  protected:
    alc_sha2_mode_t m_mode;
    std::string     m_name;
    uint64_t        m_msg_len;
    // alc_sha2_param_t m_param;
};

class Sha256 final : public Sha2
{
  public:
    Sha256();
    Sha256(const alc_digest_info_t& rDigestInfo);

  public:
    ~Sha256();

  public:
    /**
     * \brief   Updates hash for given buffer
     *
     * \notes    Can be called repeatedly, if the hashsize is smaller
     *           it will be cached for future use. and hash is only updated
     *           after finalize() is called.
     *
     * \param    pBuf    Pointer to message buffer
     *
     * \param    size    should be valid size > 0
     */
    alc_error_t update(const uint8_t* pMsgBuf, uint64_t size) override;

    /**
     * \brief   Cleans up any resource that was allocated
     *
     * \notes   `finish()` to be called as a means to cleanup, no operation
     *           permitted after this call. The context will be unusable.
     *
     * \return nothing
     */
    void finish() override;

    /**
     * \brief    Call for the final chunk
     *
     * \notes   `finish()` to be called as a means to cleanup, necessary
     *           actions. Application can also call finalize() with
     *           empty/null args application must call copyHash before
     *           calling finish()
     *
     * \param    buf     Either valid pointer to last chunk or nullptr,
     *                   if nullptr then has is not modified, once finalize()
     *                   is called, only operation that can be performed
     *                   is copyHash()
     *
     * \param    size    Either valid size or 0, if \buf is nullptr, size
     *                   is assumed to be zero
     */
    alc_error_t finalize(const uint8_t* pMsgBuf, uint64_t size) override;

    /**
     * \brief  Copies the has from context to supplied buffer
     *
     * \notes `finalize()` to be called with last chunks that should
     *           perform all the necessary actions, can be called with
     *           NULL argument.
     *
     * \param    buf     Either valid pointer to last chunk or nullptr,
     *                   if nullptr then has is not modified, once finalize()
     *                   is called, only operation that can  be performed
     *                   is copyHash()
     *
     * \param    size    Either valid size or 0, if \buf is nullptr, size is
     *                   assumed to be zero
     */
    alc_error_t copyHash(uint8_t* pHashBuf, uint64_t size) const override;
    Sha256&     operator=(Sha256&& rhs);

  public:
    alc_error_t setIv(const void* pIv, uint64_t size);

  private:
    class Impl;
    Impl* m_pimpl;
};

class Sha224 final : public Sha2
{
  public:
    Sha224();
    Sha224(const alc_digest_info_t& rDInfo);
    alc_error_t update(const uint8_t* pMsgBuf, uint64_t size) override;
    void        finish() override;
    alc_error_t finalize(const uint8_t* pMsgBuf, uint64_t size) override;
    alc_error_t copyHash(uint8_t* pHashBuf, uint64_t size) const override;

  private:
    Sha256 m_sha256;
};

} // namespace alcp::digest
