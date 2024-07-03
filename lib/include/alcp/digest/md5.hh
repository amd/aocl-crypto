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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/digest.hh"
#include <openssl/evp.h>
namespace alcp::digest {
class ALCP_API_EXPORT MD5 final : public IDigest
{

  private:
    EVP_MD_CTX* m_ctx = nullptr;
    EVP_MD*     m_md  = nullptr;

  public:
    MD5();
    ~MD5();
    MD5(const MD5& src);
    /**
     * \brief    inits the internal state.
     *
     * \notes   `init()` to be called as a means to reset the internal state.
     *           This enables the processing the new buffer.
     *
     * \return nothing
     */
    void init(void) override;

    /**
     * @brief   Updates hash for given buffer
     *
     * @note    Can be called repeatedly, if the hashsize is smaller
     *           it will be cached for future use. and hash is only updated
     *           after finalize() is called.
     *
     * @param    pBuf    Pointer to message buffer
     *
     * @param    size    should be valid size > 0
     */
    alc_error_t update(const Uint8* pBuf, Uint64 size) override;

    /**
     * \brief    Call for fetching final digest
     *
     *
     * \param    pBuf    Destination buffer to which digest will be copied
     *
     * \param    size    Destination buffer size in bytes, should be big
     *                   enough to hold the digest
     */
    alc_error_t finalize(Uint8* pBuf, Uint64 size) override;
};

} // namespace alcp::digest