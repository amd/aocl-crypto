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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "digest.hh"
#include "mac.hh"
#include "utils/copy.hh"
#include <immintrin.h>
#include <memory.h>

// To store the class validity status to be used as gatekeeper for HMAC
// functions
enum hmac_state_t
{
    VALID,
    INVALID
};

namespace alcp::mac {
class Hmac : public Mac
{

  public:
    alcp::digest::Digest* p_digest;

  private:
    class Impl;
    std::unique_ptr<Impl> m_pimpl;
    const Impl*           pImpl() const { return m_pimpl.get(); }
    Impl*                 pImpl() { return m_pimpl.get(); }

  public:
    Hmac(const alc_mac_info_t mac_info, alcp::digest::Digest* p_digest);
    /**
     * @brief Can be called continously to update message on small chunks
     * @param buff: message block to update HMAC
     * @returns Error Status
     */
    alc_error_t update(std::vector<Uint8> buff) override;
    /**
     * @brief Can be called continously to update message on small chunks
     * @param buff: message array block to update HMAC
     * @param size: Size of the message array
     * @returns Error Status
     */
    alc_error_t update(const Uint8* buff, Uint64 size) override;
    /**
     * @brief Can be called only once to update the final message chunk
     * @param size: Size of the final message chunk
     * @returns Error Status
     */
    alc_error_t finalize(const Uint8* buff, Uint64 size) override;
    /**
     * @brief Can be called only once to update the final message chunk
     * @param buff: Pointer to the array to copy the message hash to
     * @param size: Message digest Size
     * @returns Error Status
     */
    alc_error_t copyHash(Uint8* buff, Uint64 size) const;
    /**
     * @brief get the output hash size to allocate the output array on
     * @returns the output hash size of HMAC
     */
    Uint64 getHashSize();
    /**
     * @brief get the state of the HMAC class at any point after initialization.
     * @returns the output hash size of HMAC
     */
    hmac_state_t getState() const;

    // TODO: Implement Finish and Reset after Builder design is complete
    void finish(){};
    void reset(){};

    ~Hmac();

  private:
    std::vector<Uint8> calculate_hash(alcp::digest::Digest* p_digest,
                                      std::vector<Uint8>    input);

    int calculate_hash(alcp::digest::Digest* p_digest,
                       const Uint8*          input,
                       Uint64                len,
                       Uint8*                output);

    std::vector<Uint8> get_k0(Uint32 block_len);

    void        get_k0_xor_pad();
    alc_error_t setUp(const alc_key_info_t& rKeyInfo);
};
} // namespace alcp::mac