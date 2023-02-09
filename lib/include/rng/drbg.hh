/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

#include "alcp/base.hh"
#include "rng.hh"
#include "utils/copy.hh"
#include <functional>
#include <vector>

namespace alcp::rng {

class Drbg : public IRng
{
    // Way to take entropy (IRng class object)
    // Way to select type of DRBG (HMAC,CTR)
    // Set Reseed interval?
  private:
    std::shared_ptr<IRng> m_entropy_in = {};

  public:
    Drbg() {}

    Drbg(std::shared_ptr<IRng> entropy_in)
        : m_entropy_in{ entropy_in }
    {}

    Status initialize(int                 security_strength,
                      std::vector<Uint8>& personalization_string);

    // FIXME: Predicition resistance is to be added
    Status randomize(Uint8               output[],
                     size_t              length,
                     int                 security_strength,
                     std::vector<Uint8>& additional_input);

    Status randomize(Uint8 output[], size_t length);

    Status readRandom(Uint8* pBuf, Uint64 size)
    {
        return randomize(pBuf, size);
    }

    virtual std::string name() const = 0;

    bool isSeeded() const { return true; }

    size_t reseed() { return 0; }

    virtual void instantiate(const Uint8* entropy_input,
                             const Uint64 entropy_input_len,
                             const Uint8* nonce,
                             const Uint64 nonce_len,
                             const Uint8* personalization_string,
                             const Uint64 personalization_string_len) = 0;

    virtual void instantiate(
        const std::vector<Uint8>& entropy_input,
        const std::vector<Uint8>& nonce,
        const std::vector<Uint8>& personalization_string) = 0;

    virtual void generate(const Uint8* additional_input,
                          const Uint64 additional_input_len,
                          Uint8*       output,
                          const Uint64 output_len) = 0;

    virtual void generate(const std::vector<Uint8>& additional_input,
                          std::vector<Uint8>&       output) = 0;

  protected:
    virtual void internalReseed(const Uint8* entropy_input,
                                const Uint64 entropy_input_len,
                                const Uint8* additional_input,
                                const Uint64 additional_input_len) = 0;

    virtual void internalReseed(const std::vector<Uint8>& entropy_input,
                                const std::vector<Uint8>& additional_input) = 0;
};
} // namespace alcp::rng
