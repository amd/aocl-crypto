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
#include "alcp/rng.hh"
#include "alcp/utils/copy.hh"
#include <functional>
#include <vector>

namespace alcp::rng {

class IDrbg : public IRng
{
  public:
    virtual Status initialize(int                 securityStrength,
                              std::vector<Uint8>& p_cPersonalizationString) = 0;
    virtual Status randomize(Uint8               p_Output[],
                             size_t              length,
                             int                 securityStrength,
                             std::vector<Uint8>& p_cAdditionalInput)        = 0;

    virtual Status randomize(Uint8 p_Output[], size_t length) = 0;
};

class ALCP_API_EXPORT Drbg : public IDrbg
{
  private:
    std::shared_ptr<IRng> m_entropy_in            = {};
    bool                  m_prediction_resistance = false;

  public:
    Drbg() {}

    Status setRng(std::shared_ptr<IRng> entropyIn);

    Status randomize(Uint8 p_Output[], size_t length);

    // FIXME: Predicition resistance is to be added
    Status randomize(Uint8        p_Output[],
                     const size_t cOutputLength,
                     int          securityStrength,
                     const Uint8  cAdditionalInput[],
                     const size_t cAdditionalInputLength);

    Status randomize(Uint8               p_Output[],
                     const size_t        cOutputLength,
                     const int           cSecurityStrength,
                     std::vector<Uint8>& additional_input);

    Status readRandom(Uint8* pBuf, Uint64 size);

    bool isSeeded() const { return true; }

    size_t reseed() { return 0; }

    Status setPredictionResistance(bool value);

    Status initialize(int                 securityStrength,
                      std::vector<Uint8>& p_cPersonalizationString);

    virtual std::string name() const = 0;

  protected:
    virtual void instantiate(const Uint8* p_cEntropyInput,
                             const Uint64 cEntropyInputLen,
                             const Uint8* p_cNonce,
                             const Uint64 cNonceLen,
                             const Uint8* p_cPersonalizationString,
                             const Uint64 cPersonalizationStringLen) = 0;

    virtual void instantiate(
        const std::vector<Uint8>& cEntropyInput,
        const std::vector<Uint8>& cNonce,
        const std::vector<Uint8>& cPersonalizationString) = 0;

    virtual void generate(const Uint8* p_cAdditionalInput,
                          const Uint64 cAdditionalInputLen,
                          Uint8*       p_Output,
                          const Uint64 cOutputLen) = 0;

    virtual void generate(const std::vector<Uint8>& p_cAdditionalInput,
                          std::vector<Uint8>&       output) = 0;

    virtual void internalReseed(const Uint8* p_cEntropyInput,
                                const Uint64 cEntropyInputLen,
                                const Uint8* p_cAdditionalInput,
                                const Uint64 cAdditionalInputLen) = 0;

    virtual void internalReseed(const std::vector<Uint8>& cEntropyInput,
                                const std::vector<Uint8>& cAdditionalInput) = 0;
};
} // namespace alcp::rng
