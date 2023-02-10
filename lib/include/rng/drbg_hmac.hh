/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use p_cIn source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions p_cIn binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer p_cIn the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
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
#include "alcp/mac.h"
#include "digest.hh"
#include "digest/sha2.hh"
#include "digest/sha3.hh"
#include "mac/hmac.hh"
#include "rng/drbg.hh"

// Kernel debugging interface
// #define DEBUG_MODE
#ifdef DEBUG_MODE
#include "openssl/bio.h"
#endif

namespace alcp::rng::drbg {
template<typename VectType>
using concat_type_t = std::vector<const std::vector<VectType>*>;
void
DebugPrint(const std::vector<Uint8>& p_cIn,
           std::string               message,
           std::string               file,
           int                       line);

class HmacDrbg : public Drbg
{
  private:
    class IHmacDrbg;

    std::unique_ptr<IHmacDrbg> p_impl;

  public:
    std::string name() const;

    HmacDrbg();
    HmacDrbg(int digestSize, std::shared_ptr<alcp::digest::Digest> digestObj);
    HmacDrbg(int                                   digestSize,
             std::shared_ptr<alcp::digest::Digest> digestObj,
             std::shared_ptr<IRng>                 pEntropyIn);
    ~HmacDrbg();

  protected:
    /**
     * @brief Given Data and Length, updates key and value internally
     *
     * @param p_cProvidedData    - Uint8 of data
     * @param cProvidedDataLen  - Length of the data p_cIn bytes
     */
    void update(const Uint8* p_cProvidedData, const Uint64 cProvidedDataLen);

    /**
     * @brief Given Data and Length, updates key and value internally
     *
     * @param p_cProvidedData    - vector<Uint8> of data
     */
    void update(const std::vector<Uint8>& cProvidedData);

    /**
     * @brief Insitantiate DRBG given Entropy, Nonce, Personal Data
     *
     * @param p_cEntropyInput               - Pointer to location where
     * entropy is stored
     * @param cEntropyInputLen           - Length of the entropy buffer
     * @param p_cNonce                       - Number used only once
     * @param cNonceLen                   - Length of the number buffer
     * p_cIn bytes
     * @param p_cPersonalizationString      - Additional Entropy by user
     * @param p_cPersonalizationStringLen  - Length of the
     * personalization string
     */
    void instantiate(const Uint8* p_cEntropyInput,
                     const Uint64 cEntropyInputLen,
                     const Uint8* p_cNonce,
                     const Uint64 cNonceLen,
                     const Uint8* p_cPersonalizationString,
                     const Uint64 p_cPersonalizationStringLen);

    /**
     * @brief Insitantiate DRBG given Entropy, Nonce, Personal Data
     *
     * @param p_cEntropyInput           - vector<Uint8> of entropy
     * @param p_cNonce                   - vector<Uint8> which has p_cNonce
     * value
     * @param p_cPersonalizationString  - vector<Uint8> given by user as
     * additional entropy
     */
    void instantiate(const std::vector<Uint8>& cEntropyInput,
                     const std::vector<Uint8>& cNonce,
                     const std::vector<Uint8>& cPersonalizationString);

    /**
     * @brief Generates the drbg random bits given additional data and
     * buffer to p_cOutput to
     *
     * @param p_cAdditionalInput     - Additional entropy buffer
     * @param cAdditionalInputLen - Length of the additional entropy
     * buffer
     * @param p_cOutput               - Output buffer
     * @param cOutputLen           - Length of the p_cOutput buffer
     */
    void generate(const Uint8* p_cAdditionalInput,
                  const Uint64 cAdditionalInputLen,
                  Uint8*       p_cOutput,
                  const Uint64 cOutputLen);

    /**
     * @brief Generates the drbg random bits given additional data and
     * buffer to p_cOutput to
     *
     * @param p_cAdditionalInput     - Additional entropy buffer
     * vector<Uint8>
     * @param p_cOutput               - Output buffer vector<Uint8>
     */
    void generate(const std::vector<Uint8>& cAdditionalInput,
                  std::vector<Uint8>&       cOutput);

    /**
     * @brief Reseed the drbg internal state for unpredictability.
     *
     * @param p_cEntropyInput        - Buffer which has entropy
     * @param cEntropyInputLen    - Length of the buffer which has
     * entropy stored
     * @param p_cAdditionalInput     - Additional Entropy from user
     * @param cAdditionalInputLen - Length of the additional entropy
     * buffer
     */
    void internalReseed(const Uint8* p_cEntropyInput,
                        const Uint64 cEntropyInputLen,
                        const Uint8* p_cAdditionalInput,
                        const Uint64 cAdditionalInputLen);
    /**
     * @brief Reseed the drbg internal state for unpredictability.
     *
     * @param p_cEntropyInput    - Buffer which has entropy vector<Uint8>
     * @param p_cAdditionalInput - Additional Entropy from user
     * vector<Uint8>
     */
    void internalReseed(const std::vector<Uint8>& cEntropyInput,
                        const std::vector<Uint8>& cAdditionalInput);

    // FIXME: This should not exist, its a key leakage, leaving it here
    // for debugging sake
    /**
     * @brief Get a copy of internal Key
     *
     * @return std::vector<Uint8> Key vector
     */
    std::vector<Uint8> getKCopy();

    /**
     * @brief Get a copy of internal Value
     *
     * @return std::vector<Uint8> Value vector
     */
    std::vector<Uint8> getVCopy();
};

} // namespace alcp::rng::drbg
