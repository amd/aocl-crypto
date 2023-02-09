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
    class IHmacDrbg
    {
      private:
        std::shared_ptr<alcp::digest::Digest> m_digest;
        std::vector<Uint8>                    m_v = {}, m_key = {};

      public:
        /**
         * @brief Concatinate List of vectors into a single vector
         *
         * @param p_cIn - Set of Vectors concat_type_t
         * @param p_out - Buffer to write to, Vector of bytes.
         */
        static void concat(concat_type_t<Uint8>& p_cIn,
                           std::vector<Uint8>&   out);
        /**
         * @brief Given input (key,data,sha_object) will give p_out the HMAC
         * directly. Input will all be treated same as if they are
         * concatinated into single input.
         * @param key     - Key used for HMAC
         * @param key_len - Length of the HMAC Key
         * @param p_cIn1     - First input
         * @param cIn1Len - Length of the first input
         * @param p_cIn2     - Second input
         * @param cIn2Len - Length of the second input
         * @param p_cIn3     - Third input
         * @param cIn3Len - Length of the third input
         * @param p_out     - Output buffer
         * @param cOutLen - Allocated memory of p_cOutput buffer
         * @param sha_ob  - Pointer to the SHA object
         */
        void HMAC_Wrapper(const Uint8* p_cIn1,
                          const Uint64 cIn1Len,
                          const Uint8* p_cIn2,
                          const Uint64 cIn2Len,
                          const Uint8* p_cIn3,
                          const Uint64 cIn3Len,
                          Uint8*       p_out,
                          const Uint64 cOutLen);
        /**
         * @brief Given input (key,data,sha_object) will give p_out the HMAC
         * directly. Input will all be treated same as if they are
         * concatinated into single input.
         * @param key     - Key used for HMAC
         * @param key_len - Length of the HMAC Key
         * @param p_cIn     - First input
         * @param cInLen - Length of the first input
         * @param p_cIn1     - Second input
         * @param cIn1Len - Length of the second input
         * @param p_out     - Output buffer
         * @param cOutLen - Allocated memory of p_cOutput buffer
         * @param sha_ob  - Pointer to the SHA object
         */
        void HMAC_Wrapper(const Uint8* p_cIn,
                          const Uint64 cInLen,
                          const Uint8* p_cIn1,
                          const Uint64 cIn1Len,
                          Uint8*       p_out,
                          const Uint64 cOutLen);
        /**
         * @brief Given input (key,data,sha_object) will give p_out the HMAC
         * directly.
         * @param key     - Key used for HMAC
         * @param key_len - Length of the HMAC Key
         * @param p_cIn     - First input
         * @param cInLen - Length of the first input
         * @param p_out     - Output buffer
         * @param cOutLen - Allocated memory of p_cOutput buffer
         * @param sha_ob  - Pointer to the SHA object
         */
        void HMAC_Wrapper(const Uint8* p_cIn,
                          const Uint64 cInLen,
                          Uint8*       p_out,
                          const Uint64 cOutLen);
        /**
         * @brief Given input (key,data,sha_object) will give p_out the HMAC
         * directly.
         *
         * @param key     - Key used for HMAC vector<Uint8>
         * @param p_cIn      - Input data vector<Uint8>
         * @param p_out     - Output buffer vector<Uint8>
         * @param sha_obj - Pointer to SHA object
         */
        void HMAC_Wrapper(const std::vector<Uint8>& cIn,
                          std::vector<Uint8>&       out);
        /**
         * @brief Given Data and Length, updates key and value internally
         *
         * @param p_cProvidedData    - Uint8 of data
         * @param cProvidedDataLen  - Length of the data p_cIn bytes
         */
        void Update(const Uint8* p_cProvidedData,
                    const Uint64 cProvidedDataLen);
        /**
         * @brief Given Data and Length, updates key and value internally
         *
         * @param p_cProvidedData    - vector<Uint8> of data
         */
        void Update(const std::vector<Uint8>& cProvidedData);
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

        /**
         * @brief Get a copy of internal Key
         *
         * @return std::vector<Uint8> Key vector
         */
        std::vector<Uint8> GetKCopy() { return m_key; }
        /**
         * @brief Get a copy of internal Value
         *
         * @return std::vector<Uint8> Value vector
         */
        std::vector<Uint8> GetVCopy() { return m_v; }

        IHmacDrbg() = default;
        IHmacDrbg(int                                   digestSize,
                  std::shared_ptr<alcp::digest::Digest> digestObj);
        ~IHmacDrbg() = default;
    };

    std::unique_ptr<IHmacDrbg> p_impl = {};

  public:
    /**
     * @brief Given Data and Length, updates key and value internally
     *
     * @param p_cProvidedData    - Uint8 of data
     * @param cProvidedDataLen  - Length of the data p_cIn bytes
     */
    void Update(const Uint8* p_cProvidedData, const Uint64 cProvidedDataLen)
    {
        p_impl->Update(p_cProvidedData, cProvidedDataLen);
    }
    /**
     * @brief Given Data and Length, updates key and value internally
     *
     * @param p_cProvidedData    - vector<Uint8> of data
     */
    void Update(const std::vector<Uint8>& p_cProvidedData)
    {
        p_impl->Update(p_cProvidedData);
    }
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
                     const Uint64 p_cPersonalizationStringLen)
    {
        p_impl->instantiate(p_cEntropyInput,
                            cEntropyInputLen,
                            p_cNonce,
                            cNonceLen,
                            p_cPersonalizationString,
                            p_cPersonalizationStringLen);
    }
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
                     const std::vector<Uint8>& cPersonalizationString)
    {
        p_impl->instantiate(cEntropyInput, cNonce, cPersonalizationString);
    }
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
                  const Uint64 cOutputLen)
    {
        p_impl->generate(
            p_cAdditionalInput, cAdditionalInputLen, p_cOutput, cOutputLen);
    }
    /**
     * @brief Generates the drbg random bits given additional data and
     * buffer to p_cOutput to
     *
     * @param p_cAdditionalInput     - Additional entropy buffer
     * vector<Uint8>
     * @param p_cOutput               - Output buffer vector<Uint8>
     */
    void generate(const std::vector<Uint8>& cAdditionalInput,
                  std::vector<Uint8>&       cOutput)
    {
        p_impl->generate(cAdditionalInput, cOutput);
    }
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

    std::string name() const { return "HMAC-DRBG"; }

    // FIXME: This should not exist, its a key leakage, leaving it here
    // for debugging sake
    /**
     * @brief Get a copy of internal Key
     *
     * @return std::vector<Uint8> Key vector
     */
    std::vector<Uint8> GetKCopy() { return p_impl.get()->GetKCopy(); }
    /**
     * @brief Get a copy of internal Value
     *
     * @return std::vector<Uint8> Value vector
     */
    std::vector<Uint8> GetVCopy() { return p_impl.get()->GetVCopy(); }

    HmacDrbg()
        : p_impl{ std::make_unique<IHmacDrbg>() }
    {}
    HmacDrbg(int digestSize, std::shared_ptr<alcp::digest::Digest> digestObj)
        : p_impl{ std::make_unique<IHmacDrbg>(digestSize, digestObj) }
    {}
    HmacDrbg(int                                   digestSize,
             std::shared_ptr<alcp::digest::Digest> digestObj,
             std::shared_ptr<IRng>                 pEntropyIn)
        : Drbg::Drbg(pEntropyIn)
        , p_impl{ std::make_unique<IHmacDrbg>(digestSize, digestObj) }
    {}
    ~HmacDrbg() = default;

  protected:
    void internalReseed(const Uint8* p_cEntropyInput,
                        const Uint64 cEntropyInputLen,
                        const Uint8* p_cAdditionalInput,
                        const Uint64 cAdditionalInputLen)
    {
        p_impl->internalReseed(p_cEntropyInput,
                               cEntropyInputLen,
                               p_cAdditionalInput,
                               cAdditionalInputLen);
    }
    /**
     * @brief Reseed the drbg internal state for unpredictability.
     *
     * @param p_cEntropyInput    - Buffer which has entropy vector<Uint8>
     * @param p_cAdditionalInput - Additional Entropy from user
     * vector<Uint8>
     */
    void internalReseed(const std::vector<Uint8>& cEntropyInput,
                        const std::vector<Uint8>& cAdditionalInput)
    {
        p_impl->internalReseed(cEntropyInput, cAdditionalInput);
    }
};

} // namespace alcp::rng::drbg
