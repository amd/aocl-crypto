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

// CTR DRBG is implemented as per NIST.SP.800-90Ar1 and the algorithm
// steps are also shown as in the documentation as part of the code for future
// matching and references
#include "alcp/rng/drbg_ctr.hh"
#include "alcp/cipher/aes.hh"
#include "alcp/utils/bignum.hh"
#include "alcp/utils/copy.hh"

namespace alcp::rng::drbg {

class CtrDrbg::Impl
{
  private:
    std::vector<Uint8> m_v = std::vector<Uint8>(16);
    std::vector<Uint8> m_key;
    Uint64             m_keySize                 = 0;
    Uint64             m_seedlength              = 0;
    bool               m_use_derivation_function = false;

  public:
    void setKeySize(Uint64 keySize);
    void setUseDerivationFunction(const bool use_derivation_function);

    /**
     * @brief Given Data and Length, updates key and value internally
     *
     * @param cProvidedData    - Uint8 of data
     * @param cProvidedDataLen  - Length of the data p_cIn bytes
     */
    void update(const Uint8 cProvidedData[], const Uint64 cProvidedDataLen);

    /**
     * @brief Given Data and Length, updates key and value internally
     *
     * @param p_cProvidedData    - vector<Uint8> of data
     */
    void update(const std::vector<Uint8>& cProvidedData);

    /**
     * @brief Insitantiate DRBG given Entropy, Nonce, Personal Data
     *
     * @param cEntropyInput               - Pointer to location where
     * entropy is stored
     * @param cEntropyInputLen           - Length of the entropy buffer
     * @param cNonce                       - Number used only once
     * @param cNonceLen                   - Length of the number buffer
     * p_cIn bytes
     * @param cPersonalizationString      - Additional Entropy by user
     * @param cPersonalizationStringLen  - Length of the
     * personalization string
     */
    void instantiate(const Uint8  cEntropyInput[],
                     const Uint64 cEntropyInputLen,
                     const Uint8  cNonce[],
                     const Uint64 cNonceLen,
                     const Uint8  cPersonalizationString[],
                     const Uint64 cPersonalizationStringLen);

    /**
     * @brief Insitantiate DRBG given Entropy, Nonce, Personal Data
     *
     * @param cEntropyInput           - vector<Uint8> of entropy
     * @param cNonce                   - vector<Uint8> which has p_cNonce
     * value
     * @param cPersonalizationString  - vector<Uint8> given by user as
     * additional entropy
     */
    void instantiate(const std::vector<Uint8>& cEntropyInput,
                     const std::vector<Uint8>& cNonce,
                     const std::vector<Uint8>& cPersonalizationString);

    /**
     * @brief Generates the drbg random bits given additional data and
     * buffer to p_cOutput to
     *
     * @param cAdditionalInput     - Additional entropy buffer
     * @param cAdditionalInputLen - Length of the additional entropy
     * buffer
     * @param p_cOutput               - Output buffer
     * @param cOutputLen           - Length of the cOutput buffer
     */
    void generate(const Uint8  cAdditionalInput[],
                  const Uint64 cAdditionalInputLen,
                  Uint8        cOutput[],
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
     * @param cEntropyInput        - Buffer which has entropy
     * @param cEntropyInputLen    - Length of the buffer which has
     * entropy stored
     * @param cAdditionalInput     - Additional Entropy from user
     * @param cAdditionalInputLen - Length of the additional entropy
     * buffer
     */
    void internalReseed(const Uint8  cEntropyInput[],
                        const Uint64 cEntropyInputLen,
                        const Uint8  cAdditionalInput[],
                        const Uint64 cAdditionalInputLen);

    /**
     * @brief Reseed the drbg internal state for unpredictability.
     *
     * @param cEntropyInput    - Buffer which has entropy vector<Uint8>
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
    std::vector<Uint8> getKCopy() { return m_key; }

    /**
     * @brief Get a copy of internal Value
     *
     * @return std::vector<Uint8> Value vector
     */
    std::vector<Uint8> getVCopy() { return m_v; }

    Impl()  = default;
    ~Impl() = default;
};

void
CtrDrbg::Impl::update(const Uint8  p_provided_data[],
                      const Uint64 cProvidedDataLen)
{
    avx2::ctrDrbgUpdate(
        p_provided_data, cProvidedDataLen, &m_key[0], m_keySize, &m_v[0]);
}

void
CtrDrbg::Impl::update(const std::vector<Uint8>& p_provided_data)
{
    update(&p_provided_data[0], p_provided_data.size());
}

// CTR_DRBG_Instantiate_algorithm
void
CtrDrbg::Impl::instantiate(const Uint8  cEntropyInput[],
                           const Uint64 cEntropyInputLen,
                           const Uint8  cNonce[],
                           const Uint64 cNonceLen,
                           const Uint8  cPersonalizationString[],
                           const Uint64 cPersonalizationStringLen)
{
#ifdef DEBUG
    printf("Running CtrDrbg Instantiate\n");
#endif
    // From NIST documentation, temp = len (personalization_string). This does
    // not mean temp is length. This means a temporary buffer temp of
    // seed_length is created.

    // ALGO: If (temp < seedlen), then personalization_string =
    // personalization_string || 0^(seedlen- temp)

    // Here buffer is created of length m_seedlength and not
    // cPersonalizationStringLen to avoid further padding of 0^(seedlen- temp)
    // Uint8 seed_material_copy[m_seedlength] = {};

    // Key = 0^keylen
    std::fill(m_key.begin(), m_key.end(), 0);
    // V = 0^blocklen
    std::fill(m_v.begin(), m_v.end(), 0);

    std::vector<Uint8> seed_material_copy;
    if (!m_use_derivation_function) {
        seed_material_copy = std::vector<Uint8>(m_seedlength, 0);
        utils::CopyBytes(&seed_material_copy[0],
                         cPersonalizationString,
                         cPersonalizationStringLen);

        // seed_material = entropy_input ⊕ personalization_string.
        assert(cEntropyInputLen == m_seedlength);
        for (Uint64 i = 0; i < cEntropyInputLen; i++) {
            seed_material_copy[i] = cEntropyInput[i] ^ seed_material_copy[i];
        }

        DebugPrint(m_key, "K", __FILE__, __LINE__);
        DebugPrint(m_v, "V", __FILE__, __LINE__);
#ifdef DEBUG
        std::cout << "&seed_material_copy[0]: "
                  << parseBytesToHexStr(&seed_material_copy[0],
                                        seed_material.size())
                  << std::endl;
        std::cout << "Seed Material Length: " << seed_material.size()
                  << std::endl;
#endif
        // (Key, V) = CTR_DRBG_Update (seed_material, Key, V).
        update(&seed_material_copy[0], seed_material_copy.size());

        DebugPrint(m_key, "K", __FILE__, __LINE__);
        DebugPrint(m_v, "V", __FILE__, __LINE__);

        // FIXME: Currently no reseed counter is there
        // reseed_counter = 1
    } else {
        seed_material_copy = std::vector<Uint8>(
            cEntropyInputLen + cNonceLen + cPersonalizationStringLen, 0);
        // Copy can't be avoided
        utils::CopyBytes(
            &seed_material_copy[0], cEntropyInput, cEntropyInputLen);
        utils::CopyBytes(
            &seed_material_copy[0] + cEntropyInputLen, cNonce, cNonceLen);
        utils::CopyBytes(&seed_material_copy[0] + cEntropyInputLen + cNonceLen,
                         cPersonalizationString,
                         cPersonalizationStringLen);

        std::vector<Uint8> df_output(m_seedlength);
        alcp::rng::drbg::avx2::Block_Cipher_df(&seed_material_copy[0],
                                               seed_material_copy.size() * 8,
                                               &df_output[0],
                                               df_output.size() * 8,
                                               m_key.size());

        DebugPrint(m_key, "K", __FILE__, __LINE__);
        DebugPrint(m_v, "V", __FILE__, __LINE__);
#ifdef DEBUG
        std::cout << "&seed_material_copy[0]: "
                  << parseBytesToHexStr(&seed_material_copy[0],
                                        seed_material.size())
                  << std::endl;
        std::cout << "Seed Material Length: " << seed_material.size()
                  << std::endl;
#endif
        // (Key, V) = CTR_DRBG_Update (seed_material, Key, V).
        update(&df_output[0], df_output.size());

        DebugPrint(m_key, "K", __FILE__, __LINE__);
        DebugPrint(m_v, "V", __FILE__, __LINE__);

        // FIXME: Currently no reseed counter is there
        // reseed_counter = 1
    }
}

void
CtrDrbg::Impl::instantiate(const std::vector<Uint8>& cEntropyInput,
                           const std::vector<Uint8>& cNonce,
                           const std::vector<Uint8>& cPersonalizationString)
{
    instantiate(&cEntropyInput[0],
                cEntropyInput.size(),
                &cNonce[0],
                cNonce.size(),
                &cPersonalizationString[0],
                cPersonalizationString.size());
}

void
CtrDrbg::Impl::internalReseed(const Uint8  cEntropyInput[],
                              const Uint64 cEntropyInputLen,
                              const Uint8  cAdditionalInput[],
                              const Uint64 cAdditionalInputLen)
{

    // TODO: Reseed to be implemented
}

void
CtrDrbg::Impl::internalReseed(const std::vector<Uint8>& cEntropyInput,
                              const std::vector<Uint8>& cAdditionalInput)
{
    internalReseed(&cEntropyInput[0],
                   cEntropyInput.size(),
                   &cAdditionalInput[0],
                   cAdditionalInput.size());
}

void
CtrDrbg::Impl::generate(const std::vector<Uint8>& cAdditionalInput,
                        std::vector<Uint8>&       output)
{
    generate(&cAdditionalInput[0],
             cAdditionalInput.size(),
             &output[0],
             output.size());
}

void
CtrDrbg::Impl::generate(const Uint8  cAdditionalInput[],
                        const Uint64 cAdditionalInputLen,
                        Uint8        output[],
                        const Uint64 cOutputLen)
{
    alcp::rng::drbg::avx2::DrbgCtrGenerate(cAdditionalInput,
                                           cAdditionalInputLen,
                                           output,
                                           cOutputLen,
                                           &m_key[0],
                                           m_key.size(),
                                           &m_v[0],
                                           m_v.size(),
                                           m_use_derivation_function);
}

void
CtrDrbg::Impl::setKeySize(Uint64 keySize)
{
    m_keySize    = keySize;
    m_seedlength = 16 + m_keySize;

    m_key = std::vector<Uint8>(m_keySize);
#ifdef DEBUG
    std::cout << "Key value after setting "
              << parseBytesToHexStr(&m_key[0], m_key.size()) << std::endl;

    std::cout << "Key length after setting " << m_keySize << std::endl;
#endif
}

void
CtrDrbg::Impl::setUseDerivationFunction(const bool use_derivation_function)
{
    m_use_derivation_function = use_derivation_function;
}

void
CtrDrbg::generate(const Uint8* p_cAdditionalInput,
                  const Uint64 cAdditionalInputLen,
                  Uint8*       p_cOutput,
                  const Uint64 cOutputLen)
{
    p_impl->generate(
        p_cAdditionalInput, cAdditionalInputLen, p_cOutput, cOutputLen);
}

void
CtrDrbg::generate(const std::vector<Uint8>& cAdditionalInput,
                  std::vector<Uint8>&       cOutput)
{
    p_impl->generate(cAdditionalInput, cOutput);
}

void
CtrDrbg::internalReseed(const Uint8  p_cEntropyInput[],
                        const Uint64 cEntropyInputLen,
                        const Uint8  p_cAdditionalInput[],
                        const Uint64 cAdditionalInputLen)
{
    p_impl->internalReseed(p_cEntropyInput,
                           cEntropyInputLen,
                           p_cAdditionalInput,
                           cAdditionalInputLen);
}

void
CtrDrbg::internalReseed(const std::vector<Uint8>& cEntropyInput,
                        const std::vector<Uint8>& cAdditionalInput)
{
    p_impl->internalReseed(cEntropyInput, cAdditionalInput);
}

void
CtrDrbg::instantiate(const Uint8  cEntropyInput[],
                     const Uint64 cEntropyInputLen,
                     const Uint8  cNonce[],
                     const Uint64 cNonceLen,
                     const Uint8  cPersonalizationString[],
                     const Uint64 cPersonalizationStringLen)
{
    p_impl->instantiate(cEntropyInput,
                        cEntropyInputLen,
                        cNonce,
                        cNonceLen,
                        cPersonalizationString,
                        cPersonalizationStringLen);
}

void
CtrDrbg::instantiate(const std::vector<Uint8>& cEntropyInput,
                     const std::vector<Uint8>& cNonce,
                     const std::vector<Uint8>& cPersonalizationString)
{
    p_impl->instantiate(cEntropyInput, cNonce, cPersonalizationString);
}

void
CtrDrbg::setKeySize(Uint64 keySize)
{
    p_impl->setKeySize(keySize);
}

void
CtrDrbg::setUseDerivationFunction(const bool use_derivation_function)
{
    p_impl->setUseDerivationFunction(use_derivation_function);
}

std::string
CtrDrbg::name() const
{
    return "CTR-DRBG";
}

std::vector<Uint8>
CtrDrbg::getKCopy()
{
    return p_impl.get()->getKCopy();
}

std::vector<Uint8>
CtrDrbg::getVCopy()
{
    return p_impl.get()->getVCopy();
}

CtrDrbg::CtrDrbg()
    : p_impl{ std::make_unique<Impl>() }
{}

CtrDrbg::~CtrDrbg() = default;

} // namespace alcp::rng::drbg
