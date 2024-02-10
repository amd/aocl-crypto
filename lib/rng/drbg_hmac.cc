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

#include "alcp/rng/drbg_hmac.hh"
#include "alcp/utils/copy.hh"
#include "iostream"

namespace alcp::rng::drbg {

using alcp::digest::Digest;
using alcp::digest::Sha256;
using alcp::mac::Hmac;

/**
 * @brief Print Value in a vector given vector, file and line where its
 * called and message.
 *
 * @param in      - Vector to be print
 * @param message - Debug message to print
 * @param file    - Which file called this
 * @param line    - Which line in source code is this
 */
#ifdef DEBUG_MODE
void
DebugPrint(const std::vector<Uint8>& in,
           std::string               message,
           std::string               file,
           int                       line)
{
    std::cout << "Debug Location " << file << ":" << line << std::endl;
    std::cout << message << "=" << std::endl;
    BIO_dump_fp(stdout, &in[0], in.size());
    std::cout << std::endl;
}
#else
void
DebugPrint(const std::vector<Uint8>& in,
           std::string               message,
           std::string               file,
           int                       line)
{
}
#endif

class HmacDrbg::Impl
{
  private:
    std::shared_ptr<alcp::digest::Digest> m_digest;
    std::vector<Uint8>                    m_v = {}, m_key = {};
    Hmac                                  m_hmac_obj;

  public:
    /**
     * @brief Concatinate List of vectors into a single vector
     *
     * @param p_cIn - Set of Vectors concat_type_t
     * @param p_out - Buffer to write to, Vector of bytes.
     */
    static void concat(concat_type_t<Uint8>& p_cIn, std::vector<Uint8>& out);

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
    void HMAC_Wrapper(const Uint8  p_cIn1[],
                      const Uint64 cIn1Len,
                      const Uint8  p_cIn2[],
                      const Uint64 cIn2Len,
                      const Uint8  p_cIn3[],
                      const Uint64 cIn3Len,
                      Uint8        p_out[],
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
    void HMAC_Wrapper(const Uint8  p_cIn[],
                      const Uint64 cInLen,
                      const Uint8  p_cIn1[],
                      const Uint64 cIn1Len,
                      Uint8        p_out[],
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
    void HMAC_Wrapper(const Uint8  p_cIn[],
                      const Uint64 cInLen,
                      Uint8        p_out[],
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
    void HMAC_Wrapper(const std::vector<Uint8>& cIn, std::vector<Uint8>& out);

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

    // FIXME: Change alcp::digest::Digest to alcp::digest::IDigest
    /**
     * @brief Set the Digest object
     *
     * @param digestObject - Object of Digest class.
     * @return Status
     */
    Status setDigest(std::shared_ptr<alcp::digest::Digest> digestObject);

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
HmacDrbg::Impl::concat(concat_type_t<Uint8>& in, std::vector<Uint8>& out)
{
    int   pos   = 0;
    auto* p_out = &out[0];
    for (Uint64 i = 0; i < in.size(); i++) {
        auto current = *(in.at(i));
        utils::CopyBytes(p_out + pos, &(current[0]), current.size());
        pos += current.size();
    }
}

void
HmacDrbg::Impl::HMAC_Wrapper(const Uint8  cIn1[],
                             const Uint64 cIn1Len,
                             const Uint8  cIn2[],
                             const Uint64 cIn2Len,
                             const Uint8  cIn3[],
                             const Uint64 cIn3Len,
                             Uint8        out[],
                             const Uint64 cOutLen)
{

    m_hmac_obj.setDigest(*m_digest);
    m_hmac_obj.setKey(&m_key[0], m_key.size());
    m_hmac_obj.update(cIn1, cIn1Len);
    if (cIn2 != nullptr && cIn2Len != 0)
        m_hmac_obj.update(cIn2, cIn2Len);
    if (cIn3 != nullptr && cIn3Len != 0)
        m_hmac_obj.update(cIn3, cIn3Len);
    m_hmac_obj.finalize(nullptr, 0);

    // Assert that we have enough memory to write the output into
    assert(cOutLen >= m_digest->getHashSize());

    m_hmac_obj.copyHash(out, m_digest->getHashSize());
}

void
HmacDrbg::Impl::HMAC_Wrapper(const Uint8  cIn[],
                             const Uint64 cInLen,
                             const Uint8  cIn1[],
                             const Uint64 cIn1Len,
                             Uint8        out[],
                             const Uint64 cOutLen)
{
    HmacDrbg::Impl::HMAC_Wrapper(cIn,
                                 cInLen,
                                 cIn1,
                                 cIn1Len,
                                 nullptr,
                                 static_cast<Uint64>(0),
                                 out,
                                 cOutLen);
}

void
HmacDrbg::Impl::HMAC_Wrapper(const Uint8* cIn,
                             const Uint64 cInLen,
                             Uint8*       out,
                             const Uint64 cOutLen)
{
    HmacDrbg::Impl::HMAC_Wrapper(cIn,
                                 cInLen,
                                 nullptr,
                                 static_cast<Uint64>(0),
                                 nullptr,
                                 static_cast<Uint64>(0),
                                 out,
                                 cOutLen);
}

void
HmacDrbg::Impl::HMAC_Wrapper(const std::vector<Uint8>& cIn,
                             std::vector<Uint8>&       out)
{
    // Call the real implementation
    HMAC_Wrapper(&cIn[0], cIn.size(), &out[0], out.size());
}

/*
    NIST SP 800-90A Rev 1 Page 44
    Section 10.1.2.2
*/
void
HmacDrbg::Impl::update(const Uint8  p_provided_data[],
                       const Uint64 cProvidedDataLen)
{
    const std::vector<Uint8> cZeroVect = std::vector<Uint8>{ 0x00 };
    const std::vector<Uint8> cOneVect  = std::vector<Uint8>{ 0x01 };

    HMAC_Wrapper(&m_v[0],
                 m_v.size(),
                 &cZeroVect[0],
                 cZeroVect.size(),
                 p_provided_data,
                 cProvidedDataLen,
                 &m_key[0],
                 m_key.size());

    DebugPrint(m_key, "Update K", __FILE__, __LINE__);

    // V = HMAC(K,V)
    HMAC_Wrapper(m_v, m_v);

    DebugPrint(m_v, "Update V", __FILE__, __LINE__);

    if (cProvidedDataLen == 0) {
        return;
    }

    // K = HMAC(K,V || 0x01 || provided_data)
    HMAC_Wrapper(&m_v[0],
                 m_v.size(),
                 &cOneVect[0],
                 cOneVect.size(),
                 p_provided_data,
                 cProvidedDataLen,
                 &m_key[0],
                 m_key.size());

    // V = HMAC(K,V)
    HMAC_Wrapper(m_v, m_v);
}

void
HmacDrbg::Impl::update(const std::vector<Uint8>& p_provided_data)
{
    update(&p_provided_data[0], p_provided_data.size());
}

/*
    NIST SP 800-90A Rev 1 Page 45
    Section 10.1.2.3
*/
void
HmacDrbg::Impl::instantiate(const Uint8  cEntropyInput[],
                            const Uint64 cEntropyInputLen,
                            const Uint8  cNonce[],
                            const Uint64 cNonceLen,
                            const Uint8  cPersonalizationString[],
                            const Uint64 cPersonalizationStringLen)
{
    std::vector<Uint8> seed_material(cEntropyInputLen + cNonceLen
                                     + cPersonalizationStringLen);

    Uint8* p_seed_material_buff = &seed_material[0];

    // Copy can't be avoided
    utils::CopyBytes(p_seed_material_buff, cEntropyInput, cEntropyInputLen);
    utils::CopyBytes(
        p_seed_material_buff + cEntropyInputLen, cNonce, cNonceLen);
    if (cPersonalizationStringLen != 0)
        utils::CopyBytes(p_seed_material_buff + cEntropyInputLen + cNonceLen,
                         cPersonalizationString,
                         cPersonalizationStringLen);
    // concat(concatVect, seed_material);

    // Initialize key with 0x00
    std::fill(m_key.begin(), m_key.end(), 0);
    // Initialize v with 0x01
    std::fill(m_v.begin(), m_v.end(), 1);

    DebugPrint(m_key, "K", __FILE__, __LINE__);
    DebugPrint(m_v, "V", __FILE__, __LINE__);

    // (Key,V) = HMAC_DRBG_Update(seed_material,Key,V)
    update(p_seed_material_buff, seed_material.size());

    DebugPrint(m_key, "K", __FILE__, __LINE__);
    DebugPrint(m_v, "V", __FILE__, __LINE__);

    // FIXME: Currently no reseed counter is there
    // reseed_counter = 1
}

void
HmacDrbg::Impl::instantiate(const std::vector<Uint8>& cEntropyInput,
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

/*
    NIST SP 800-90A Rev 1 Page 46
    Section 10.1.2.5
*/
void
HmacDrbg::Impl::generate(const Uint8  cAdditionalInput[],
                         const Uint64 cAdditionalInputLen,
                         Uint8        output[],
                         const Uint64 cOutputLen)
{
    // FIXME: Implement below
    // if (reseed_counter > reseed_interval) {
    //     return reseed_required
    // }
    if (cAdditionalInputLen != 0) {
        update(cAdditionalInput, cAdditionalInputLen);
    }

    // Treating size of m_v as digest size;
    Uint64 blocks = cOutputLen / m_v.size();

    for (Uint64 i = 0; i < blocks; i++) {
        HMAC_Wrapper(m_v, m_v);

        DebugPrint(m_v, "generate: m_v", __FILE__, __LINE__);

        utils::CopyBlock(output + i * m_v.size(), &m_v[0], m_v.size());
    }

    if ((cOutputLen - (blocks * m_v.size())) != 0) {
        HMAC_Wrapper(m_v, m_v);
        utils::CopyBlock(output + blocks * m_v.size(),
                         &m_v[0],
                         (cOutputLen - (blocks * m_v.size())));
    }

    update(cAdditionalInput, cAdditionalInputLen);
    // FIXME: Reseed counter not implemented
    // reseed_counter += 1;
}

void
HmacDrbg::Impl::generate(const std::vector<Uint8>& cAdditionalInput,
                         std::vector<Uint8>&       output)
{
    generate(&cAdditionalInput[0],
             cAdditionalInput.size(),
             &output[0],
             output.size());
}

/*
    NIST SP 800-90A Rev 1 Page 46
    Section 10.1.2.4
*/
void
HmacDrbg::Impl::internalReseed(const Uint8  cEntropyInput[],
                               const Uint64 cEntropyInputLen,
                               const Uint8  cAdditionalInput[],
                               const Uint64 cAdditionalInputLen)
{
    std::vector<Uint8> seed_material(cEntropyInputLen + cAdditionalInputLen);
    Uint8*             p_seed_material = &seed_material[0];

    utils::CopyBytes(p_seed_material, cEntropyInput, cEntropyInputLen);
    utils::CopyBytes(p_seed_material + cEntropyInputLen,
                     cAdditionalInput,
                     cAdditionalInputLen);

    update(seed_material);

    // FIXME: Reseed counter not implemented yet
    // reseed_counter = 1
}

void
HmacDrbg::Impl::internalReseed(const std::vector<Uint8>& cEntropyInput,
                               const std::vector<Uint8>& cAdditionalInput)
{
    internalReseed(&cEntropyInput[0],
                   cEntropyInput.size(),
                   &cAdditionalInput[0],
                   cAdditionalInput.size());
}

Status
HmacDrbg::Impl::setDigest(std::shared_ptr<Digest> digest_obj)
{
    Status s = StatusOk();
    m_digest = digest_obj;
    // Initialize Internal States (Will serve also as reset)
    m_v   = std::vector<Uint8>(m_digest->getHashSize());
    m_key = std::vector<Uint8>(m_digest->getHashSize());
    return s;
}

void
HmacDrbg::update(const Uint8* p_cProvidedData, const Uint64 cProvidedDataLen)
{
    p_impl->update(p_cProvidedData, cProvidedDataLen);
}

void
HmacDrbg::update(const std::vector<Uint8>& p_cProvidedData)
{
    p_impl->update(p_cProvidedData);
}

void
HmacDrbg::instantiate(const Uint8  cEntropyInput[],
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
HmacDrbg::instantiate(const std::vector<Uint8>& cEntropyInput,
                      const std::vector<Uint8>& cNonce,
                      const std::vector<Uint8>& cPersonalizationString)
{
    p_impl->instantiate(cEntropyInput, cNonce, cPersonalizationString);
}

void
HmacDrbg::generate(const Uint8* p_cAdditionalInput,
                   const Uint64 cAdditionalInputLen,
                   Uint8*       p_cOutput,
                   const Uint64 cOutputLen)
{
    p_impl->generate(
        p_cAdditionalInput, cAdditionalInputLen, p_cOutput, cOutputLen);
}

void
HmacDrbg::generate(const std::vector<Uint8>& cAdditionalInput,
                   std::vector<Uint8>&       cOutput)
{
    p_impl->generate(cAdditionalInput, cOutput);
}

void
HmacDrbg::internalReseed(const Uint8  p_cEntropyInput[],
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
HmacDrbg::internalReseed(const std::vector<Uint8>& cEntropyInput,
                         const std::vector<Uint8>& cAdditionalInput)
{
    p_impl->internalReseed(cEntropyInput, cAdditionalInput);
}

Status
HmacDrbg::setDigest(std::shared_ptr<Digest> digest_obj)
{
    return p_impl->setDigest(digest_obj);
}

std::string
HmacDrbg::name() const
{
    return "HMAC-DRBG";
}

std::vector<Uint8>
HmacDrbg::getKCopy()
{
    return p_impl.get()->getKCopy();
}

std::vector<Uint8>
HmacDrbg::getVCopy()
{
    return p_impl.get()->getVCopy();
}

HmacDrbg::HmacDrbg()
    : p_impl{ std::make_unique<Impl>() }
{
}

HmacDrbg::~HmacDrbg() = default;
} // namespace alcp::rng::drbg