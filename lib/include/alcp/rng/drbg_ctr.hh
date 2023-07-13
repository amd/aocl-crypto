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
#include "alcp/rng/drbg.hh"
#include "iostream"
#include <immintrin.h>

// FIXME: Remove once debug ctr debug utilities are removed
// #define DEBUG 0

namespace alcp::rng::drbg {

namespace avx2 {
    ALCP_API_EXPORT void encrypt_block(Uint8*       input,
                                       const Uint8* key,
                                       Uint64       key_size,
                                       Uint8*       output);
    ALCP_API_EXPORT void ctrDrbgUpdate(const Uint8  p_provided_data[],
                                       const Uint64 cProvidedDataLen,
                                       Uint8*       key,
                                       Uint64       key_len,
                                       Uint8*       value);

    ALCP_API_EXPORT void DrbgCtrGenerate(const Uint8  cAdditionalInput[],
                                         const Uint64 cAdditionalInputLen,
                                         Uint8        output[],
                                         const Uint64 cOutputLen,
                                         Uint8*       key,
                                         Uint64       key_len,
                                         Uint8*       value,
                                         Uint64       value_len);
} // namespace avx2

// Data structures and functions for debugging. FIXME: Remove once API testing
// is in place.
typedef union _reg_128
{
    __m128i  reg;
    uint64_t u64[2];
    uint32_t u32[4];
    uint16_t u16[8];
    uint8_t  u8[16];

} reg_128;

typedef union
{
    __m256i  reg;
    uint64_t u64[4];
    uint32_t u32[8];
    uint16_t u16[16];
    uint8_t  u8[32];

} reg_256;

inline std::string
parseBytesToHexStr(const uint8_t* bytes, const int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        int               charRep;
        std::stringstream il;
        charRep = bytes[i];
        // Convert int to hex
        il << std::hex << charRep;
        std::string ilStr = il.str();
        // 01 will be 0x1 so we need to make it 0x01
        if (ilStr.size() != 2) {
            ilStr = "0" + ilStr;
        }
        ss << ilStr;
    }
    // return "something";
    return ss.str();
}

template<typename T>
inline void
print(T reg, bool split_64 = false, bool split_bytes = false)
{
    for (int i = sizeof(reg) - 1; i > -1; i--) {
        if (split_64 && (i == 7 || i == 15 || i == 23)) {
            std::cout << " ";
        }
        std::cout << parseBytesToHexStr((const uint8_t*)&(reg.u8) + i, 1);
        if (split_bytes) {
            std::cout << " ";
        }
    }
}
template<typename VectType>
using concat_type_t = std::vector<const std::vector<VectType>*>;
void
DebugPrint(const std::vector<Uint8>& p_cIn,
           std::string               message,
           std::string               file,
           int                       line);
// end of debugging structures and functions

class ALCP_API_EXPORT CtrDrbg : public Drbg
{
  private:
    class Impl;

    std::unique_ptr<Impl> p_impl;

  public:
    std::string name() const;
    CtrDrbg();
    ~CtrDrbg();

    void setKeySize(Uint64 keySize);

  protected:
    /**
     * @brief Given Data and Length, updates key and value internally
     *
     * @param p_cProvidedData    - Uint8 of data
     * @param cProvidedDataLen  - Length of the data p_cIn bytes
     */
    void update(const Uint8 p_cProvidedData[], const Uint64 cProvidedDataLen);

    /**
     * @brief Given Data and Length, updates key and value internally
     *
     * @param p_cProvidedData    - vector<Uint8> of data
     */
    void update(const std::vector<Uint8>& cProvidedData);

    /**
     * @brief Instantiate DRBG given Entropy, Nonce, Personal Data
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
     * @param p_cEntropyInput           - vector<Uint8> of entropy
     * @param cNonce                   - vector<Uint8> which has p_cNonce
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
    void generate(const Uint8  p_cAdditionalInput[],
                  const Uint64 cAdditionalInputLen,
                  Uint8        p_cOutput[],
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
    void internalReseed(const Uint8  p_cEntropyInput[],
                        const Uint64 cEntropyInputLen,
                        const Uint8  p_cAdditionalInput[],
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