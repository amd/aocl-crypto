/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

namespace alcp::random_number { namespace drbg {
    template<typename VectType>
    using concat_type_t = std::vector<const std::vector<VectType>*>;
    void DebugPrint(const std::vector<Uint8>& in,
                    std::string               message,
                    std::string               file,
                    int                       line);

    class HmacDrbg final : public Drbg
    {
      private:
        class IHmacDrbg
        {
          private:
            std::vector<Uint8>    m_key = {}, m_v = {};
            alcp::digest::Digest* m_digest = {};

          public:
            static void concat(std::vector<const std::vector<Uint8>*>& in,
                               std::vector<Uint8>&                     out);
            static void HMAC_Wrapper(const std::vector<Uint8>& key,
                                     const std::vector<Uint8>& in,
                                     std::vector<Uint8>&       out,
                                     alcp::digest::Digest*     sha_obj);
            void        Update(const std::vector<Uint8>& p_provided_data);

            void Instantiate(const std::vector<Uint8>& entropy_input,
                             const std::vector<Uint8>& nonce,
                             const std::vector<Uint8>& personalization_string);

            void Generate(const std::vector<Uint8>& additional_input,
                          std::vector<Uint8>&       output);
            void Reseed(const std::vector<Uint8>& entropy_input,
                        const std::vector<Uint8>& additional_input);

            std::vector<Uint8> GetKCopy() { return m_key; }
            std::vector<Uint8> GetVCopy() { return m_v; }

            IHmacDrbg() = default;
            IHmacDrbg(int digestSize, alcp::digest::Digest* digest_obj);
            ~IHmacDrbg() = default;
        };

        std::unique_ptr<IHmacDrbg> p_impl = {};

      public:
        void Update(const std::vector<Uint8>& p_provided_data)
        {
            p_impl.get()->Update(p_provided_data);
        }

        void Instantiate(const std::vector<Uint8>& entropy_input,
                         const std::vector<Uint8>& nonce,
                         const std::vector<Uint8>& personalization_string)
        {
            p_impl.get()->Instantiate(
                entropy_input, nonce, personalization_string);
        }

        void Generate(const std::vector<Uint8>& additional_input,
                      std::vector<Uint8>&       output)
        {
            p_impl.get()->Generate(additional_input, output);
        }
        void Reseed(const std::vector<Uint8>& entropy_input,
                    const std::vector<Uint8>& additional_input)
        {
            p_impl.get()->Reseed(entropy_input, additional_input);
        }

        // FIXME: This should not exist, its a key leakage, leaving it here for
        // debugging sake
        std::vector<Uint8> GetKCopy() { return p_impl.get()->GetKCopy(); }
        std::vector<Uint8> GetVCopy() { return p_impl.get()->GetVCopy(); }

        HmacDrbg() { p_impl = std::make_unique<IHmacDrbg>(); };
        HmacDrbg(int digestSize, alcp::digest::Digest* digest_obj)
        {
            p_impl = std::make_unique<IHmacDrbg>(digestSize, digest_obj);
        };
        ~HmacDrbg() = default;
    };

}} // namespace alcp::random_number::drbg