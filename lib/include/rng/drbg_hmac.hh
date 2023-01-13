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

#include "alcp/alcp.h"
#include "alcp/mac.h"
#include "alcp/types.h"
#include "digest/sha2.hh"
#include "mac/hmac.hh"
#include "utils/copy.hh"
#include <functional>
#include <vector>

namespace alcp::random_number { namespace drbg {
    template<typename VectType>
    using concat_type_t = std::vector<const std::vector<VectType>*>;

    class HmacDrbg
    {
      public:
        static void concat(std::vector<const std::vector<Uint8>*>& in,
                           std::vector<Uint8>&                     out);
        static void HMAC_Wrapper(const std::vector<Uint8>& key,
                                 const std::vector<Uint8>& in,
                                 std::vector<Uint8>&       out);
        static void Update(const std::vector<Uint8>& p_provided_data,
                           std::vector<Uint8>&       p_K,
                           std::vector<Uint8>&       p_V);

        static void Instantiate(
            const std::vector<Uint8>& entropy_input,
            const std::vector<Uint8>& nonce,
            const std::vector<Uint8>& personalization_string,
            std::vector<Uint8>&       p_K,
            std::vector<Uint8>&       p_V);

        static void Generate(const std::vector<Uint8>& additional_input,
                             std::vector<Uint8>&       output,
                             std::vector<Uint8>&       p_K,
                             std::vector<Uint8>&       p_V);
        static void Reseed(const std::vector<Uint8>& entropy_input,
                           const std::vector<Uint8>& additional_input,
                           std::vector<Uint8>&       K,
                           std::vector<Uint8>&       V);
        HmacDrbg()  = default;
        ~HmacDrbg() = default;

      private:
    };
    // void concat(std::vector<const std::vector<Uint8>*>& in,
    //             std::vector<Uint8>&                     out);
    // void HMAC_Wrapper(const std::vector<Uint8>& key,
    //                   const std::vector<Uint8>& in,
    //                   std::vector<Uint8>&       out);
}} // namespace alcp::random_number::drbg