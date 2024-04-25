/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

#include "alcp/capi/cipher/builder.hh"
#include "alcp/cipher/aes.hh"

using alcp::utils::CpuId;
namespace alcp::cipher {
CpuCipherFeatures
getCpuCipherfeature()
{
    CpuCipherFeatures cpu_feature =
        CpuCipherFeatures::eReference; // If no arch features present,means
                                       // no acceleration, Fall back to
                                       // reference

    if (CpuId::cpuHasAesni()) {
        cpu_feature = CpuCipherFeatures::eAesni;

        if (CpuId::cpuHasVaes()) {
            cpu_feature = CpuCipherFeatures::eVaes256;

            if (CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
                && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_DQ)
                && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW)) {
                cpu_feature = CpuCipherFeatures::eVaes512;
            }
        }
    }
    return cpu_feature;
}
} // namespace alcp::cipher