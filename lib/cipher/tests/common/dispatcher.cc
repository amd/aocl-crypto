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

#include "dispatcher.hh"

using namespace alcp::utils;
namespace alcp::cipher::unittest {

CpuCipherFeatures
getMaxFeature()
{
    CpuId             cpu;
    CpuCipherFeatures maxFeature = {};
    if (cpu.cpuHasVaes() && cpu.cpuHasAvx512f()) {
        maxFeature = utils::CpuCipherFeatures::eVaes512;
    } else if (cpu.cpuHasVaes()) {
        maxFeature = utils::CpuCipherFeatures::eVaes256;
    } else if (cpu.cpuHasAesni()) {
        maxFeature = utils::CpuCipherFeatures::eAesni;
    } else {
        maxFeature = utils::CpuCipherFeatures::eReference;
    }
    return maxFeature;
}

std::vector<CpuCipherFeatures>
getSupportedFeatures()
{
    std::vector<CpuCipherFeatures> ret        = {};
    CpuCipherFeatures              maxFeature = getMaxFeature();
    switch (maxFeature) {
        case CpuCipherFeatures::eVaes512:
            ret.insert(ret.begin(), CpuCipherFeatures::eVaes512);
        case CpuCipherFeatures::eVaes256:
            ret.insert(ret.begin(), CpuCipherFeatures::eVaes256);
        case CpuCipherFeatures::eAesni:
            ret.insert(ret.begin(), CpuCipherFeatures::eAesni);
            break;
        default:
            ret.insert(ret.begin(), CpuCipherFeatures::eReference);
            break;
    }
    return ret;
}
} // namespace alcp::cipher::unittest
