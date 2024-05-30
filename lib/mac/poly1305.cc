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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <algorithm>
#include <array>
#include <iostream>
#include <tuple>

#include "alcp/base.hh"
#include "alcp/mac/macerror.hh"
#include "alcp/mac/poly1305.hh"
#include "alcp/mac/poly1305_zen4.hh"
#include "alcp/utils/cpuid.hh"

namespace alcp::mac::poly1305 {
using utils::CpuId;

template<utils::CpuArchFeature feature>
Poly1305<feature>::Poly1305()
{
    if constexpr (utils::CpuArchFeature::eReference == feature
                  || utils::CpuArchFeature::eAvx2 == feature) {
        poly1305_impl = std::make_unique<reference::Poly1305Ref>();
    } else if constexpr (utils::CpuArchFeature::eDynamic == feature) {
        // utils::CpuArchFeature::eDynamic
        if (!(CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
              && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_DQ)
              && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW))) {
            poly1305_impl = std::make_unique<reference::Poly1305Ref>();
        }
    }
}

template<utils::CpuArchFeature feature>
Poly1305<feature>::Poly1305(const Poly1305& src)
{}

template<utils::CpuArchFeature feature>
Status
Poly1305<feature>::init(const Uint8 key[], Uint64 keyLen)
{
    if (keyLen != 32) {
        std::cout << "ERROR KEYLEN:" << keyLen << std::endl;
        return status::InitError("Wrong key size!");
    }

    // default utils::CpuArchFeature::eAvx512 is only supported.
    // ref support temporarily removed poly1305_impl->init(key, keyLen);
    zen4::poly1305_init_radix44(state, key);
    return StatusOk();

    return base::status::InternalError("Dispatch Failure");
}

template<utils::CpuArchFeature feature>
Status
Poly1305<feature>::update(const Uint8 pMsg[], Uint64 msgLen)
{
    if constexpr ((utils::CpuArchFeature::eReference == feature)
                  || (utils::CpuArchFeature::eAvx2 == feature)) {
        return poly1305_impl->update(pMsg, msgLen);
    } else if constexpr (utils::CpuArchFeature::eAvx512 == feature) {
        if (zen4::poly1305_update_radix44(state, pMsg, msgLen) == true) {
            return StatusOk();
        } else {
            return status::UpdateAfterFinalzeError("");
        }
    } else if constexpr (utils::CpuArchFeature::eDynamic == feature) {
        // Manual dispatch in case we don't know where to dispatch to.
        if (CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
            && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_DQ)
            && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW)) {
            if (zen4::poly1305_update_radix44(state, pMsg, msgLen) == true) {
                return StatusOk();
            } else {
                return status::UpdateAfterFinalzeError("");
            }
        } else {
            return poly1305_impl->update(pMsg, msgLen);
        }
    }
    return base::status::InternalError("Dispatch Failure");
}

template<utils::CpuArchFeature feature>
Status
Poly1305<feature>::reset()
{
    if constexpr ((utils::CpuArchFeature::eReference == feature)
                  || (utils::CpuArchFeature::eAvx2 == feature)) {
        return poly1305_impl->reset();
    } else if constexpr (utils::CpuArchFeature::eAvx512 == feature) {
        state.reset();
        return StatusOk();
    } else if constexpr (utils::CpuArchFeature::eDynamic == feature) {
        // Manual dispatch in case we don't know where to dispatch to.
        if (CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
            && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_DQ)
            && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW)) {
            state.reset();
            return StatusOk();
        } else {
            return poly1305_impl->reset();
        }
    }
    return base::status::InternalError("Dispatch Failure");
}

template<utils::CpuArchFeature feature>
Status
Poly1305<feature>::finalize(Uint8 digest[], Uint64 digestLen)
{
    if constexpr ((utils::CpuArchFeature::eReference == feature)
                  || (utils::CpuArchFeature::eAvx2 == feature)) {
        return poly1305_impl->finish(digest, digestLen);
    } else if constexpr (utils::CpuArchFeature::eAvx512 == feature) {
        // return poly1305_impl->finish(pMsg, msgLen);
        if (zen4::poly1305_finalize_radix44(state, digest, digestLen) == true)
            return StatusOk();
        else
            return status::AlreadyFinalizedError("");

    } else if constexpr (utils::CpuArchFeature::eDynamic == feature) {
        // Manual dispatch in case we don't know where to dispatch to.
        if (CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_F)
            && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_DQ)
            && CpuId::cpuHasAvx512(utils::Avx512Flags::AVX512_BW)) {
            if (zen4::poly1305_finalize_radix44(state, digest, digestLen)
                == true)
                return StatusOk();
            else
                return status::AlreadyFinalizedError("");
        } else {
            return poly1305_impl->finish(digest, digestLen);
        }
    }
    return base::status::InternalError("Dispatch Failure");
}

template class Poly1305<utils::CpuArchFeature::eAvx512>;
template class Poly1305<utils::CpuArchFeature::eAvx2>;
template class Poly1305<utils::CpuArchFeature::eReference>;
template class Poly1305<utils::CpuArchFeature::eDynamic>;
} // namespace alcp::mac::poly1305
