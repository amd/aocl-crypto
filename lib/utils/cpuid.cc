/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include "alcp/utils/cpuid.hh"
#include "config.h"
#ifdef ALCP_ENABLE_AOCL_CPUID
#include "alci/alci.h"
#endif

namespace alcp::utils {

// FIXME: Memeory Allocations for static variables
std::unique_ptr<CpuId::Impl> CpuId::pImpl = std::make_unique<CpuId::Impl>();

bool
CpuId::Impl::cpuHasAvx512f()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isAvailable(ALC_E_FLAG_AVX512F);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512dq()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isAvailable(ALC_E_FLAG_AVX512DQ);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512bw()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isAvailable(ALC_E_FLAG_AVX512BW);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512(avx512_flags_t flag)
{
    switch (flag) {
        case AVX512_DQ:
            return cpuHasAvx512dq();
        case AVX512_F:
            return cpuHasAvx512f();
        case AVX512_BW:
            return cpuHasAvx512bw();
        default:
            // FIXME: Raise an exception
            return false;
    }
}

bool
CpuId::Impl::cpuHasVaes()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isAvailable(ALC_E_FLAG_VAES);
#else
    static bool state = false;
#endif
    return state;
}
bool
CpuId::Impl::cpuHasAesni()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isAvailable(ALC_E_FLAG_AES);
#else
    static bool state = true;
#endif
    return state;
}
bool
CpuId::Impl::cpuHasShani()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isAvailable(ALC_E_FLAG_SHA_NI);
#else
    // FIXME: Settig SHANI as available by default
    static bool state = false;
#endif
    return state;
}
bool
CpuId::Impl::cpuHasAvx2()
{
    // FIXME: CPUID does not support this.
    static int state = true;
    return state;
}
bool
CpuId::Impl::cpuHasRdRand()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isAvailable(ALC_E_FLAG_RDRAND);
#else
    static bool state = false;
#endif
    return state;
}
bool
CpuId::Impl::cpuHasRdSeed()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isAvailable(ALC_E_FLAG_RDSEED);
#else
    static bool state = false;
#endif
    return state;
}
bool
CpuId::Impl::cpuIsZen1()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isUarch(Uarch::eZen);
#else
    static bool state = false;
#endif
    return state;
}
bool
CpuId::Impl::cpuIsZen2()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isUarch(Uarch::eZen2);
#else
    static bool state = false;
#endif
    return state;
}
bool
CpuId::Impl::cpuIsZen3()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isUarch(Uarch::eZen3);
#else
    static bool state = false;
#endif
    return state;
}
bool
CpuId::Impl::cpuIsZen4()
{
#ifdef ALCP_ENABLE_AOCL_CPUID
    static bool state = Impl::m_cpu.isUarch(Uarch::eZen4);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::cpuHasAesni()
{
    return pImpl.get()->cpuHasAesni();
}

bool
CpuId::cpuHasAvx2()
{
    return pImpl.get()->cpuHasAvx2();
}

bool
CpuId::cpuHasAvx512(avx512_flags_t flag)
{
    return pImpl.get()->cpuHasAvx512(flag);
}

bool
CpuId::cpuHasAvx512bw()
{
    return pImpl.get()->cpuHasAvx512bw();
}

bool
CpuId::cpuHasAvx512dq()
{
    return pImpl.get()->cpuHasAvx512dq();
}

bool
CpuId::cpuHasAvx512f()
{
    return pImpl.get()->cpuHasAvx512f();
}

bool
CpuId::cpuHasShani()
{
    return pImpl.get()->cpuHasShani();
}

bool
CpuId::cpuHasVaes()
{
    return pImpl.get()->cpuHasVaes();
}

bool
CpuId::cpuHasRdRand()
{
    return pImpl.get()->cpuHasRdRand();
}

bool
CpuId::cpuHasRdSeed()
{
    return pImpl.get()->cpuHasRdSeed();
}

bool
CpuId::cpuIsZen1()
{
    return pImpl.get()->cpuIsZen1();
}

bool
CpuId::cpuIsZen2()
{
    return pImpl.get()->cpuIsZen2();
}

bool
CpuId::cpuIsZen3()
{
    return pImpl.get()->cpuIsZen3();
}

bool
CpuId::cpuIsZen4()
{
    return pImpl.get()->cpuIsZen4();
}

} // namespace alcp::utils