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
#include "alci/cpu_features.h"
#endif

namespace alcp::utils {

class CpuId::Impl
{
  public:
    Impl()  = default;
    ~Impl() = default;

  public:
    // Genoa functions
    /**
     * @brief Returns true if CPU has AVX512f Flag
     *
     * @return true
     * @return false
     */
    static inline bool cpuHasAvx512f();
    /**
     * @brief Returns true if CPU has AVX512DQ Flag
     *
     * @return true
     * @return false
     */
    static inline bool cpuHasAvx512dq();
    /**
     * @brief Retrurns true if CPU has AVX512BW Flag
     *
     * @return true
     * @return false
     */
    static inline bool cpuHasAvx512bw();
    /**
     * @brief Returns true depending on the flag is available or not on CPU
     *
     * @param flag Which AVX512 flag to get info on.
     * @return true
     * @return false
     */
    static inline bool cpuHasAvx512(avx512_flags_t flag);

    // Milan functions
    /**
     * @brief Returns true if CPU supports vector AES
     * @note  Will return true if either 256 or 512 bit vector AES is supported
     *
     * @return true
     * @return false
     */
    static inline bool cpuHasVaes();

    // Rome functions
    /**
     * @brief Returns true if CPU supports block AES instruction
     *
     * @return true
     * @return false
     */
    static inline bool cpuHasAesni();
    /**
     * @brief Returns true if CPU supports block SHA instruction
     *
     * @return true
     * @return false
     */
    static inline bool cpuHasShani();
    /**
     * @brief Returns true if CPU supports AVX2 instructions
     *
     * @return true
     * @return false
     */
    static inline bool cpuHasAvx2();
    /**
     * @brief Returns true if RDRAND, secure RNG number generator is supported
     * by CPU
     *
     * @return true
     * @return false
     */
    static inline bool cpuHasRdRand();
    /**
     * @brief Returns true if RDSEED, secure RNG seed generator is supported by
     * CPU
     *
     * @return true
     * @return false
     */
    static inline bool cpuHasRdSeed();
    /**
     * @brief Returns true if currently executing cpu is Zen1
     *
     * @return true
     * @return false
     */
    static inline bool cpuIsZen1();
    /**
     * @brief Returns true if currently executing cpu is Zen2
     *
     * @return true
     * @return false
     */
    static inline bool cpuIsZen2();
    /**
     * @brief Returns true if currently executing cpu is Zen3
     *
     * @return true
     * @return false
     */
    static inline bool cpuIsZen3();
    /**l
     * @brief Returns true if currently executing cpu is Zen4
     *
     * @return true
     * @return false
     */
    static inline bool cpuIsZen4();
};

bool
CpuId::Impl::cpuHasAvx512f()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_avx512f() > 0);
#else
    state = UNAVAILABLE;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512dq()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_avx512dq() > 0);
#else
    state = UNAVAILABLE;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512bw()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_avx512bw() > 0);
#else
    state = UNAVAILABLE;
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

/**
 * In the below functions there is a state variable,
 *
 * This state variable can be of 3 states,
 * 1) Unavailable - means the flag is not detected in cpu
 * 2) Available   - means the flag is detected or force enabled.
 * 3) Unknown.    - means the flag is uninitialized and unknown.
 *
 * Purpose of making state variable static is to cache the information,
 * thereby not hindering the performance of the code which is calling this
 * function.
 */
bool
CpuId::Impl::cpuHasVaes()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_vaes() > 0);
#else
    state = UNAVAILABLE;
#endif
    return state;
}
bool
CpuId::Impl::cpuHasAesni()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_aes() > 0);
#else
    // FIXME: Settig SHANI as available by default
    state = AVAILABLE;
#endif
    return state;
}
bool
CpuId::Impl::cpuHasShani()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_sha() > 0);
#else
    // FIXME: Settig SHANI as available by default
    state = AVAILABLE;
#endif
    return state;
}
bool
CpuId::Impl::cpuHasAvx2()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
    // FIXME: CPUID does not support this.
    state = AVAILABLE;
    return state;
}
bool
CpuId::Impl::cpuHasRdRand()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_rdrnd() > 0);
#else
    state = UNAVAILABLE;
#endif
    return state;
}
bool
CpuId::Impl::cpuHasRdSeed()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_rdseed() > 0);
#else
    state = UNAVAILABLE;
#endif
    return state;
}
bool
CpuId::Impl::cpuIsZen1()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
// FIXME: CPUID alc_cpu_arch_is_zen is broken, debug statements below will be
// removed after that fix
#if 0
    state = (alc_cpu_arch_is_zen() > 0);
#else
    state = AVAILABLE;
#endif
    // printf("Debug CPUID ZEN1:%d\n", state);
#else
    state = UNAVAILABLE;
#endif
    return state;
}
bool
CpuId::Impl::cpuIsZen2()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_arch_is_zen2() > 0);
#else
    state = UNAVAILABLE;
#endif
    return state;
}
bool
CpuId::Impl::cpuIsZen3()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_arch_is_zen3() > 0);
#else
    state = UNAVAILABLE;
#endif
    return state;
}
bool
CpuId::Impl::cpuIsZen4()
{
    static int state = UNKNOWN;
    if (state != UNKNOWN) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_arch_is_zen4() > 0);
#else
    state = UNAVAILABLE;
#endif
    return state;
}

bool
CpuId::cpuHasAesni()
{
    return Impl::cpuHasAesni();
}

bool
CpuId::cpuHasAvx2()
{
    return Impl::cpuHasAvx2();
}

bool
CpuId::cpuHasAvx512(avx512_flags_t flag)
{
    return Impl::cpuHasAvx512(flag);
}

bool
CpuId::cpuHasAvx512bw()
{
    return Impl::cpuHasAvx512bw();
}

bool
CpuId::cpuHasAvx512dq()
{
    return Impl::cpuHasAvx512dq();
}

bool
CpuId::cpuHasAvx512f()
{
    return Impl::cpuHasAvx512f();
}

bool
CpuId::cpuHasShani()
{
    return Impl::cpuHasShani();
}

bool
CpuId::cpuHasVaes()
{
    return Impl::cpuHasVaes();
}

bool
CpuId::cpuHasRdRand()
{
    return Impl::cpuHasRdRand();
}

bool
CpuId::cpuHasRdSeed()
{
    return Impl::cpuHasRdSeed();
}

bool
CpuId::cpuIsZen1()
{
    return Impl::cpuIsZen1();
}

bool
CpuId::cpuIsZen2()
{
    return Impl::cpuIsZen2();
}

bool
CpuId::cpuIsZen3()
{
    return Impl::cpuIsZen3();
}

bool
CpuId::cpuIsZen4()
{
    return Impl::cpuIsZen4();
}

CpuId::CpuId()  = default;
CpuId::~CpuId() = default;

} // namespace alcp::utils