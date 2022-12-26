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

class Cpuid::Impl
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
     * @param flag
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
    /**
     * @brief Returns true if currently executing cpu is Zen4
     *
     * @return true
     * @return false
     */
    static inline bool cpuIsZen4();
};

bool
Cpuid::Impl::cpuHasAvx512f()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_avx512f() > 0);
#else
    state = 0;
#endif
    return state;
}

bool
Cpuid::Impl::cpuHasAvx512dq()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_avx512dq() > 0);
#else
    state = 0;
#endif
    return state;
}

bool
Cpuid::Impl::cpuHasAvx512bw()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_avx512bw() > 0);
#else
    state = 0;
#endif
    return state;
}

bool
Cpuid::Impl::cpuHasAvx512(avx512_flags_t flag)
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
Cpuid::Impl::cpuHasVaes()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_vaes() > 0);
#else
    state = 0;
#endif
    return state;
}
bool
Cpuid::Impl::cpuHasAesni()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_aes() > 0);
#else
    // FIXME: Settig SHANI as available by default
    state = 1;
#endif
    return state;
}
bool
Cpuid::Impl::cpuHasShani()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_sha() > 0);
#else
    // FIXME: Settig SHANI as available by default
    state = 1;
#endif
    return state;
}
bool
Cpuid::Impl::cpuHasAvx2()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
    // FIXME: CPUID does not support this.
    state = 1;
    return state;
}
bool
Cpuid::Impl::cpuHasRdRand()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_rdrnd() > 0);
#else
    state = 0;
#endif
    return state;
}
bool
Cpuid::Impl::cpuHasRdSeed()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_has_rdseed() > 0);
#else
    state = 0;
#endif
    return state;
}
bool
Cpuid::Impl::cpuIsZen2()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_arch_is_zen2() > 0);
#else
    state = 0;
#endif
    return state;
}
bool
Cpuid::Impl::cpuIsZen3()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_arch_is_zen3() > 0);
#else
    state = 0;
#endif
    return state;
}
bool
Cpuid::Impl::cpuIsZen4()
{
    static int state = -1;
    if (state != -1) {
        return state;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    state = (alc_cpu_arch_is_zen4() > 0);
#else
    state = 0;
#endif
    return state;
}

bool
Cpuid::cpuHasAesni()
{
    return Impl::cpuHasAesni();
}

bool
Cpuid::cpuHasAvx2()
{
    return Impl::cpuHasAvx2();
}

bool
Cpuid::cpuHasAvx512(avx512_flags_t flag)
{
    return Impl::cpuHasAvx512(flag);
}

bool
Cpuid::cpuHasAvx512bw()
{
    return Impl::cpuHasAvx512bw();
}

bool
Cpuid::cpuHasAvx512dq()
{
    return Impl::cpuHasAvx512dq();
}

bool
Cpuid::cpuHasAvx512f()
{
    return Impl::cpuHasAvx512f();
}

bool
Cpuid::cpuHasShani()
{
    return Impl::cpuHasShani();
}

bool
Cpuid::cpuHasVaes()
{
    return Impl::cpuHasVaes();
}

bool
Cpuid::cpuHasRdRand()
{
    return Impl::cpuHasRdRand();
}

bool
Cpuid::cpuHasRdSeed()
{
    return Impl::cpuHasRdSeed();
}

bool
Cpuid::cpuIsZen2()
{
    return Impl::cpuIsZen2();
}

bool
Cpuid::cpuIsZen3()
{
    return Impl::cpuIsZen3();
}

bool
Cpuid::cpuIsZen4()
{
    return Impl::cpuIsZen4();
}

Cpuid::Cpuid()  = default;
Cpuid::~Cpuid() = default;

} // namespace alcp::utils