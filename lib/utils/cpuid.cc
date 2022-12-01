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

#include "utils/cpuid.hh"
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
};

bool
Cpuid::Impl::cpuHasAvx512f()
{
    static int m_avx512f = -1;
    if (m_avx512f != -1) {
        return m_avx512f;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    m_avx512f = (alc_cpu_has_avx512f() > 0);
#else
    m_avx512f  = 0;
#endif
    return m_avx512f;
}

bool
Cpuid::Impl::cpuHasAvx512dq()
{
    static int m_avx512dq = -1;
    if (m_avx512dq != -1) {
        return m_avx512dq;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    m_avx512dq = (alc_cpu_has_avx512dq() > 0);
#else
    m_avx512dq = 0;
#endif
    return m_avx512dq;
}

bool
Cpuid::Impl::cpuHasAvx512bw()
{
    static int m_avx512bw = -1;
    if (m_avx512bw != -1) {
        return m_avx512bw;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    m_avx512bw = (alc_cpu_has_avx512bw() > 0);
#else
    m_avx512bw = 0;
#endif
    return m_avx512bw;
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
    static int m_vaes = -1;
    if (m_vaes != -1) {
        return m_vaes;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    m_vaes = (alc_cpu_has_vaes() > 0);
#else
    m_vaes     = 0;
#endif
    return m_vaes;
}
bool
Cpuid::Impl::cpuHasAesni()
{
    static int m_aesni = -1;
    if (m_aesni != -1) {
        return m_aesni;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    m_aesni = (alc_cpu_has_aes() > 0);
#else
    // FIXME: Settig SHANI as available by default
    m_aesni = 1;
#endif
    return m_aesni;
}
bool
Cpuid::Impl::cpuHasShani()
{
    static int m_shani = -1;
    if (m_shani != -1) {
        return m_shani;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    m_shani = (alc_cpu_has_sha() > 0);
#else
    // FIXME: Settig SHANI as available by default
    m_shani  = 1;
#endif
    return m_shani;
}
bool
Cpuid::Impl::cpuHasAvx2()
{
    static int m_avx2 = -1;
    if (m_avx2 != -1) {
        return m_avx2;
    }
    // FIXME: CPUID does not support this.
    m_avx2 = 1;
    return m_avx2;
}
bool
Cpuid::Impl::cpuHasRdRand()
{
    static int m_rdrand = -1;
    if (m_rdrand != -1) {
        return m_rdrand;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    m_rdrand = (alc_cpu_has_rdrnd() > 0);
#else
    m_rdrand = 0;
#endif
    return m_rdrand;
}
bool
Cpuid::Impl::cpuHasRdSeed()
{
    static int m_rdseed = -1;
    if (m_rdseed != -1) {
        return m_rdseed;
    }
#ifdef ALCP_ENABLE_AOCL_CPUID
    m_rdseed = (alc_cpu_has_rdseed() > 0);
#else
    m_rdseed = 0;
#endif
    return m_rdseed;
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

Cpuid::Cpuid()  = default;
Cpuid::~Cpuid() = default;

} // namespace alcp::utils