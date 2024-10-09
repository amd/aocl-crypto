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

#include "alcp/utils/cpuid.hh"
#include <alcp/base.hh>
#ifdef __linux__
#include <sched.h>
#include <unistd.h>
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif
#else
#include <Windows.h>
#include <direct.h>
#include <io.h>
#endif
#ifdef ALCP_ENABLE_AOCL_UTILS
#include <Au/Cpuid/X86Cpu.hh>
#endif

namespace alcp::utils {
#ifdef ALCP_ENABLE_AOCL_UTILS
using namespace Au;
#endif

// FIXME: Memory Allocations for static variables
std::unique_ptr<CpuId::Impl> CpuId::pImpl = std::make_unique<CpuId::Impl>();
// Impl class declaration
class CpuId::Impl
{
  public:
    Impl();
    ~Impl() = default;
#ifdef ALCP_ENABLE_AOCL_UTILS
    std::unique_ptr<X86Cpu> m_cpu;
#endif

  public:
    // Genoa functions
    /**
     * @brief Returns true if CPU has AVX512f Flag
     *
     * @return true
     * @return false
     */
    bool cpuHasAvx512f();
    /**
     * @brief Returns true if CPU has AVX512DQ Flag
     *
     * @return true
     * @return false
     */
    bool cpuHasAvx512dq();
    /**
     * @brief Retrurns true if CPU has AVX512BW Flag
     *
     * @return true
     * @return false
     */
    bool cpuHasAvx512bw();
    /**
     * @brief Returns true depending on the flag is available or not on CPU
     *
     * @param flag Which AVX512 flag to get info on.
     * @return true
     * @return false
     */
    bool cpuHasAvx512(Avx512Flags flag);

    // Milan functions
    /**
     * @brief Returns true if CPU supports vector AES
     * @note  Will return true if either 256 or 512 bit vector AES is
     * supported
     *
     * @return true
     * @return false
     */
    bool cpuHasVaes();

    // Rome functions
    /**
     * @brief Returns true if CPU supports block AES instruction
     *
     * @return true
     * @return false
     */
    bool cpuHasAesni();
    /**
     * @brief Returns true if CPU supports block SHA instruction
     *
     * @return true
     * @return false
     */
    bool cpuHasShani();
    /**
     * @brief Returns true if CPU supports AVX2 instructions
     *
     * @return true
     * @return false
     */
    bool cpuHasAvx2();
    /**
     * @brief Returns true if CPU supports SSE3 instructions
     *
     * @return true
     * @return false
     */
    bool cpuHasSse3();
    /**
     * @brief Returns true if RDRAND, secure RNG number generator is
     * supported by CPU
     *
     * @return true
     * @return false
     */
    bool cpuHasRdRand();
    /**
     * @brief Returns true if RDSEED, secure RNG seed generator is supported
     * by CPU
     *
     * @return true
     * @return false
     */
    bool cpuHasRdSeed();
    /**
     * @brief Returns true if Adx is supported
     * by CPU
     *
     * @return true
     * @return false
     */
    bool cpuHasAdx();
    /**
     * @brief Returns true if BMI2 is supported
     * by CPU
     *
     * @return true
     * @return false
     */
    bool cpuHasBmi2();
    /**
     * @brief Returns true if currently executing cpu is Zen1
     *
     * @return true
     * @return false
     */
    bool cpuIsZen1();
    /**
     * @brief Returns true if currently executing cpu is Zen2
     *
     * @return true
     * @return false
     */
    bool cpuIsZen2();
    /**
     * @brief Returns true if currently executing cpu is Zen3
     *
     * @return true
     * @return false
     */
    bool cpuIsZen3();
    /**
     * @brief Returns true if currently executing cpu is Zen4
     *
     * @return true
     * @return false
     */
    bool cpuIsZen4();
    /**
     * @brief Returns true if currently executing cpu is Zen5
     *
     * @return true
     * @return false
     */
    bool cpuIsZen5();

    bool ensureCpuArch(CpuZenVer cpuZenVer);
};

CpuId::Impl::Impl()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
#ifdef ALCP_BUILD_OS_LINUX
    cpu_set_t current_mask = {};
    pid_t     tid          = gettid();
    int       result = sched_getaffinity(tid, sizeof(cpu_set_t), &current_mask);
    if (result != 0) {
        std::cout << "CPU AFFINITY FAILURE!" << std::endl;
    }

    // FIXME: There is a possible risk of not creating an object for cpu, but
    // highly unlikely
    for (int i = 0; i < CPU_SETSIZE; ++i) {
        if (CPU_ISSET(i, &current_mask)) {
            m_cpu = std::make_unique<X86Cpu>(i);
            break;
        }
    }

    result = sched_setaffinity(tid, sizeof(cpu_set_t), &current_mask);
    if (result != 0) {
        std::cout << "CPU AFFINITY FAILURE!" << std::endl;
    }
#else
    HANDLE hProcess = GetCurrentProcess();

    DWORD_PTR procAffinity, sysAffinity;
    if (!GetProcessAffinityMask(hProcess, &procAffinity, &sysAffinity))
        std::cout << "CPU AFFINITY FAILURE!" << std::endl;

    m_cpu = std::make_unique<X86Cpu>(0);

    bool result = SetProcessAffinityMask(hProcess, procAffinity);
    if (result == 0) {
        std::cout << "CPU AFFINITY FAILURE!" << std::endl;
    }
#endif
#endif

#ifndef ALCP_ENABLE_AOCL_UTILS
    std::fprintf(stderr,
                 "AOCL-Utils is unavailable at compile time! Defaulting to "
                 "ZEN2 dispatch!\n");
    std::fprintf(stderr,
                 "Check ALCP_ENABLE_AOCL_UTILS param at configure stage!"
                 "\n");
#endif
}

bool
CpuId::Impl::cpuHasAvx512f()
{
#ifdef ALCP_CPUID_DISABLE_AVX512
    return false;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512f);
#else
    static bool state = false;
#endif
    return state;
#endif
}

bool
CpuId::Impl::cpuHasAvx512dq()
{
#ifdef ALCP_CPUID_DISABLE_AVX512
    return false;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512dq);
#else
    static bool state = false;
#endif
    return state;
#endif
}

bool
CpuId::Impl::cpuHasAvx512bw()
{
#ifdef ALCP_CPUID_DISABLE_AVX512
    return false;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512bw);
#else
    static bool state = false;
#endif
    return state;
#endif
}

bool
CpuId::Impl::cpuHasAvx512(Avx512Flags flag)
{
#ifdef ALCP_CPUID_DISABLE_AVX512
    return false;
#else
    switch (flag) {
        case Avx512Flags::AVX512_DQ:
            return cpuHasAvx512dq();
        case Avx512Flags::AVX512_F:
            return cpuHasAvx512f();
        case Avx512Flags::AVX512_BW:
            return cpuHasAvx512bw();
        default:
            // FIXME: Raise an exception
            return false;
    }
#endif
}

bool
CpuId::Impl::cpuHasVaes()
{
#ifdef ALCP_CPUID_DISABLE_VAES
    return false;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::vaes);
#else
    static bool state = false;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuHasAesni()
{
#ifdef ALCP_CPUID_DISABLE_AESNI
    return false;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::aes);
#else
    static bool state = true;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuHasShani()
{
#ifdef ALCP_CPUID_DISABLE_SHANI
    return false;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::sha_ni);
#else
    static bool state = true;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuHasAvx2()
{
#ifdef ALCP_CPUID_DISABLE_AVX2
    return false;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx2);
#else
    static bool state = true;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuHasSse3()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::sse3);
#else
    static bool state = true;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuHasRdRand()
{
#ifdef ALCP_CPUID_DISABLE_RAND
    return false;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::rdrand);
#else
    static bool state = true;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuHasRdSeed()
{
#ifdef ALCP_CPUID_DISABLE_RAND
    return false;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::rdseed);
#else
    static bool state = true;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuHasAdx()
{
#ifdef ALCP_CPUID_DISABLE_ADX
    return false;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::adx);
#else
    static bool state = true;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuHasBmi2()
{
#ifdef ALCP_CPUID_DISABLE_BMI2
    return false;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::bmi2);
#else
    static bool state = true;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuIsZen1()
{
#if defined(ALCP_CPUID_FORCE)
    static bool flag = ensureCpuArch(CpuZenVer::ZEN);
    return flag;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->isUarch(EUarch::Zen);
#else
    static bool state = false;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuIsZen2()
{
#if defined(ALCP_CPUID_FORCE)
    static bool flag = ensureCpuArch(CpuZenVer::ZEN2);
    return flag;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->isUarch(EUarch::Zen2);
#else
    static bool state = true;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuIsZen3()
{
#if defined(ALCP_CPUID_FORCE)
    static bool flag = ensureCpuArch(CpuZenVer::ZEN3);
    return flag;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->isUarch(EUarch::Zen3);
#else
    static bool state = false;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuIsZen4()
{
#if defined(ALCP_CPUID_FORCE)
    static bool flag = ensureCpuArch(CpuZenVer::ZEN4);
    return flag;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->isUarch(EUarch::Zen4);
#else
    static bool state = false;
#endif
    return state;
#endif
}
bool
CpuId::Impl::cpuIsZen5()
{
#if defined(ALCP_CPUID_FORCE)
    static bool flag = ensureCpuArch(CpuZenVer::ZEN5);
    return flag;
#else
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->isUarch(EUarch::Zen5);
#else
    static bool state = false;
#endif
    return state;
#endif
}

bool
CpuId::Impl::ensureCpuArch(CpuZenVer cpuZenVer)
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    bool zen1_flag = Impl::m_cpu->isUarch(EUarch::Zen);
    bool zen2_flag = Impl::m_cpu->isUarch(EUarch::Zen2);
    bool zen3_flag = Impl::m_cpu->isUarch(EUarch::Zen3);
    bool zen4_flag = Impl::m_cpu->isUarch(EUarch::Zen4);
    bool zen5_flag = Impl::m_cpu->isUarch(EUarch::Zen5);
#else
    // Default dispatch is to Zen2
    // If this condition is setup, you can never force it to zen3 or zen4
    // We need cpuid to verify it can actually run on the machine
    bool zen1_flag = false;
    bool zen2_flag = true;
    bool zen3_flag = false;
    bool zen4_flag = false;
    bool zen5_flag = false;
#endif
#if defined(ALCP_CPUID_FORCE)
#if defined(ALCP_CPUID_FORCE_ZEN5)
    if (zen5_flag) {
        return (cpuZenVer == CpuZenVer::ZEN5);
    }
#elif defined(ALCP_CPUID_FORCE_ZEN4)
    if (zen4_flag || zen5_flag) {
        return (cpuZenVer == CpuZenVer::ZEN4);
    }
#elif defined(ALCP_CPUID_FORCE_ZEN3)
    if (zen3_flag || zen4_flag || zen5_flag) {
        return (cpuZenVer == CpuZenVer::ZEN3);
    }
#elif defined(ALCP_CPUID_FORCE_ZEN2)
    if (zen2_flag || zen3_flag || zen4_flag || zen5_flag) {
        return (cpuZenVer == CpuZenVer::ZEN2);
    }
#elif defined(ALCP_CPUID_FORCE_ZEN)
    if (zen1_flag || zen2_flag || zen3_flag || zen4_flag || zen5_flag) {
        return (cpuZenVer == CpuZenVer::ZEN);
    }
#else
    if (true) {
    }
#endif
    // Probably will never be used but if it comes to it.
    // This will trigger in case of an invalid cpuid force
    // Dispatch to highest possible cpu arch
    else {
        std::fprintf(stderr, "ZenVer upgrade cannot be done!\n");
        std::fprintf(stderr, "Finding best possible ZenVer!\n");
    }
#endif
    switch (cpuZenVer) {
        case CpuZenVer::ZEN5:
            return zen5_flag;

        case CpuZenVer::ZEN4:
            return zen4_flag;

        case CpuZenVer::ZEN3:
            return zen3_flag;

        case CpuZenVer::ZEN2:
            return zen2_flag;

        case CpuZenVer::ZEN:
            return zen1_flag;
    }
    return false;
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
CpuId::cpuHasSse3()
{
    return pImpl.get()->cpuHasSse3();
}

bool
CpuId::cpuHasAvx512(Avx512Flags flag)
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
CpuId::cpuHasBmi2()
{
    return pImpl.get()->cpuHasBmi2();
}

bool
CpuId::cpuHasAdx()
{
    return pImpl.get()->cpuHasAdx();
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

bool
CpuId::cpuIsZen5()
{
    return pImpl.get()->cpuIsZen5();
}

} // namespace alcp::utils