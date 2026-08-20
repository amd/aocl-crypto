/*
 * Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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
#include <array>
#include <mutex>
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
    bool AlcpEnableInstructionSet         = false;
    bool cpuid_disable_avx512             = false;
    bool cpuid_disable_vaes               = false;
    bool cpuid_disable_avx512_vpintersect = false;

    std::string actual_cpu_arch    = "Unknown";
    bool        cpu_detection_done = false;

    bool get_alcp_enabled_instr();
    void detect_cpu_architecture();

    // Per-algorithm arch level computation (uses this-> instead of pImpl)
    CpuArchLevel computeArchLevelCipher();
    CpuArchLevel computeArchLevelRsa();
    CpuArchLevel computeArchLevelPoly1305();
    CpuArchLevel computeArchLevelX25519();
    CpuArchLevel computeArchLevelSha2_256();
    CpuArchLevel computeArchLevelSha2_512();
    CpuArchLevel computeArchLevelSha3();
    CpuArchLevel computeArchLevelDefault();
    CpuArchLevel computeArchLevel(AlgorithmType algo);

    // Low-level CPU feature detection
    bool cpuHasAvx512f();
    bool cpuHasAvx512dq();
    bool cpuHasAvx512bw();
    bool cpuHasAvx512ifma();
    bool cpuHasAvx512vl();
    bool cpuHasAvx512VP2Intersect();
    bool cpuHasAvx512(Avx512Flags flag);
    bool cpuHasVaes();
    bool cpuHasAesni();
    bool cpuHasShani();
    bool cpuHasAvx2();
    bool cpuHasSse3();
    bool cpuHasRdRand();
    bool cpuHasRdSeed();
    bool cpuHasAdx();
    bool cpuHasBmi2();

    // Vendor detection
    bool cpuIsAmd();
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

    // Find first available CPU from affinity mask
    for (int i = 0; i < CPU_SETSIZE; ++i) {
        if (CPU_ISSET(i, &current_mask)) {
            m_cpu = std::make_unique<X86Cpu>(i);
            break;
        }
    }

    // Fallback: if no CPU was found in affinity mask, use CPU 0
    // This can happen in containers or unusual scheduling configurations
    if (!m_cpu) {
        m_cpu = std::make_unique<X86Cpu>(0);
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
    /* detect cpu architecture */
    detect_cpu_architecture();

    /* read environment variable to force cpu arch */
    bool env_var_was_set = get_alcp_enabled_instr();

#ifndef ALCP_ENABLE_AOCL_UTILS
    std::fprintf(stderr,
                 "AOCL-Utils is unavailable at compile time! "
                 "Vendor/micro-arch detection disabled, defaulting to "
                 "AVX2 (eZen) ISA level.\n");
    std::fprintf(stderr,
                 "Check ALCP_ENABLE_AOCL_UTILS param at configure stage!\n");
#endif

    // Print per-algorithm kernel levels when AOCL_ENABLE_INSTRUCTION is set.
    // Safe to call computeArchLevel*() here since they use this-> (not pImpl).
    if (env_var_was_set) {
        std::fprintf(
            stderr,
            "Detected CPU=%s, Kernel levels: Cipher=%s, RSA=%s, Poly1305=%s, "
            "X25519=%s, SHA256=%s, SHA512=%s, SHA3=%s\n",
            actual_cpu_arch.c_str(),
            CpuArchLevelToString(computeArchLevelCipher()),
            CpuArchLevelToString(computeArchLevelRsa()),
            CpuArchLevelToString(computeArchLevelPoly1305()),
            CpuArchLevelToString(computeArchLevelX25519()),
            CpuArchLevelToString(computeArchLevelSha2_256()),
            CpuArchLevelToString(computeArchLevelSha2_512()),
            CpuArchLevelToString(computeArchLevelSha3()));
    }
}

/**
 * @brief Reads the environment variable `AOCL_ENABLE_INSTRUCTION` to determine
 * the enabled CPU instructions.
 *
 * Supported values: ZEN, ZEN1, ZEN2, ZEN3, ZEN4, ZEN5
 * - ZEN/ZEN1/ZEN2: Disables AVX512 and VAES (forces max Zen1/Zen2 level)
 * - ZEN3: Disables AVX512 (forces max Zen3 level with 256-bit VAES)
 * - ZEN4: Disables VP2INTERSECT (forces max Zen4 level)
 * - ZEN5: No effect (native CPU detection used)
 *
 * Note: Setting a higher level on a lower CPU has no effect - the actual
 * kernel level is determined by ISA feature detection, not this env var.
 * This env var can only DOWNGRADE.
 */
bool
CpuId::Impl::get_alcp_enabled_instr()
{
    const char* AOCL_Enable_Inst = std::getenv("AOCL_ENABLE_INSTRUCTION");

    if (AOCL_Enable_Inst == NULL) {
        AlcpEnableInstructionSet = true;
        return false;
    }

    if (strcmp(AOCL_Enable_Inst, "ZEN5") == 0) {
        std::fprintf(stderr,
                     "AOCL_ENABLE_INSTRUCTION=ZEN5: "
                     "Max kernel level set to ZEN5 (no features disabled)\n");
    } else if (strcmp(AOCL_Enable_Inst, "ZEN4") == 0) {
        cpuid_disable_avx512_vpintersect = true;
        std::fprintf(stderr,
                     "AOCL_ENABLE_INSTRUCTION=ZEN4: "
                     "Max kernel level set to ZEN4 (VP2INTERSECT disabled)\n");
    } else if (strcmp(AOCL_Enable_Inst, "ZEN3") == 0) {
        cpuid_disable_avx512_vpintersect = true;
        cpuid_disable_avx512             = true;
        std::fprintf(stderr,
                     "AOCL_ENABLE_INSTRUCTION=ZEN3: "
                     "Max kernel level set to ZEN3 (AVX512 disabled)\n");
    } else if (strcmp(AOCL_Enable_Inst, "ZEN2") == 0) {
        cpuid_disable_avx512_vpintersect = true;
        cpuid_disable_avx512             = true;
        cpuid_disable_vaes               = true;
        std::fprintf(stderr,
                     "AOCL_ENABLE_INSTRUCTION=ZEN2: "
                     "Max kernel level set to ZEN2 (AVX512, VAES disabled)\n");
    } else if ((strcmp(AOCL_Enable_Inst, "ZEN") == 0)
               || (strcmp(AOCL_Enable_Inst, "ZEN1") == 0)) {
        cpuid_disable_avx512_vpintersect = true;
        cpuid_disable_avx512             = true;
        cpuid_disable_vaes               = true;
        std::fprintf(stderr,
                     "AOCL_ENABLE_INSTRUCTION=%s: "
                     "Max kernel level set to ZEN1 (AVX512, VAES disabled)\n",
                     AOCL_Enable_Inst);
    } else {
        std::cerr << "Invalid option passed to environment variable "
                     "AOCL_ENABLE_INSTRUCTION "
                     "(Supported values: ZEN/ZEN1/ZEN2/ZEN3/ZEN4/ZEN5)"
                  << std::endl;
        std::exit(-1);
    }
    AlcpEnableInstructionSet = true;
    return true;
}

/**
 * @brief Detects and caches the CPU architecture once during initialization
 *
 * Uses AOCL-Utils getUarch() for accurate model-number-based detection.
 * The result is used only for debug logging (AOCL_ENABLE_INSTRUCTION).
 */
void
CpuId::Impl::detect_cpu_architecture()
{
    if (cpu_detection_done) {
        return; // Already detected
    }

#ifdef ALCP_ENABLE_AOCL_UTILS
    if (Impl::m_cpu->isAMD()) {
        int uarch_val   = static_cast<int>(Impl::m_cpu->getUarch());
        actual_cpu_arch = EUarchValToString(uarch_val);
    } else {
        actual_cpu_arch = "Unknown";
    }
#else
    actual_cpu_arch = "Unknown";
#endif

    cpu_detection_done = true;
}

bool
CpuId::Impl::cpuHasAvx512f()
{
    if (AlcpEnableInstructionSet && cpuid_disable_avx512) {
        return false;
    }
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512f);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512dq()
{
    if (AlcpEnableInstructionSet && cpuid_disable_avx512) {
        return false;
    }

#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512dq);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512bw()
{
    if (cpuid_disable_avx512) {
        return false;
    }
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512bw);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512ifma()
{
    if (cpuid_disable_avx512) {
        return false;
    }
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512ifma);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512vl()
{
    if (cpuid_disable_avx512) {
        return false;
    }
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512vl);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512VP2Intersect()
{
    if (cpuid_disable_avx512 || cpuid_disable_avx512_vpintersect) {
        return false;
    }
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx512_vpintersect);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx512(Avx512Flags flag)
{
    if (cpuid_disable_avx512) {
        return false;
    }
    switch (flag) {
        case Avx512Flags::AVX512_DQ:
            return cpuHasAvx512dq();
        case Avx512Flags::AVX512_F:
            return cpuHasAvx512f();
        case Avx512Flags::AVX512_BW:
            return cpuHasAvx512bw();
        case Avx512Flags::AVX512_IFMA:
            return cpuHasAvx512ifma();
        case Avx512Flags::AVX512_VL:
            return cpuHasAvx512vl();
        default:
            return false;
    }
}

bool
CpuId::Impl::cpuHasVaes()
{
    if (cpuid_disable_vaes) {
        return false;
    }
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::vaes);
#else
    static bool state = false;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAesni()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::aes);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasShani()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::sha_ni);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAvx2()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::avx2);
#else
    static bool state = true;
#endif
    return state;
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
}

bool
CpuId::Impl::cpuHasRdRand()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::rdrand);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasRdSeed()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::rdseed);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasAdx()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::adx);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuHasBmi2()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->hasFlag(ECpuidFlag::bmi2);
#else
    static bool state = true;
#endif
    return state;
}

bool
CpuId::Impl::cpuIsAmd()
{
#ifdef ALCP_ENABLE_AOCL_UTILS
    static bool state = Impl::m_cpu->isAMD();
#else
    // Default to true when AOCL_UTILS is not available (assumes AMD)
    static bool state = true;
#endif
    return state;
}

// Per-algorithm arch level computation (member functions using this->)

// Cipher (AES modes, ChaCha20): AESNI -> VAES -> VAES+AVX512
CpuArchLevel
CpuId::Impl::computeArchLevelCipher()
{
    // eZen4: AVX512 full + VAES (512-bit vectorized)
    if (cpuHasAvx512(Avx512Flags::AVX512_F)
        && cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && cpuHasAvx512(Avx512Flags::AVX512_BW)
        && cpuHasAvx512(Avx512Flags::AVX512_VL) && cpuHasVaes()) {
        return CpuArchLevel::eZen4;
    }
    // eZen3: VAES (256-bit vectorized) + AVX2
    if (cpuHasVaes() && cpuHasAvx2()) {
        return CpuArchLevel::eZen3;
    }
    // eZen: AESNI (128-bit) + AVX2
    if (cpuHasAesni() && cpuHasAvx2()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

// RSA: ADX+BMI2 -> ADX+BMI2 -> ADX+BMI2+IFMA
// RSA does NOT require VAES, only IFMA for Zen4 optimization
CpuArchLevel
CpuId::Impl::computeArchLevelRsa()
{
    // eZen4: ADX + AVX2 + BMI2 + IFMA (optimized modular multiplication)
    if (cpuHasAdx() && cpuHasAvx2() && cpuHasBmi2() && cpuHasAvx512ifma()) {
        return CpuArchLevel::eZen4;
    }
    // eZen3: ADX + AVX2 + BMI2 (same as eZen for RSA, but keeps hierarchy)
    if (cpuHasAdx() && cpuHasAvx2() && cpuHasBmi2()) {
        return CpuArchLevel::eZen3;
    }
    // eZen: ADX + AVX2 + BMI2
    if (cpuHasAdx() && cpuHasAvx2() && cpuHasBmi2()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

// Poly1305: Reference -> AVX2 (radix-26) -> AVX512-IFMA (radix-44).
// eZen3/eZen run the AVX2 radix-26 kernel; eZen4 runs the AVX-512 IFMA kernel.
CpuArchLevel
CpuId::Impl::computeArchLevelPoly1305()
{
    // eZen4: AVX512 F+DQ+BW+IFMA radix-44 kernel
    if (cpuHasAvx512(Avx512Flags::AVX512_F)
        && cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && cpuHasAvx512(Avx512Flags::AVX512_BW)
        && cpuHasAvx512(Avx512Flags::AVX512_IFMA)) {
        return CpuArchLevel::eZen4;
    }
    // eZen3: AVX2 radix-26 kernel. Gated on VAES (the Zen3 ISA differentiator)
    // so the -march=znver3 object it dispatches to only runs on Zen3+.
    if (cpuHasVaes() && cpuHasAvx2()) {
        return CpuArchLevel::eZen3;
    }
    // eZen: pre-Zen3 AVX2 parts. Still routed to the AVX2 kernel by the
    // dispatch; a portable (-mno-vaes) build for these parts is future work.
    if (cpuHasAvx2()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

// X25519 implementations:
//   eZen4: radix51bit (AVX512 F+DQ+BW+IFMA+VL) - NO ADX/BMI2
//   eZen3: radix64bit via x25519.cc.inc - requires ADX+BMI2
//   eZen:  radix64bit via x25519.cc.inc - requires ADX+BMI2
CpuArchLevel
CpuId::Impl::computeArchLevelX25519()
{
    // eZen4: AVX512 radix51bit implementation
    if (cpuHasAvx512(Avx512Flags::AVX512_F)
        && cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && cpuHasAvx512(Avx512Flags::AVX512_BW)
        && cpuHasAvx512(Avx512Flags::AVX512_IFMA)
        && cpuHasAvx512(Avx512Flags::AVX512_VL)) {
        return CpuArchLevel::eZen4;
    }
    // eZen3: radix64bit, requires ADX+BMI2+VAES
    if (cpuHasAdx() && cpuHasAvx2() && cpuHasBmi2() && cpuHasVaes()) {
        return CpuArchLevel::eZen3;
    }
    // eZen: radix64bit, requires ADX+BMI2
    if (cpuHasAdx() && cpuHasAvx2() && cpuHasBmi2()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

// SHA256: dispatch is orthogonal to architecture level.
// Primary path: SHA-NI (hardware acceleration).
// Fallback: Reference implementation (AVX2 fallback is disabled).
CpuArchLevel
CpuId::Impl::computeArchLevelSha2_256()
{
    if (cpuHasShani()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

// SHA512: AVX2+SSE3 -> AVX256 -> AVX512
// Uses AVX2/AVX512 intrinsics, NOT ADX/BMI2.
CpuArchLevel
CpuId::Impl::computeArchLevelSha2_512()
{
    // eZen4: AVX512 (F+DQ+BW+IFMA+VL)
    if (cpuHasAvx512(Avx512Flags::AVX512_F)
        && cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && cpuHasAvx512(Avx512Flags::AVX512_BW)
        && cpuHasAvx512(Avx512Flags::AVX512_IFMA)
        && cpuHasAvx512(Avx512Flags::AVX512_VL)) {
        return CpuArchLevel::eZen4;
    }
    // eZen3: AVX256 (zen3 kernel, VAES as differentiator)
    if (cpuHasVaes() && cpuHasAvx2()) {
        return CpuArchLevel::eZen3;
    }
    // eZen: AVX2 + SSE3
    if (cpuHasAvx2() && cpuHasSse3()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

// SHA3: AVX2 -> AVX2+VAES -> AVX512 -> AVX512+VP2INTERSECT
// Uses AVX2/AVX512 intrinsics, NOT ADX/BMI2.
CpuArchLevel
CpuId::Impl::computeArchLevelSha3()
{
    // eZen5: AVX512 + VP2INTERSECT (used for compiler-specific dispatch)
    if (cpuHasAvx512(Avx512Flags::AVX512_F)
        && cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && cpuHasAvx512(Avx512Flags::AVX512_BW)
        && cpuHasAvx512(Avx512Flags::AVX512_IFMA)
        && cpuHasAvx512(Avx512Flags::AVX512_VL)
        && cpuHasAvx512VP2Intersect()) {
        return CpuArchLevel::eZen5;
    }
    // eZen4: AVX512 (F+DQ+BW+IFMA+VL) without VP2INTERSECT
    if (cpuHasAvx512(Avx512Flags::AVX512_F)
        && cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && cpuHasAvx512(Avx512Flags::AVX512_BW)
        && cpuHasAvx512(Avx512Flags::AVX512_IFMA)
        && cpuHasAvx512(Avx512Flags::AVX512_VL)) {
        return CpuArchLevel::eZen4;
    }
    // eZen3: AVX2 + VAES (VAES as differentiator for eZen3 vs eZen)
    if (cpuHasVaes() && cpuHasAvx2()) {
        return CpuArchLevel::eZen3;
    }
    // eZen: AVX2
    if (cpuHasAvx2()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

// Default: original blanket check for backward compatibility
CpuArchLevel
CpuId::Impl::computeArchLevelDefault()
{
    // eZen4/eZen5: AVX512 full + VAES
    if (cpuHasAvx512(Avx512Flags::AVX512_F)
        && cpuHasAvx512(Avx512Flags::AVX512_DQ)
        && cpuHasAvx512(Avx512Flags::AVX512_BW)
        && cpuHasAvx512(Avx512Flags::AVX512_IFMA)
        && cpuHasAvx512(Avx512Flags::AVX512_VL) && cpuHasVaes()) {
        return CpuArchLevel::eZen4;
    }
    // eZen3: VAES (256-bit) + ADX + AVX2 + BMI2
    if (cpuHasVaes() && cpuHasAdx() && cpuHasAvx2() && cpuHasBmi2()) {
        return CpuArchLevel::eZen3;
    }
    // eZen: ADX + AVX2 + BMI2 + AESNI
    if (cpuHasAdx() && cpuHasAvx2() && cpuHasBmi2() && cpuHasAesni()) {
        return CpuArchLevel::eZen;
    }
    return CpuArchLevel::eReference;
}

CpuArchLevel
CpuId::Impl::computeArchLevel(AlgorithmType algo)
{
    switch (algo) {
        case AlgorithmType::eCipher:
            return computeArchLevelCipher();
        case AlgorithmType::eRsa:
            return computeArchLevelRsa();
        case AlgorithmType::ePoly1305:
            return computeArchLevelPoly1305();
        case AlgorithmType::eX25519:
            return computeArchLevelX25519();
        case AlgorithmType::eSha2_256:
            return computeArchLevelSha2_256();
        case AlgorithmType::eSha2_512:
            return computeArchLevelSha2_512();
        case AlgorithmType::eSha3:
            return computeArchLevelSha3();
        case AlgorithmType::eDefault:
        default:
            return computeArchLevelDefault();
    }
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
CpuId::cpuHasAvx512ifma()
{
    return pImpl.get()->cpuHasAvx512ifma();
}

bool
CpuId::cpuHasAvx512vl()
{
    return pImpl.get()->cpuHasAvx512vl();
}

bool
CpuId::cpuHasAvx512VP2Intersect()
{
    return pImpl.get()->cpuHasAvx512VP2Intersect();
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
CpuId::cpuIsAmd()
{
    return pImpl.get()->cpuIsAmd();
}

bool
CpuId::cpuHasAvx512Base()
{
    static bool s_avx512Base = cpuHasAvx512(Avx512Flags::AVX512_F)
                               && cpuHasAvx512(Avx512Flags::AVX512_DQ)
                               && cpuHasAvx512(Avx512Flags::AVX512_BW);
    return s_avx512Base;
}

bool
CpuId::cpuHasAvx512VL()
{
    static bool s_avx512VL = cpuHasAvx512(Avx512Flags::AVX512_F)
                             && cpuHasAvx512(Avx512Flags::AVX512_VL)
                             && cpuHasAvx512(Avx512Flags::AVX512_BW);
    return s_avx512VL;
}

// Per-algorithm architecture level detection
// Delegates to Impl member functions (which use this-> instead of pImpl)

CpuArchLevel
CpuId::getArchLevel(AlgorithmType algo)
{
    return pImpl->computeArchLevel(algo);
}

// Per-algorithm cached architecture levels
constexpr int kCacheSize = static_cast<int>(AlgorithmType::eDefault) + 1;
static std::array<CpuArchLevel, kCacheSize>   s_cachedArchLevels = {};
static std::array<std::once_flag, kCacheSize> s_initFlags        = {};

CpuArchLevel
CpuId::getCachedArchLevel(AlgorithmType algo)
{
    int idx = static_cast<int>(algo);
    // Ensure index is valid (eDefault maps to index 7)
    if (idx < 0 || idx >= kCacheSize) {
        idx = kCacheSize - 1; // Use default (index 7)
    }
    // This line guarantees that the initialization for s_cachedArchLevels[idx]
    // will only happen once for each algorithm, even if multiple threads or the
    // same process call this function multiple times. If the same process calls
    // this code repeatedly, only the first call will execute getArchLevel(algo)
    // and set s_cachedArchLevels[idx]. All subsequent calls for the same index
    // will skip the lambda, immediately returning the cached result, ensuring
    // both thread safety and cached efficiency.
    std::call_once(s_initFlags[idx], [idx, algo]() {
        s_cachedArchLevels[idx] = getArchLevel(algo);
    });

    return s_cachedArchLevels[idx];
}

CpuCapability
CpuId::getCapabilities()
{
    CpuCapability caps = CpuCapability::eNone;

    if (cpuHasShani()) {
        caps = caps | CpuCapability::eShaNi;
    }
    if (cpuHasRdRand()) {
        caps = caps | CpuCapability::eRdRand;
    }
    if (cpuHasRdSeed()) {
        caps = caps | CpuCapability::eRdSeed;
    }

    return caps;
}

CpuCapability
CpuId::getCachedCapabilities()
{
    static CpuCapability s_caps = getCapabilities();
    return s_caps;
}

bool
CpuId::hasCapability(CpuCapability cap)
{
    return alcp::utils::hasCapability(getCachedCapabilities(), cap);
}

std::vector<CpuArchLevel>
CpuId::getSupportedArchLevels()
{
    std::vector<CpuArchLevel> levels;
    CpuArchLevel              maxLevel = getCachedArchLevel();

    switch (maxLevel) {
        case CpuArchLevel::eZen5:
            levels.push_back(CpuArchLevel::eZen5);
            [[fallthrough]];
        case CpuArchLevel::eZen4:
            levels.push_back(CpuArchLevel::eZen4);
            [[fallthrough]];
        case CpuArchLevel::eZen3:
            levels.push_back(CpuArchLevel::eZen3);
            [[fallthrough]];
        case CpuArchLevel::eZen:
            levels.push_back(CpuArchLevel::eZen);
            break;
        default:
            levels.push_back(CpuArchLevel::eReference);
            break;
    }
    return levels;
}

} // namespace alcp::utils
