/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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
#include <iostream>
#include <string>
#ifdef ALCP_ENABLE_AOCL_UTILS
#include <Au/Cpuid/X86Cpu.hh>
#endif

using alcp::utils::Avx512Flags;
using alcp::utils::CpuId;

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define RESET "\033[0m"

void
printBoolMsg(const std::string& msg, bool val)
{
    if (val) {
        std::cout << GREEN;
    } else {
        std::cout << RED;
    }
    std::cout << "\t" << msg << ":";
    if (val) {
        std::cout << "YES";
    } else {
        std::cout << "NO";
    }
    std::cout << RESET << std::endl;
}

void
checkAVX512Support()
{
    std::cout << "======AVX512 FLAGS=======" << std::endl;
    printBoolMsg("AVX512F", CpuId::cpuHasAvx512f());
    printBoolMsg("AVX512BW", CpuId::cpuHasAvx512bw());
    printBoolMsg("AVX512DQ", CpuId::cpuHasAvx512dq());
    printBoolMsg("AVX512IFMA", CpuId::cpuHasAvx512ifma());
    printBoolMsg("AVX512VL", CpuId::cpuHasAvx512vl());
    printBoolMsg("AVX512_VP2INTERSECT",
                 CpuId::cpuHasAvx512VP2Intersect());
}

void
checkAVX2Support()
{
    std::cout << "======AVX2 FLAGS=======" << std::endl;
    printBoolMsg("AVX2", CpuId::cpuHasAvx2());
}

void
checkAESSupport()
{
    std::cout << "======AES FLAGS=======" << std::endl;
    printBoolMsg("AESNI", CpuId::cpuHasAesni());
    printBoolMsg("VAES", CpuId::cpuHasVaes());
}

void
checkSHASupport()
{
    std::cout << "======SHA FLAGS=======" << std::endl;
    printBoolMsg("SHANI", CpuId::cpuHasShani());
}

void
checkRandSupport()
{
    std::cout << "======Rand FLAGS=======" << std::endl;
    printBoolMsg("RDRAND", CpuId::cpuHasRdRand());
    printBoolMsg("RDSEED", CpuId::cpuHasRdSeed());
}

void
checkAdxSupport()
{
    std::cout << "======ADX FLAGS=======" << std::endl;
    printBoolMsg("ADX", CpuId::cpuHasAdx());
}

void
checkBmi2Support()
{
    std::cout << "======BMI FLAGS=======" << std::endl;
    printBoolMsg("BMI2", CpuId::cpuHasBmi2());
}

void
checkVendorAndMicroarch()
{
    std::cout << "======CPU VENDOR=======" << std::endl;
    printBoolMsg("AMD", CpuId::cpuIsAmd());

    std::cout << "======MICRO-ARCHITECTURE (AMD)=======" << std::endl;
#ifdef ALCP_ENABLE_AOCL_UTILS
    Au::X86Cpu cpu(0);
    for (int i = 1; i <= static_cast<int>(Au::EUarch::Max); i++) {
        Au::EUarch uarch = static_cast<Au::EUarch>(i);
        printBoolMsg(alcp::utils::EUarchValToString(i), cpu.isUarch(uarch));
    }
#else
    std::cout << "\t(AOCL-Utils unavailable at compile time)" << std::endl;
#endif

    std::cout << "======ISA FEATURE GROUPS=======" << std::endl;
    printBoolMsg("BASELINE (ADX+AVX2+BMI2)",
                 CpuId::cpuHasAdx() && CpuId::cpuHasAvx2()
                     && CpuId::cpuHasBmi2());
    printBoolMsg("AVX512_BASE (F+DQ+BW)", CpuId::cpuHasAvx512Base());
    printBoolMsg("AVX512_FULL (F+DQ+BW+IFMA+VL)",
                 CpuId::cpuHasAvx512(Avx512Flags::AVX512_F)
                     && CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ)
                     && CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW)
                     && CpuId::cpuHasAvx512(Avx512Flags::AVX512_IFMA)
                     && CpuId::cpuHasAvx512(Avx512Flags::AVX512_VL));
}

void
checkArchLevel()
{
    using alcp::utils::AlgorithmType;
    using alcp::utils::CpuArchLevel;
    using alcp::utils::CpuCapability;

    std::cout << "======DEFAULT ARCH LEVEL (Backward Compatible)======="
              << std::endl;
    CpuArchLevel defaultArch = CpuId::getCachedArchLevel();
    std::cout << "\tDefault: " << alcp::utils::CpuArchLevelToString(defaultArch) << std::endl;

    std::cout << "======PER-ALGORITHM ARCH LEVELS=======" << std::endl;
    std::cout << "\tCipher:   "
              << alcp::utils::CpuArchLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eCipher))
              << std::endl;
    std::cout << "\tRSA:      "
              << alcp::utils::CpuArchLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eRsa))
              << std::endl;
    std::cout << "\tPoly1305: "
              << alcp::utils::CpuArchLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::ePoly1305))
              << std::endl;
    std::cout << "\tX25519:   "
              << alcp::utils::CpuArchLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eX25519))
              << std::endl;
    std::cout << "\tSHA2-256: "
              << alcp::utils::CpuArchLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eSha2_256))
              << std::endl;
    std::cout << "\tSHA2-512: "
              << alcp::utils::CpuArchLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eSha2_512))
              << std::endl;
    std::cout << "\tSHA3:     "
              << alcp::utils::CpuArchLevelToString(
                     CpuId::getCachedArchLevel(AlgorithmType::eSha3))
              << std::endl;

    std::cout << "======SPECIAL CAPABILITIES=======" << std::endl;
    printBoolMsg("SHA-NI", CpuId::hasCapability(CpuCapability::eShaNi));
    printBoolMsg("RDRAND", CpuId::hasCapability(CpuCapability::eRdRand));
    printBoolMsg("RDSEED", CpuId::hasCapability(CpuCapability::eRdSeed));
}

int
main()
{
    checkArchLevel();
    checkVendorAndMicroarch();
    checkAESSupport();
    checkSHASupport();
    checkRandSupport();
    checkAVX2Support();
    checkAVX512Support();
    checkAdxSupport();
    checkBmi2Support();

    return 0;
}
