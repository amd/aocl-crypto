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

#include "gtest/gtest.h"

#include <iostream>
#include <string>

#ifdef ALCP_ENABLE_AOCL_UTILS
#include <Au/Cpuid/X86Cpu.hh>
#endif

namespace {
using alcp::utils::AlgorithmType;
using alcp::utils::Avx512Flags;
using alcp::utils::CpuArchLevel;
using alcp::utils::CpuCapability;
using alcp::utils::CpuId;

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define RESET "\033[0m"

void
RecordFeature(const char* name, bool val)
{
    ::testing::Test::RecordProperty(name, val ? "YES" : "NO");
    if (val) {
        std::cout << GREEN;
    } else {
        std::cout << RED;
    }
    std::cout << "\t" << name << ":" << (val ? "YES" : "NO") << RESET << std::endl;
}

void
ExpectValidArchLevel(const char* label, CpuArchLevel level)
{
    const char* str = alcp::utils::CpuArchLevelToString(level);
    SCOPED_TRACE(label);
    EXPECT_NE(std::string(str), "Unknown");
    ::testing::Test::RecordProperty(label, str);
    std::cout << "\t" << label << ": " << str << std::endl;
}

} // namespace

TEST(CpuIdDiagnostic, ArchLevels)
{
    std::cout << "======DEFAULT ARCH LEVEL (Backward Compatible)======="
              << std::endl;
    ExpectValidArchLevel("default", CpuId::getCachedArchLevel());

    std::cout << "======PER-ALGORITHM ARCH LEVELS=======" << std::endl;
    ExpectValidArchLevel("cipher", CpuId::getCachedArchLevel(AlgorithmType::eCipher));
    ExpectValidArchLevel("rsa", CpuId::getCachedArchLevel(AlgorithmType::eRsa));
    ExpectValidArchLevel("poly1305", CpuId::getCachedArchLevel(AlgorithmType::ePoly1305));
    ExpectValidArchLevel("x25519", CpuId::getCachedArchLevel(AlgorithmType::eX25519));
    ExpectValidArchLevel("sha2_256", CpuId::getCachedArchLevel(AlgorithmType::eSha2_256));
    ExpectValidArchLevel("sha2_512", CpuId::getCachedArchLevel(AlgorithmType::eSha2_512));
    ExpectValidArchLevel("sha3", CpuId::getCachedArchLevel(AlgorithmType::eSha3));

    std::cout << "======SPECIAL CAPABILITIES=======" << std::endl;
    RecordFeature("SHA-NI", CpuId::hasCapability(CpuCapability::eShaNi));
    RecordFeature("RDRAND", CpuId::hasCapability(CpuCapability::eRdRand));
    RecordFeature("RDSEED", CpuId::hasCapability(CpuCapability::eRdSeed));

    EXPECT_EQ(CpuId::hasCapability(CpuCapability::eShaNi), CpuId::cpuHasShani());
    EXPECT_EQ(CpuId::hasCapability(CpuCapability::eRdRand), CpuId::cpuHasRdRand());
    EXPECT_EQ(CpuId::hasCapability(CpuCapability::eRdSeed), CpuId::cpuHasRdSeed());
}

TEST(CpuIdDiagnostic, VendorAndMicroarch)
{
    std::cout << "======CPU VENDOR=======" << std::endl;
    RecordFeature("AMD", CpuId::cpuIsAmd());

    std::cout << "======MICRO-ARCHITECTURE (inclusive isUarch)=======" << std::endl;
#ifdef ALCP_ENABLE_AOCL_UTILS
    Au::X86Cpu cpu(0);
    for (int i = 1; i <= static_cast<int>(Au::EUarch::Max); i++) {
        Au::EUarch uarch = static_cast<Au::EUarch>(i);
        const std::string uarch_name = alcp::utils::EUarchValToString(i);
        RecordFeature(uarch_name.c_str(), cpu.isUarch(uarch));
    }
#else
    std::cout << "\t(AOCL-Utils unavailable at compile time)" << std::endl;
#endif

    std::cout << "======ISA FEATURE GROUPS=======" << std::endl;
    const bool baseline = CpuId::cpuHasAdx() && CpuId::cpuHasAvx2()
                          && CpuId::cpuHasBmi2();
    RecordFeature("BASELINE (ADX+AVX2+BMI2)", baseline);

    const bool avx512Base = CpuId::cpuHasAvx512(Avx512Flags::AVX512_F)
                            && CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ)
                            && CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW);
    RecordFeature("AVX512_BASE (F+DQ+BW)", CpuId::cpuHasAvx512Base());
    EXPECT_EQ(CpuId::cpuHasAvx512Base(), avx512Base);

    const bool avx512Full = CpuId::cpuHasAvx512(Avx512Flags::AVX512_F)
                            && CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ)
                            && CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW)
                            && CpuId::cpuHasAvx512(Avx512Flags::AVX512_IFMA)
                            && CpuId::cpuHasAvx512(Avx512Flags::AVX512_VL);
    RecordFeature("AVX512_FULL (F+DQ+BW+IFMA+VL)", avx512Full);
    if (avx512Full) {
        EXPECT_TRUE(CpuId::cpuHasAvx512Base());
    }
}

TEST(CpuIdDiagnostic, AesFlags)
{
    std::cout << "======AES FLAGS=======" << std::endl;
    RecordFeature("AESNI", CpuId::cpuHasAesni());
    RecordFeature("VAES", CpuId::cpuHasVaes());
    if (CpuId::cpuHasVaes()) {
        EXPECT_TRUE(CpuId::cpuHasAesni());
    }
}

TEST(CpuIdDiagnostic, ShaFlags)
{
    std::cout << "======SHA FLAGS=======" << std::endl;
    RecordFeature("SHANI", CpuId::cpuHasShani());
    EXPECT_EQ(CpuId::cpuHasShani(), CpuId::hasCapability(CpuCapability::eShaNi));
}

TEST(CpuIdDiagnostic, RandFlags)
{
    std::cout << "======Rand FLAGS=======" << std::endl;
    RecordFeature("RDRAND", CpuId::cpuHasRdRand());
    RecordFeature("RDSEED", CpuId::cpuHasRdSeed());
    EXPECT_EQ(CpuId::cpuHasRdRand(), CpuId::hasCapability(CpuCapability::eRdRand));
    EXPECT_EQ(CpuId::cpuHasRdSeed(), CpuId::hasCapability(CpuCapability::eRdSeed));
    if (CpuId::cpuHasRdSeed()) {
        EXPECT_TRUE(CpuId::cpuHasRdRand());
    }
}

TEST(CpuIdDiagnostic, Avx2Flags)
{
    std::cout << "======AVX2 FLAGS=======" << std::endl;
    RecordFeature("AVX2", CpuId::cpuHasAvx2());
}

TEST(CpuIdDiagnostic, Avx512Flags)
{
    std::cout << "======AVX512 FLAGS=======" << std::endl;
    RecordFeature("AVX512F", CpuId::cpuHasAvx512f());
    RecordFeature("AVX512BW", CpuId::cpuHasAvx512bw());
    RecordFeature("AVX512DQ", CpuId::cpuHasAvx512dq());
    RecordFeature("AVX512IFMA", CpuId::cpuHasAvx512ifma());
    RecordFeature("AVX512VL", CpuId::cpuHasAvx512vl());
    RecordFeature("AVX512_VP2INTERSECT", CpuId::cpuHasAvx512VP2Intersect());

    EXPECT_EQ(CpuId::cpuHasAvx512f(), CpuId::cpuHasAvx512(Avx512Flags::AVX512_F));
    EXPECT_EQ(CpuId::cpuHasAvx512dq(), CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ));
    EXPECT_EQ(CpuId::cpuHasAvx512bw(), CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW));
    EXPECT_EQ(CpuId::cpuHasAvx512ifma(),
              CpuId::cpuHasAvx512(Avx512Flags::AVX512_IFMA));
    EXPECT_EQ(CpuId::cpuHasAvx512vl(), CpuId::cpuHasAvx512(Avx512Flags::AVX512_VL));
}

TEST(CpuIdDiagnostic, AdxFlags)
{
    std::cout << "======ADX FLAGS=======" << std::endl;
    RecordFeature("ADX", CpuId::cpuHasAdx());
}

TEST(CpuIdDiagnostic, BmiFlags)
{
    std::cout << "======BMI FLAGS=======" << std::endl;
    RecordFeature("BMI2", CpuId::cpuHasBmi2());
}

int
main(int argc, char** argv)
{
    try {
        ::testing::InitGoogleTest(&argc, argv);
        return RUN_ALL_TESTS();
    } catch (const std::exception& e) {
        std::cerr << "Unhandled exception: " << e.what() << std::endl;
        return 1;
    } catch (const char* e) {
        std::cerr << "Unhandled exception: " << e << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown exception caught" << std::endl;
        return 1;
    }
}
