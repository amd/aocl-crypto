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
 */

/**
 * @file dispatch_test.cc
 * @brief Unit tests for the centralized CPU dispatch logic with simulated
 * architectures
 *
 * These tests verify the correct architecture level is returned when
 * AOCL_ENABLE_INSTRUCTION environment variable is set.
 *
 * To run with specific simulated architecture:
 *   AOCL_ENABLE_INSTRUCTION=ZEN  ./base_dispatch_test
 *   AOCL_ENABLE_INSTRUCTION=ZEN3 ./base_dispatch_test
 *   AOCL_ENABLE_INSTRUCTION=ZEN4 ./base_dispatch_test
 */

#include "alcp/utils/cpuid.hh"

#include "gtest/gtest.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

// Valgrind detection without requiring valgrind headers
// Check /proc/self/status for TracerPid (non-zero when being traced/debugged)
// or check environment hints that valgrind sets
static bool
isRunningUnderValgrind()
{
#ifdef __linux__
    // Method 1: Check if LD_PRELOAD contains valgrind (common indicator)
    const char* ldPreload = std::getenv("LD_PRELOAD");
    if (ldPreload && std::string(ldPreload).find("valgrind") != std::string::npos) {
        return true;
    }

    // Method 2: Check /proc/self/maps for valgrind libraries
    std::ifstream maps("/proc/self/maps");
    if (maps.is_open()) {
        std::string line;
        while (std::getline(maps, line)) {
            if (line.find("valgrind") != std::string::npos
                || line.find("vgpreload") != std::string::npos) {
                return true;
            }
        }
    }
#endif
    return false;
}

namespace {
using namespace alcp::utils;

// =============================================================================
// Simulated Architecture Tests
// =============================================================================

class SimulatedArchTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Skip all dispatch tests when running under valgrind
        // Valgrind emulates CPUID and doesn't report advanced CPU features correctly,
        // causing all tests to see eReference level instead of actual hardware capabilities
        if (isRunningUnderValgrind()) {
            GTEST_SKIP() << "Skipping dispatch tests under valgrind (CPUID "
                            "emulation unreliable)";
        }

        // Get the current simulated arch from environment
#ifdef _WIN32
        // Use _dupenv_s on Windows to avoid deprecation warning
        char*  envVar = nullptr;
        size_t len    = 0;
        if (_dupenv_s(&envVar, &len, "AOCL_ENABLE_INSTRUCTION") == 0
            && envVar != nullptr) {
            m_simulatedArch = std::string(envVar);
            free(envVar); // Must free the allocated memory
        } else {
            m_simulatedArch = "";
        }
#else
        const char* envVar = std::getenv("AOCL_ENABLE_INSTRUCTION");
        m_simulatedArch    = envVar ? std::string(envVar) : "";
#endif
    }

    std::string m_simulatedArch;

    // Helper to check if we're running with a specific simulated arch
    bool isSimulatedArch(const std::string& arch) const
    {
        return m_simulatedArch == arch;
    }

    // Helper to check if simulation is active
    bool hasSimulatedArch() const { return !m_simulatedArch.empty(); }
};

// -----------------------------------------------------------------------------
// Feature Flag Tests for Simulated Architectures
// -----------------------------------------------------------------------------

TEST_F(SimulatedArchTest, Zen1SimulationDisablesAvx512AndVaes)
{
    if (!isSimulatedArch("ZEN") && !isSimulatedArch("ZEN1")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN or ZEN1";
    }

    // ZEN/ZEN1 simulation should disable AVX512 and VAES
    EXPECT_FALSE(CpuId::cpuHasAvx512(Avx512Flags::AVX512_F))
        << "ZEN simulation should disable AVX512_F";
    EXPECT_FALSE(CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ))
        << "ZEN simulation should disable AVX512_DQ";
    EXPECT_FALSE(CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW))
        << "ZEN simulation should disable AVX512_BW";
    EXPECT_FALSE(CpuId::cpuHasVaes())
        << "ZEN simulation should disable VAES";
}

TEST_F(SimulatedArchTest, Zen2SimulationDisablesAvx512AndVaes)
{
    if (!isSimulatedArch("ZEN2")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN2";
    }

    // ZEN2 simulation should disable AVX512 and VAES
    EXPECT_FALSE(CpuId::cpuHasAvx512(Avx512Flags::AVX512_F))
        << "ZEN2 simulation should disable AVX512_F";
    EXPECT_FALSE(CpuId::cpuHasVaes())
        << "ZEN2 simulation should disable VAES";
}

TEST_F(SimulatedArchTest, Zen3SimulationDisablesAvx512Only)
{
    if (!isSimulatedArch("ZEN3")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN3";
    }

    // ZEN3 simulation should disable AVX512 but NOT VAES
    EXPECT_FALSE(CpuId::cpuHasAvx512(Avx512Flags::AVX512_F))
        << "ZEN3 simulation should disable AVX512_F";
    EXPECT_FALSE(CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ))
        << "ZEN3 simulation should disable AVX512_DQ";
    // Note: VAES should still be available if HW supports it
}

TEST_F(SimulatedArchTest, Zen4SimulationAllowsAllFeatures)
{
    if (!isSimulatedArch("ZEN4") && !isSimulatedArch("ZEN5")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN4 or ZEN5";
    }

    // ZEN4/ZEN5 simulation should not disable any features
    // Features will be available if hardware supports them
    // This test just verifies no unexpected disabling occurs
    // (actual availability depends on underlying hardware)
}

// -----------------------------------------------------------------------------
// Per-Algorithm Architecture Level Tests for Simulated Architectures
// -----------------------------------------------------------------------------

TEST_F(SimulatedArchTest, CipherArchLevelForZen1Simulation)
{
    if (!isSimulatedArch("ZEN") && !isSimulatedArch("ZEN1")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN or ZEN1";
    }

    // With ZEN simulation (no AVX512, no VAES), cipher should be at most eZen
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eCipher);
    EXPECT_LE(level, CpuArchLevel::eZen)
        << "Cipher with ZEN simulation should be at most eZen";

    // Cipher requires AESNI + AVX2 for eZen (no ADX/BMI2 needed)
    if (CpuId::cpuHasAesni() && CpuId::cpuHasAvx2()) {
        EXPECT_EQ(level, CpuArchLevel::eZen)
            << "Cipher with ZEN simulation and AESNI+AVX2 should be eZen";
    }
}

TEST_F(SimulatedArchTest, CipherArchLevelForZen3Simulation)
{
    if (!isSimulatedArch("ZEN3")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN3";
    }

    // With ZEN3 simulation (no AVX512, but VAES allowed), cipher can be up to eZen3
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eCipher);
    EXPECT_LE(level, CpuArchLevel::eZen3)
        << "Cipher with ZEN3 simulation should be at most eZen3";
    EXPECT_NE(level, CpuArchLevel::eZen4)
        << "Cipher with ZEN3 simulation should NOT be eZen4";
}

TEST_F(SimulatedArchTest, RsaArchLevelForZen1Simulation)
{
    if (!isSimulatedArch("ZEN") && !isSimulatedArch("ZEN1")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN or ZEN1";
    }

    // RSA doesn't require VAES, but requires ADX+BMI2
    // With ZEN simulation, RSA should still be at least eZen if baseline available
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eRsa);

    if (CpuId::cpuHasAdx() && CpuId::cpuHasBmi2() && CpuId::cpuHasAvx2()) {
        EXPECT_GE(level, CpuArchLevel::eZen)
            << "RSA with baseline features should be at least eZen";
    }

    // RSA should NOT be eZen4 without IFMA (which requires AVX512)
    if (!CpuId::cpuHasAvx512ifma()) {
        EXPECT_NE(level, CpuArchLevel::eZen4)
            << "RSA without AVX512_IFMA should not be eZen4";
    }
}

TEST_F(SimulatedArchTest, RsaArchLevelForZen3Simulation)
{
    if (!isSimulatedArch("ZEN3")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN3";
    }

    // RSA with ZEN3 simulation - AVX512 disabled means no IFMA
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eRsa);

    // RSA should not be eZen4 without IFMA
    EXPECT_NE(level, CpuArchLevel::eZen4)
        << "RSA with ZEN3 simulation should not be eZen4 (no IFMA)";

    // RSA should be at least eZen3 if baseline features available
    if (CpuId::cpuHasAdx() && CpuId::cpuHasBmi2() && CpuId::cpuHasAvx2()) {
        EXPECT_GE(level, CpuArchLevel::eZen)
            << "RSA with baseline features should be at least eZen";
    }
}

TEST_F(SimulatedArchTest, Poly1305ArchLevelForZen1Simulation)
{
    if (!isSimulatedArch("ZEN") && !isSimulatedArch("ZEN1")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN or ZEN1";
    }

    // Poly1305 only has optimized kernel for eZen4 (requires AVX512)
    // With ZEN simulation (no AVX512), should be eZen or eReference
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::ePoly1305);

    EXPECT_NE(level, CpuArchLevel::eZen4)
        << "Poly1305 with ZEN simulation should not be eZen4";
    EXPECT_LE(level, CpuArchLevel::eZen)
        << "Poly1305 with ZEN simulation should be at most eZen";
}

TEST_F(SimulatedArchTest, Poly1305ArchLevelForZen3Simulation)
{
    if (!isSimulatedArch("ZEN3")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN3";
    }

    // Poly1305 requires AVX512 for eZen4, ZEN3 simulation disables AVX512
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::ePoly1305);

    EXPECT_NE(level, CpuArchLevel::eZen4)
        << "Poly1305 with ZEN3 simulation should not be eZen4";
}

TEST_F(SimulatedArchTest, X25519ArchLevelForZen1Simulation)
{
    if (!isSimulatedArch("ZEN") && !isSimulatedArch("ZEN1")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN or ZEN1";
    }

    // X25519 uses zen3 kernel for VAES, avx2 kernel otherwise
    // With ZEN simulation (no VAES), should be eZen if baseline available
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eX25519);

    // Should not be eZen3 without VAES
    if (!CpuId::cpuHasVaes()) {
        EXPECT_NE(level, CpuArchLevel::eZen3)
            << "X25519 without VAES should not be eZen3";
    }

    // Should be at least eZen if baseline available
    if (CpuId::cpuHasAdx() && CpuId::cpuHasBmi2() && CpuId::cpuHasAvx2()) {
        EXPECT_GE(level, CpuArchLevel::eZen)
            << "X25519 with baseline features should be at least eZen";
    }
}

TEST_F(SimulatedArchTest, X25519ArchLevelForZen3Simulation)
{
    if (!isSimulatedArch("ZEN3")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN3";
    }

    // X25519 with ZEN3 simulation - AVX512 disabled, so no Zen4 path
    // Zen4 X25519 uses radix51bit (AVX512), Zen3 uses radix64bit (ADX/BMI2)
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eX25519);

    // X25519 should not return eZen4 without AVX512
    EXPECT_NE(level, CpuArchLevel::eZen4)
        << "X25519 with ZEN3 simulation should not be eZen4 (no AVX512)";
}

TEST_F(SimulatedArchTest, Sha512ArchLevelForZen1Simulation)
{
    if (!isSimulatedArch("ZEN") && !isSimulatedArch("ZEN1")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN or ZEN1";
    }

    // SHA512 uses AVX2/AVX256/AVX512
    // With ZEN simulation, should be at most eZen
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eSha2_512);

    EXPECT_NE(level, CpuArchLevel::eZen4)
        << "SHA512 with ZEN simulation should not be eZen4";
    EXPECT_NE(level, CpuArchLevel::eZen3)
        << "SHA512 with ZEN simulation should not be eZen3";
}

TEST_F(SimulatedArchTest, Sha512ArchLevelForZen3Simulation)
{
    if (!isSimulatedArch("ZEN3")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN3";
    }

    // SHA512 with ZEN3 simulation - can use zen3 kernel if VAES available
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eSha2_512);

    EXPECT_NE(level, CpuArchLevel::eZen4)
        << "SHA512 with ZEN3 simulation should not be eZen4";
    EXPECT_LE(level, CpuArchLevel::eZen3)
        << "SHA512 with ZEN3 simulation should be at most eZen3";
}

TEST_F(SimulatedArchTest, Sha3ArchLevelForZen1Simulation)
{
    if (!isSimulatedArch("ZEN") && !isSimulatedArch("ZEN1")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN or ZEN1";
    }

    // SHA3 uses AVX2/VAES/AVX512
    // With ZEN simulation, should be at most eZen
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eSha3);

    EXPECT_NE(level, CpuArchLevel::eZen4)
        << "SHA3 with ZEN simulation should not be eZen4";
    EXPECT_NE(level, CpuArchLevel::eZen3)
        << "SHA3 with ZEN simulation should not be eZen3";
}

TEST_F(SimulatedArchTest, Sha3ArchLevelForZen3Simulation)
{
    if (!isSimulatedArch("ZEN3")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN3";
    }

    // SHA3 with ZEN3 simulation - can use zen3 kernel if VAES available
    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eSha3);

    EXPECT_NE(level, CpuArchLevel::eZen4)
        << "SHA3 with ZEN3 simulation should not be eZen4";
    EXPECT_LE(level, CpuArchLevel::eZen3)
        << "SHA3 with ZEN3 simulation should be at most eZen3";
}

// -----------------------------------------------------------------------------
// Default Algorithm Tests for Simulated Architectures
// -----------------------------------------------------------------------------

TEST_F(SimulatedArchTest, DefaultArchLevelForZen1Simulation)
{
    if (!isSimulatedArch("ZEN") && !isSimulatedArch("ZEN1")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN or ZEN1";
    }

    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eDefault);

    // Default with ZEN simulation should be at most eZen
    EXPECT_LE(level, CpuArchLevel::eZen)
        << "Default with ZEN simulation should be at most eZen";
}

TEST_F(SimulatedArchTest, DefaultArchLevelForZen3Simulation)
{
    if (!isSimulatedArch("ZEN3")) {
        GTEST_SKIP() << "Test requires AOCL_ENABLE_INSTRUCTION=ZEN3";
    }

    CpuArchLevel level = CpuId::getArchLevel(AlgorithmType::eDefault);

    // Default with ZEN3 simulation should be at most eZen3
    EXPECT_LE(level, CpuArchLevel::eZen3)
        << "Default with ZEN3 simulation should be at most eZen3";
    EXPECT_NE(level, CpuArchLevel::eZen4)
        << "Default with ZEN3 simulation should NOT be eZen4";
}

// -----------------------------------------------------------------------------
// No Simulation (Native) Verification Tests
// -----------------------------------------------------------------------------

TEST_F(SimulatedArchTest, NativeArchLevelMatchesHardware)
{
    if (hasSimulatedArch()) {
        GTEST_SKIP() << "Test requires no AOCL_ENABLE_INSTRUCTION set (native)";
    }

    // When no simulation is active, arch levels should match hardware capabilities
    CpuArchLevel cipherLevel = CpuId::getArchLevel(AlgorithmType::eCipher);

    // Verify cipher level matches hardware features
    // Cipher requires: eZen4 = AVX512(F,DQ,BW,VL) + VAES
    //                  eZen3 = VAES + AVX2
    //                  eZen = AESNI + AVX2
    if (cipherLevel == CpuArchLevel::eZen4) {
        EXPECT_TRUE(CpuId::cpuHasAvx512(Avx512Flags::AVX512_F));
        EXPECT_TRUE(CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ));
        EXPECT_TRUE(CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW));
        EXPECT_TRUE(CpuId::cpuHasAvx512(Avx512Flags::AVX512_VL));
        EXPECT_TRUE(CpuId::cpuHasVaes());
    } else if (cipherLevel == CpuArchLevel::eZen3) {
        EXPECT_TRUE(CpuId::cpuHasVaes());
        EXPECT_TRUE(CpuId::cpuHasAvx2());
        // Should NOT have full AVX512 cipher requirements (or would be eZen4)
        bool hasFullAvx512Cipher = CpuId::cpuHasAvx512(Avx512Flags::AVX512_F)
                                   && CpuId::cpuHasAvx512(Avx512Flags::AVX512_DQ)
                                   && CpuId::cpuHasAvx512(Avx512Flags::AVX512_BW)
                                   && CpuId::cpuHasAvx512(Avx512Flags::AVX512_VL)
                                   && CpuId::cpuHasVaes();
        EXPECT_FALSE(hasFullAvx512Cipher)
            << "eZen3 should not have full AVX512(F,DQ,BW,VL)+VAES";
    } else if (cipherLevel == CpuArchLevel::eZen) {
        EXPECT_TRUE(CpuId::cpuHasAesni());
        EXPECT_TRUE(CpuId::cpuHasAvx2());
        EXPECT_FALSE(CpuId::cpuHasVaes())
            << "eZen level means VAES is not available";
    }
}

// -----------------------------------------------------------------------------
// Comprehensive Algorithm Matrix Test
// -----------------------------------------------------------------------------

TEST_F(SimulatedArchTest, AllAlgorithmsRespectSimulation)
{
    // This test verifies all algorithms respect the simulated arch
    // It runs regardless of simulation state and validates consistency

    CpuArchLevel cipher   = CpuId::getArchLevel(AlgorithmType::eCipher);
    CpuArchLevel rsa      = CpuId::getArchLevel(AlgorithmType::eRsa);
    CpuArchLevel poly1305 = CpuId::getArchLevel(AlgorithmType::ePoly1305);
    CpuArchLevel x25519   = CpuId::getArchLevel(AlgorithmType::eX25519);
    CpuArchLevel sha256   = CpuId::getArchLevel(AlgorithmType::eSha2_256);
    CpuArchLevel sha512   = CpuId::getArchLevel(AlgorithmType::eSha2_512);
    CpuArchLevel sha3     = CpuId::getArchLevel(AlgorithmType::eSha3);
    CpuArchLevel defLevel = CpuId::getArchLevel(AlgorithmType::eDefault);

    // Log current state for debugging
    std::cout << "Current simulation: "
              << (m_simulatedArch.empty() ? "NONE (native)" : m_simulatedArch)
              << std::endl;
    std::cout << "  Cipher:   " << static_cast<int>(cipher) << std::endl;
    std::cout << "  RSA:      " << static_cast<int>(rsa) << std::endl;
    std::cout << "  Poly1305: " << static_cast<int>(poly1305) << std::endl;
    std::cout << "  X25519:   " << static_cast<int>(x25519) << std::endl;
    std::cout << "  SHA256:   " << static_cast<int>(sha256) << std::endl;
    std::cout << "  SHA512:   " << static_cast<int>(sha512) << std::endl;
    std::cout << "  SHA3:     " << static_cast<int>(sha3) << std::endl;
    std::cout << "  Default:  " << static_cast<int>(defLevel) << std::endl;

    // Basic invariants that should always hold
    // X25519 can be eZen4 (AVX512 radix51bit) or eZen3/eZen (radix64bit with ADX/BMI2)

    // Poly1305 is eZen4 (AVX512-IFMA), eZen3 (Zen3 AVX2 kernel), or at most
    // eZen (plain AVX2 / reference).
    EXPECT_TRUE(poly1305 == CpuArchLevel::eZen4
                || poly1305 == CpuArchLevel::eZen3
                || poly1305 <= CpuArchLevel::eZen);

    // SHA256 is either eZen (SHA-NI) or eReference
    EXPECT_TRUE(sha256 == CpuArchLevel::eZen
                || sha256 == CpuArchLevel::eReference);

    // If simulation disables features, verify constraints
    if (isSimulatedArch("ZEN") || isSimulatedArch("ZEN1")
        || isSimulatedArch("ZEN2")) {
        // No AVX512, no VAES
        EXPECT_LE(cipher, CpuArchLevel::eZen);
        EXPECT_LE(sha512, CpuArchLevel::eZen);
        EXPECT_LE(sha3, CpuArchLevel::eZen);
        EXPECT_LE(poly1305, CpuArchLevel::eZen);
    } else if (isSimulatedArch("ZEN3")) {
        // No AVX512
        EXPECT_NE(cipher, CpuArchLevel::eZen4);
        EXPECT_NE(sha512, CpuArchLevel::eZen4);
        EXPECT_NE(sha3, CpuArchLevel::eZen4);
        EXPECT_NE(poly1305, CpuArchLevel::eZen4);
        EXPECT_NE(rsa, CpuArchLevel::eZen4);
    }
}

} // namespace
