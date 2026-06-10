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

#pragma once

#include "alcp/alcp.hh"
#include "config.h"
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace alcp::utils {

/**
 * @brief Unified CPU architecture level for ISA-based dispatch
 *
 * Levels are defined by ISA feature sets and apply to any x86-64 CPU
 * (AMD or Intel) that supports the required instructions.  The names
 * use AMD Zen generations as shorthand because the library was first
 * optimized for those parts, but dispatch is purely ISA-driven.
 *
 * For cipher dispatch:
 *   - eReference: No SIMD optimizations
 *   - eZen: AESNI-based implementations
 *   - eZen3: VAES 256-bit implementations
 *   - eZen4: VAES 512-bit implementations
 */
enum class CpuArchLevel
{
    eReference = 0, // Fallback, no SIMD optimizations
    eZen       = 1, // ISA: ADX, AVX2, BMI2, AESNI, SSE3
    eZen3      = 2, // ISA: adds VAES (256-bit)
    eZen4      = 3, // ISA: adds AVX512 (F/DQ/BW/IFMA/VL), VAES512
    eZen5      = 4, // ISA: adds AVX512_VP2INTERSECT
    eDynamic   = 5, // Runtime dispatch (default)
};

inline const char*
CpuArchLevelToString(CpuArchLevel level)
{
    switch (level) {
        case CpuArchLevel::eZen5:
            return "Zen5";
        case CpuArchLevel::eZen4:
            return "Zen4";
        case CpuArchLevel::eZen3:
            return "Zen3";
        case CpuArchLevel::eZen:
            return "Zen/Zen2";
        case CpuArchLevel::eReference:
            return "Reference";
        case CpuArchLevel::eDynamic:
            return "Dynamic";
        default:
            return "Unknown";
    }
}

/**
 * @brief CPU capabilities that are orthogonal to architecture level
 *
 * Some features don't map cleanly to architecture levels (e.g., SHA-NI
 * is available on some Zen CPUs but not tied to Zen level). Use this
 * bitfield to check for specific capabilities.
 */
enum class CpuCapability : uint32_t
{
    eNone   = 0,
    eShaNi  = 1 << 0, // SHA-NI instructions (for SHA256)
    eRdRand = 1 << 1, // Hardware RNG (RDRAND)
    eRdSeed = 1 << 2, // Hardware RNG seed (RDSEED)
};

// Bitwise operators for CpuCapability
inline CpuCapability
operator|(CpuCapability a, CpuCapability b)
{
    return static_cast<CpuCapability>(static_cast<uint32_t>(a)
                                      | static_cast<uint32_t>(b));
}

inline CpuCapability
operator&(CpuCapability a, CpuCapability b)
{
    return static_cast<CpuCapability>(static_cast<uint32_t>(a)
                                      & static_cast<uint32_t>(b));
}

inline bool
hasCapability(CpuCapability caps, CpuCapability check)
{
    return (static_cast<uint32_t>(caps) & static_cast<uint32_t>(check)) != 0;
}

/**
 * @brief Algorithm type for per-algorithm CPU feature requirements
 *
 * Different algorithms have different CPU feature requirements for optimal
 * dispatch. Use this enum with getArchLevel() to get the appropriate
 * architecture level for a specific algorithm.
 *
 * Feature requirements per algorithm:
 *   - eCipher:   AESNI → VAES → VAES+AVX512
 *   - eRsa:      ADX+BMI2 → ADX+BMI2 → ADX+BMI2+IFMA
 *   - ePoly1305: Reference → AVX2 (radix-26) → AVX512-IFMA (radix-44)
 *   - eX25519:   ADX+BMI2+AVX2 → VAES → VAES
 *   - eSha2_256: SHA-NI based (orthogonal to arch level)
 *   - eSha2_512: AVX2+SSE3 → AVX256 → AVX512
 *   - eSha3:     AVX2 → AVX2+VAES → AVX512
 */
enum class AlgorithmType
{
    eCipher,   // AES modes: AESNI → VAES → VAES512
    eRsa,      // ADX+BMI2 → ADX+BMI2 → ADX+BMI2+IFMA
    ePoly1305, // Reference → AVX2 (radix-26) → AVX512-IFMA (radix-44)
    eX25519,   // ADX+BMI2+AVX2 → VAES → VAES
    eSha2_256, // SHA-NI based (orthogonal)
    eSha2_512, // AVX2+SSE3 → AVX256 → AVX512
    eSha3,     // AVX2 → AVX2+VAES → AVX512
    eDefault,  // Backward compatibility (current behavior)
};

// Number of algorithm types (excluding eDefault for caching)
constexpr int cNumAlgorithmTypes = static_cast<int>(AlgorithmType::eDefault);

enum class Avx512Flags
{
    AVX512_DQ = 1,
    AVX512_F,
    AVX512_BW,
    AVX512_IFMA,
    AVX512_VL,
};

/**
 * @brief Convert an EUarch enum integer value to a human-readable name.
 *
 * Uses the sequential enum layout of Au::EUarch:
 *   Unknown=0, Zen=1, ZenPlus=2, Zen2=3, Zen3=4, Zen4=5, Zen5=6, Zen6=7, ...
 * For values >= 3, the name follows "ZenN" where N = val - 1.
 * This auto-extends for future Zen generations without code changes.
 */
inline std::string
EUarchValToString(int val)
{
    if (val == 0)
        return "Unknown";
    if (val == 1)
        return "Zen";
    if (val == 2)
        return "Zen+";
    return "Zen" + std::to_string(val - 1);
}

class ALCP_API_EXPORT CpuId
{
  public:
    CpuId() {}
    ~CpuId() = default;

    /**
     * @brief Get the current CPU architecture level for a specific algorithm
     * @param algo The algorithm type to get architecture level for
     * @return CpuArchLevel enum value based on detected CPU features
     *
     * Different algorithms have different CPU feature requirements:
     *   - eCipher:   Requires AESNI/VAES/AVX512
     *   - eRsa:      Requires ADX+BMI2, IFMA for Zen4
     *   - ePoly1305: Reference / AVX2 (radix-26) / AVX512-IFMA (radix-44)
     *   - eX25519:   Requires ADX+BMI2+AVX2, VAES for Zen3+
     *   - eSha2_512: Requires AVX2/AVX256/AVX512
     *   - eSha3:     Requires AVX2/VAES/AVX512
     *   - eDefault:  Uses original blanket check (backward compatible)
     */
    static CpuArchLevel getArchLevel(
        AlgorithmType algo = AlgorithmType::eDefault);

    /**
     * @brief Get cached CPU architecture level for a specific algorithm
     * @param algo The algorithm type to get architecture level for
     * @return CpuArchLevel enum value (cached per algorithm type)
     */
    static CpuArchLevel getCachedArchLevel(
        AlgorithmType algo = AlgorithmType::eDefault);

    /**
     * @brief Get CPU capabilities bitfield
     * @return CpuCapability bitfield with available special features
     */
    static CpuCapability getCapabilities();

    /**
     * @brief Get cached CPU capabilities (initialized once)
     * @return CpuCapability bitfield
     */
    static CpuCapability getCachedCapabilities();

    /**
     * @brief Check if a specific capability is available
     * @param cap The capability to check
     * @return true if the capability is available
     */
    static bool hasCapability(CpuCapability cap);

    /**
     * @brief Get vector of all supported architecture levels (for testing)
     * @return Vector of CpuArchLevel from highest to lowest supported
     */
    static std::vector<CpuArchLevel> getSupportedArchLevels();

    // AVX512 flags
    static bool cpuHasAvx512f();
    static bool cpuHasAvx512dq();
    static bool cpuHasAvx512bw();
    static bool cpuHasAvx512ifma();
    static bool cpuHasAvx512vl();
    static bool cpuHasAvx512VP2Intersect();
    static bool cpuHasAvx512(Avx512Flags flag);

    // VAES/AESNI
    static bool cpuHasVaes();
    static bool cpuHasAesni();

    // SHA
    static bool cpuHasShani();

    // General SIMD
    static bool cpuHasAvx2();
    static bool cpuHasSse3();

    // RNG
    static bool cpuHasRdRand();
    static bool cpuHasRdSeed();

    // Integer operations
    static bool cpuHasAdx();
    static bool cpuHasBmi2();

    /**
     * @brief Returns true if CPU has AVX512 base features (F, DQ, BW)
     */
    static bool cpuHasAvx512Base();

    /**
     * @brief Returns true if CPU has AVX512 VL features (F, VL, BW)
     */
    static bool cpuHasAvx512VL();

    /**
     * @brief Returns true if the CPU vendor is AMD
     */
    static bool cpuIsAmd();

  private:
    class Impl;

  public:
    static std::unique_ptr<Impl> pImpl;
};

} // namespace alcp::utils
