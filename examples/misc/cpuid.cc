/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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
#include "colors.hh"
#include <iostream>

using alcp::utils::CpuId;

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
checkAMDSupport()
{
    std::cout << "======AMD FLAGS=======" << std::endl;
    printBoolMsg("ZEN1", CpuId::cpuIsZen1());
    printBoolMsg("ZEN2", CpuId::cpuIsZen2());
    printBoolMsg("ZEN3", CpuId::cpuIsZen3());
    printBoolMsg("ZEN4", CpuId::cpuIsZen4());
}

int
main()
{
    checkAMDSupport();
    checkAESSupport();
    checkSHASupport();
    checkRandSupport();
    checkAVX2Support();
    checkAVX512Support();

    return 0;
}