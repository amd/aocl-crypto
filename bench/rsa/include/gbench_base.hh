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
#pragma once

#include <iostream>

static int  verbose = 0;
static bool useipp  = false;
static bool useossl = false;
void
parseArgs(int* argc, char** argv)
{
    std::string currentArg;
    const int   _argc = *argc;
    if (*argc > 1) {
        for (int i = 1; i < _argc; i++) {
            currentArg = std::string(argv[i]);
            if ((currentArg == std::string("--help"))
                || (currentArg == std::string("-h"))) {
                std::cout << std::endl
                          << "Additional help for microbenches" << std::endl;
                std::cout << "Append these after gtest arguments only"
                          << std::endl;
                std::cout << "--verbose or -v per line status." << std::endl;
                std::cout << "--use-ipp or -i force IPP use in testing."
                          << std::endl;
            } else if ((currentArg == std::string("--verbose"))
                       || (currentArg == std::string("-v"))) {
                verbose = 1;
                *argc -= 1;
            } else if ((currentArg == std::string("--use-ipp"))
                       || (currentArg == std::string("-i"))) {
                useipp = true;
                *argc -= 1;
            } else if ((currentArg == std::string("--use-ossl"))
                       || (currentArg == std::string("-o"))) {
                useossl = true;
                *argc -= 1;
            }
        }
    }
}
