/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include "colors.hh"
#include <iostream>
#include <string>

static bool useipp  = false;
static bool useossl = false;
/*default blk size*/
static int block_size = 0;

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
                std::cout << "--use-ipp or -i for benching IPPCP" << std::endl;
                std::cout << "--use-ossl or -o for benching OpenSSL"
                          << std::endl;
                std::cout << "-b <Custom block size> for providing custom "
                             "input size to benchmark"
                          << std::endl;
                exit(-1);
            } else if ((currentArg == std::string("--blocksize"))
                       || (currentArg == std::string("-b"))) {
                /* now extract the verbose level integer */
                if (((currentArg.find(std::string("--blocksize"))
                      != currentArg.npos)
                     || (currentArg.find(std::string("-b")) != currentArg.npos))
                    && (i + 1 < _argc)) {
                    *argc -= 1;
                    std::string nextArg = std::string(argv[i + 1]);
                    // Skip the next iteration
                    i++;

                    try {
                        block_size = std::stoi(nextArg);
                        *argc -= 1;
                    } catch (const std::invalid_argument& e) {
                        std::cerr <<  RED << nextArg << " is not an integer or invalid block size."
                                  << RESET << std::endl;
                    }

                } else {
                   std::cerr << RED << "No block size provided"
                             << RESET << std::endl;
                   return;
                }
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
