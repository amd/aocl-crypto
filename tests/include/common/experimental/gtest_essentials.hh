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
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace alcp::testing::utils {

enum class ParamType
{
    TYPE_STR  = 0,
    TYPE_BOOL = 1,
};

;
struct Param
{
    ParamType                       paramType;
    std::variant<std::string, bool> value;

    Param()
        : paramType{ ParamType::TYPE_BOOL }
        , value{ false }
    {}

    ~Param() = default;
};

using ArgsMap = std::map<std::string, Param>;

// FIXME: Enable verbosity later
ArgsMap
parseArgs(int argc, char** argv)
{
    std::string currentArg;
    std::string temp;

#if 0
    std::vector<std::string> verbosity_levels = { "0", "1", "2" };
#endif

    ArgsMap argsMap;

    argsMap["USE_IPP"].paramType       = ParamType::TYPE_BOOL;
    argsMap["USE_OSSL"].paramType      = ParamType::TYPE_BOOL;
    argsMap["USE_ALCP"].paramType      = ParamType::TYPE_BOOL;
    argsMap["OVERRIDE_ALCP"].paramType = ParamType::TYPE_BOOL;

    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            currentArg = std::string(argv[i]);
            if ((currentArg == std::string("--help"))
                || (currentArg == std::string("-h"))) {

#if 0
                std::string verbosity_string = "(";
                for (size_t j = 0; j < verbosity_levels.size() - 1; j++) {
                    verbosity_string += static_cast<char>(j) + '/';
                }
                verbosity_string +=
                    verbosity_levels.at(verbosity_levels.size() - 1) + ")";
#endif
                std::cout << std::endl
                          << "Additional help for microtests" << std::endl;
                std::cout << "--verbose or -v <space>  <verbosity level(0/1/2)>"
                          << std::endl;
                std::cout << "--use-ipp or -i force IPP use in testing."
                          << std::endl;
                std::cout << "--use-ossl or -o force OpenSSL use in testing"
                          << std::endl;
                std::cout << "--replay-blackbox or -r replay blackbox with "
                             "log file"
                          << std::endl;
            }
#if 0
            else if ((currentArg == std::string("--verbose"))
                       || (currentArg == std::string("-v"))) {
                /* now extract the verbose level integer */
                if (((currentArg.find(std::string("--verbose"))
                      != currentArg.npos)
                     || (currentArg.find(std::string("-v")) !=
                     currentArg.npos))
                    && (i + 1 < argc)) {
                    std::string nextArg = std::string(argv[i + 1]);
                    // Skip the next iteration
                    i++;
                    // check if the provided verbosity is supported
                    auto it = std::find(verbosity_levels.begin(),
                                        verbosity_levels.end(),
                                        nextArg);
                    if (it != verbosity_levels.end()) {
                        verbose = std::stoi(nextArg);
                    } else {
                        std::cout << RED << "Invalid Verbosity Level \""
                                  << nextArg << "\"" << RESET << std::endl;
                        exit(-1);
                    }
                }
            }
#endif
            else if ((currentArg == std::string("--use-ipp"))
                     || (currentArg == std::string("-i"))) {
                argsMap["USE_IPP"].value = true;
            } else if ((currentArg == std::string("--use-ossl"))
                       || (currentArg == std::string("-o"))) {
                argsMap["USE_OSSL"].value = true;

            } else if ((currentArg == std::string("--use-alcp"))
                       || (currentArg == std::string("-a"))) {
                argsMap["USE_ALCP"].value = true;

            } else if ((currentArg == std::string("--override-alcp"))
                       || (currentArg == std::string("-oa"))) {
                argsMap["OVERRIDE_ALCP"].value = true;
            }
        }
    }
    return argsMap;
}
} // namespace alcp::testing::utils