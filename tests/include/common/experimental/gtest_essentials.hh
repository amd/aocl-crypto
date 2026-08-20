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
#pragma once

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "parse_args.hh"

namespace alcp::testing::utils {

inline int      block_size     = 0;
inline bool     seed_set       = false;
inline uint64_t seed_override  = 0;

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
    {
    }

    ~Param() = default;
};

using ArgsMap = std::map<std::string, Param>;

ArgsMap
parseTestArgs(int* argc, char** argv)
{
    ArgsMap argsMap;

    argsMap["USE_IPP"].paramType       = ParamType::TYPE_BOOL;
    argsMap["USE_OSSL"].paramType      = ParamType::TYPE_BOOL;
    argsMap["USE_ALCP"].paramType      = ParamType::TYPE_BOOL;
    argsMap["OVERRIDE_ALCP"].paramType = ParamType::TYPE_BOOL;

    alcp::bench::args::ParsedArgs parsed;
    alcp::bench::args::strip_custom_args(argc, argv, parsed);

    argsMap["USE_IPP"].value       = parsed.use_ipp;
    argsMap["USE_OSSL"].value      = parsed.use_ossl;
    argsMap["USE_ALCP"].value      = parsed.use_alcp;
    argsMap["OVERRIDE_ALCP"].value = parsed.override_alcp;

    if (parsed.block_size != 0) {
        block_size = parsed.block_size;
    }

    if (parsed.help_requested) {
        alcp::bench::args::print_test_help();
    }

    seed_set      = parsed.seed_set;
    seed_override = parsed.seed;

    return argsMap;
}

template<typename T>
T*
getPtr(std::vector<T>& vect)
{
    if (vect.size() == 0) {
        return nullptr;
    } else {
        return &vect[0];
    }
}

} // namespace alcp::testing::utils
