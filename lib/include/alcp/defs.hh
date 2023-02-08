/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#pragma once

/**
 * @brief ALIGNED() macro
 *        Helps to mark a variable aligned
 */
#if defined(_MSC_VER)
#define ALIGNED(x) __declspec(align(x))
#else
#if defined(__GNUC__) || defined(CLANG)
#define ALIGNED(x) __attribute__((aligned(x)))
#endif
#endif

/**
 * @brief ALCP_DEFS_MUST_USE_RETURN
 *        Attribute to mandate use of return values.
 */
#if defined(_MSC_VER)
#define ALCP_DEFS_NO_DISCARD
#else
#define ALCP_DEFS_NO_DISCARD      [[nodiscard]]
#endif

/**
 * @brief OFFSET_OF() macro
 *        Helps to mark a function, variable, parameter as unused
 */
#define OFFSET_OF(type, field)                                                 \
    (reinterpret_cast<size_t>(                                                 \
         reinterpret_cast<char*>(&(reinterpret_cast<type*>(10)->field)))       \
     - 10)

/**
 * @brief UNUSED() macro
 *        Helps to mark a function, variable, parameter as unused
 */
#if defined(_MSC_VER)
#define UNUSED(x) ((void)(x))
#else
#if defined(__GNUC__) || defined(CLANG)
#define UNUSED(x) __attribute__((unused))
#endif
#endif

/*
 * Some class Constroctor (CTOR) and
 * Destructor(DTOR) helper macros, to be readable
 */

#ifndef ALCP_DEFS_ALCP_DEFS_DISABLE_COPY_CTOR
#define ALCP_DEFS_DISABLE_COPY_CTOR(CLASS_NAME)                                     \
    CLASS_NAME(const CLASS_NAME&) = delete
#endif

#ifndef ALCP_DEFS_DISABLE_MOVE_CTOR
#define ALCP_DEFS_DISABLE_MOVE_CTOR(CLASS_NAME) CLASS_NAME(CLASS_NAME \ &&) = delete
#endif

#ifndef ALCP_DEFS_DISABLE_MOVE_ASSIGNMENT
#define ALCP_DEFS_DISABLE_MOVE_ASSIGNMENT(CLASS_NAME)                               \
    CLASS_NAME& operator=(CLASS_NAME&&) = delete
#endif

#ifndef ALCP_DEFS_DISABLE_ASSIGNMENT
#define ALCP_DEFS_DISABLE_ASSIGNMENT(CLASS_NAME)                                    \
    CLASS_NAME& operator=(const CLASS_NAME&) = delete
#endif

// Disable the copy constructor and assignment operator
// Useful macro to simply do the necessary in a single line
#ifndef ALCP_DEFS_DISABLE_COPY_AND_ASSIGNMENT
#define ALCP_DEFS_DISABLE_COPY_AND_ASSIGNMENT(CLASS_NAME)                           \
    ALCP_DEFS_DISABLE_COPY_CTOR(CLASS_NAME);                                        \
    ALCP_DEFS_DISABLE_ASSIGNMENT(CLASS_NAME)
#endif

// Disable the copy CTOR and assignment operator
// Useful macro to simply do the necessary in a single line
#ifndef ALCP_DEFS_DEFAULT_COPY_AND_ASSIGNMENT
#define ALCP_DEFS_DEFAULT_COPY_AND_ASSIGNMENT(CLASS_NAME)                           \
    CLASS_NAME(const CLASS_NAME&)            = default;                        \
    CLASS_NAME& operator=(const CLASS_NAME&) = default
#endif

#define ALCP_DEFS_CONCAT_TOKEN(a, b, c)      ALCP_DEFS_CONCAT_TOKEN_IMPL(a, b, c)
#define ALCP_DEFS_CONCAT_TOKEN_IMPL(a, b, c) a##b##c

#define ALCP_DEFS_STRINGIZE(x) #x

// Switching off clang-format as the formatter
// clubs the '~' with CLASS_NAME,
// clang-format off
#ifndef ALCP_DEFS_DEFAULT_CTOR
#define ALCP_DEFS_DEFAULT_CTOR(CLASS_NAME)                                                \
    CLASS_NAME () = default
#endif

#ifndef ALCP_DEFS_DEFAULT_DTOR
#define ALCP_DEFS_DEFAULT_DTOR(CLASS_NAME)                                                \
    ~ CLASS_NAME () = default
#endif

#ifndef ALCP_DEFS_DEFAULT_CTOR_DTOR
#define ALCP_DEFS_DEFAULT_CTOR_AND_DTOR(CLASS_NAME)                                      \
    ALCP_DEFS_DEFAULT_CTOR(CLASS_NAME);                                                  \
    ALCP_DEFS_DEFAULT_DTOR(CLASS_NAME)
#endif

#ifndef ALCP_DEFS_DEFAULT_CTOR_AND_EMPTY_VIRTUAL_DTOR
#define ALCP_DEFS_DEFAULT_CTOR_AND_EMPTY_VIRTUAL_DTOR(CLASS_NAME)                  \
    CLASS_NAME ()                = default ;                                       \
    virtual ~ CLASS_NAME() {}
#endif

#ifndef ALCP_DEFS_VIRTUAL_DTOR
#define ALCP_DEFS_VIRTUAL_DTOR(CLASS_NAME)                                               \
    virtual ~ CLASS_NAME() = 0
#endif

#ifndef ALCP_DEFS_DEFAULT_MOVE_CTOR
#define ALCP_DEFS_DEFAULT_MOVE_CTOR(CLASS_NAME)                                          \
    CLASS_NAME(CLASS_NAME &&) = default
#endif
// clang-format on
