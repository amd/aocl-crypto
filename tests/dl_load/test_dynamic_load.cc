/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "dl_load/dl_load.hh"
#include <cstdint>

int
main(int argc, char* argv[])
{
    void* handle;
    char* alcp_lib_path = NULL;

    printf("Running dynamic loading test\n");

    if (argc <= 1) {
        printf("Error! Provide .so file path as argument\n");
        return 1;
    }

    alcp_lib_path = argv[1];

    handle = dlopen(alcp_lib_path, RTLD_LAZY);
    if (!handle) {
        printf("Error! %s\n", dlerror());
        return 1;
    }

    /* now just try to load these symbols and call them dont bother about the
     * outputs */
    /* store these in fn pointers */
    func_print_version f_version =
        (func_print_version)dlsym(handle, "alcp_get_version");

    if (f_version == NULL) {
        printf("Error, null func ptr\n");
        return 1;
    }

    /* now call these */
    printf("ALCP_VERSION_IS: %s\n", (*f_version)());
    dlclose(handle);
    return 0;
}