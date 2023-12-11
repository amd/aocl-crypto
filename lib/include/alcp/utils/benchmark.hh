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
 *-
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef WIN32
#include "alcp/utils/time.hh"
#else
#include <sys/time.h>
#endif
#define ALCP_CRYPT_TIMER_INIT struct timeval begin, end;
long   seconds;
long   microseconds;
double elapsed;
double totalTimeElapsed;

#define ALCP_CRYPT_TIMER_START gettimeofday(&begin, 0);

#define ALCP_CRYPT_GET_TIME(X, Y)                                              \
    gettimeofday(&end, 0);                                                     \
    seconds      = end.tv_sec - begin.tv_sec;                                  \
    microseconds = end.tv_usec - begin.tv_usec;                                \
    elapsed      = seconds + microseconds * 1e-6;                              \
    totalTimeElapsed += elapsed;                                               \
    if (X) {                                                                   \
        printf("\t" Y);                                                        \
        printf(" %2.2f ms ", elapsed * 1000);                                  \
    }
