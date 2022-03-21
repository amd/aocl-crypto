#pragma once

#include "alc_base.hh"
#include "base.hh"
#include "string.h"
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>

#ifdef USE_IPP
#include "ipp_base.hh"
#endif

typedef enum
{
    DECRYPT = 0,
    ENCRYPT = 1,

} encrypt_t;
