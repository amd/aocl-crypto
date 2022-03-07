#ifndef DIGEST_DATA_PERF_HH_
#define DIGEST_DATA_PERF_HH_

#include <string.h>
#include <vector>
#include "common.hh"

/*conformance (KAT)test vectors for diff digest schemes */
static std::vector <_alc_hash_kat_vector>
STRING_VECTORS_PERF_SHA224 = {
        { "dfdgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgd \
        dfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgfgdhudh4y6eth436yrfgedfwefwrg \
        f354tgreg35g5g534gheyt6uj6hrthb46jh46h46h4576hj46yh464ertgdtrh",
	        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
};

static std::vector <_alc_hash_kat_vector>
STRING_VECTORS_PERF_SHA256 = {
        { "streghre5g4rthg45yw45yh46j675j65",
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
};

static std::vector <_alc_hash_kat_vector>
STRING_VECTORS_PERF_SHA384 = {
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
          "bdc0f4a6e0d7de88f374e6c2562441d856aeabed3f52553103f55eca811f64b422c7"
          "cb47a8067f123e45c1a8ee303635" }  
};

static std::vector <_alc_hash_kat_vector>
STRING_VECTORS_PERF_SHA512 = {
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "451e75996b8939bc540be780b33d2e5ab20d6e2a2b89442c9bfe6b4797f6440dac65"
          "c58b6aff10a2ca34c37735008d671037fa4081bf56b4ee243729fa5e768e" },
};

#endif //DIGEST_DATA_PERF_HH_
