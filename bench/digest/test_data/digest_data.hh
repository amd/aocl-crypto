#ifndef DIGEST_DATA_HH_
#define DIGEST_DATA_HH_

#include <string.h>
#include <vector>
#include "common.hh"

/*conformance (KAT)test vectors for diff digest schemes */
static std::vector <_alc_hash_kat_vector>
STRING_VECTORS_SHA224 = {
        { "",
	        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
        { "abc", 
	         "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "43f95590b27f2afde6dd97d951f5ba4fe1d154056ec3f8ffeaea6347" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "99da0faf832c6b266c5db29a034e536a2a81df95c499ed0ce14d7978" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
          "0a132954fcaf53473a7d4eb87d44038a17e3175d67214750a963a868" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
          "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3" }
};

static std::vector <_alc_hash_kat_vector>
STRING_VECTORS_SHA256 = {
        { "",
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc",
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "a8ae6e6ee929abea3afcfc5258c8ccd6f85273e0d4626d26c7279f3250f77c8e" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "057ee79ece0b9a849552ab8d3c335fe9a5f1c46ef5f1d9b190c295728628299c" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
          "2a6ad82f3620d3ebe9d678c812ae12312699d673240d5be8fac0910a70000d93" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
          "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d"
          "1" }
};

static std::vector <_alc_hash_kat_vector>
STRING_VECTORS_SHA384 = {
        { "",
          "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274e"
          "debfe76f65fbd51ad2f14898b95b" },
        { "abc",
          "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086"
          "072ba1e7cc2358baeca134c825a7" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "648a627ba7edae512ab128eb8e4ad9cc13c9e89da332f71fe767f1c4dd0e5c2bd3f8"
          "3009b2855c02c7c7e488bcfc84dc" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "f932b89b678dbdddb555807703b3e4ff99d7082cc4008d3a623f40361caa24f8b53f"
          "7b112ed46f027ff66ef842d2d08c" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "436ac328cb192b0077f8c29527f7a91214b8fe1b5c872cb176f5410f76c11d16b8b6"
          "d574aea17454afc4cdcd9e6a52ab" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "5fe52b687a74a341872e833f53ed68fa1fd2efe237214c6b03bba3ef1c4395ae9574"
          "b75f467d3bde21eef1b0826c9041" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "f932b89b678dbdddb555807703b3e4ff99d7082cc4008d3a623f40361caa24f8b53f"
          "7b112ed46f027ff66ef842d2d08c" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
          "1c95c92db36f7794fa23ea4d354b3bab1187cd8ee4a3dd42b70c343c1cf7d0aa92ba"
          "01e31560260caa23de17a5b76f0d" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b045"
          "5a8520bc4e6f5fe95b1fe3c8452b" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
          "bdc0f4a6e0d7de88f374e6c2562441d856aeabed3f52553103f55eca811f64b422c7"
          "cb47a8067f123e45c1a8ee303635" }  
};

static std::vector <_alc_hash_kat_vector>
STRING_VECTORS_SHA512 = {
        { "",
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0"
          "d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
        { "abc",
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192"
          "992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "ad2981aa58beca63a49b8831274b89d81766a23d7932474f03e55cf00cbe27004e66"
          "fd0912aed0b3cb1afee2aa904115c89db49d6c9bad785523023a9c309561" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "451e75996b8939bc540be780b33d2e5ab20d6e2a2b89442c9bfe6b4797f6440dac65"
          "c58b6aff10a2ca34c37735008d671037fa4081bf56b4ee243729fa5e768e" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "f650799be4b8aecf38cf6ad17538690b89cdf7291ba8ad6a19b45dcb25b52ddff42e"
          "f38ebbf851145e3b8584785d10821068ee17f1e21b36e2b01d888ca71503" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
          "ca8b236e13383f1f2293c9e286376444e99b7f180ba85713f140b55795fd2f8625d8"
          "b84201154d7956b74e2a1e0d5fbff1b61c7288c3f45834ad409e7bdfe536" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "451e75996b8939bc540be780b33d2e5ab20d6e2a2b89442c9bfe6b4797f6440dac65"
          "c58b6aff10a2ca34c37735008d671037fa4081bf56b4ee243729fa5e768e" },
        { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
          "72ddcfd4389b0735b8b5cf758592413ef174df8a2d8e21c285f5ea387369b619faa5"
          "b7b7cb5745a381c65882dd6f1cb757956de9e95b26a38a68b3f75eda6287" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd"
          "15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
          "90d1bdb9a6cbf9cb0d4a7f185ee0870456f440b81f13f514f4561a08112763523033"
          "245875b68209bb1f5d5215bac81e0d69f77374cc44d1be30f58c8b615141" }
};

#endif //DIGEST_DATA_HH_
