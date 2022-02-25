#ifndef DIGEST_DATA_HH_
#define DIGEST_DATA_HH_

#include <string.h>
#include <vector>
#include "common.hh"

static std::vector <string_vector> STRING_VECTORS_SHA224 = {
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

static std::vector <string_vector> STRING_VECTORS_SHA256 = {
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
#endif //DIGEST_DATA_HH_
