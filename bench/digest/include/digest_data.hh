#include <string.h>

struct string_vector {
        const char* input;
        const char* output;
};

const struct string_vector STRING_VECTORS_SHA224[] = {
        { "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
        { "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
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
