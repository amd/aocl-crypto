# AOCL Crypto Library Build

### Build Release Configuration

```shell
$ mkdir build
$ cd build
$ cmake ../
```

#### Extra steps for making STATIC library work
 To generate a single .a file from all the .a files
```shell
ar crsT libnew.a libalcp.a libarch_zen3.a libarch_avx2.a
mv libnew.a libalcp.a
```

#### Enabling Features of AOCL Cryptography

1. [Enable Examples - To compile example/demo code.](#example)
2. [Enable AOCL-UTILS - To dispatch correct kernel with CPU identification.](#aocl-utils)
3. [Enable DEBUG Build - To compile code in Debug Mode.](#debug)
4. [Enable Address Sanitizer Support ](#asan)
5. [Enable Valgrind Memcheck Support ](#memcheck)
6. [Enable Bench - To compile bench code.](#bench)
7. [Enable Tests - To compile test code](#tests)
8. [Build docs in pdf form](#internal-doc)
9. [Build Doxygen and Sphinx docs](#doxygen)
10. [Build with dynamic compiler selection ](#dyncompile)
11. [Build with assembly disabled](#assembly)

#### Enable Examples {#example}

To enable examples, append `-DALCP_ENABLE_EXAMPLES=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_EXAMPLES=ON ../
```

#### Enable AOCL-UTILS {#aocl-utils}

To enable aocl utils checks, append `-DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source` and `-DENABLE_AOCL_UTILS=ON` to the cmake configuration command.
```bash
$ cmake -DENABLE_AOCL_UTILS=ON -DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source ../
```

#### Build Debug Configuration {#debug}

To build in debug mode, append `-DCMAKE_BUILD_TYPE=DEBUG` to the cmake configuration command.
```sh
$ cmake -DCMAKE_BUILD_TYPE=DEBUG ../
```

#### For Compiling with Address Sanitizer Support {#asan}

To enable sanitizers (asan, tsan etc), append `-DALCP_SANITIZE=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_SANITIZE=ON ../
```

#### For Compiling with Valgrind Memcheck {#memcheck}

In order to build ALCP to run binaries with valgrind to detect any memory leaks
```sh
$ cmake -DALCP_MEMCHECK_VALGRIND=ON ../
```


#### Build Benches {#bench}

To build benchmarking support with alcp library, append `-DALCP_ENABLE_BENCH=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_BENCH=ON ../
```
Benchmarks will be built into `bench/{algorithm_type}/`

Please look into **[ README.md ](md_bench_README.html)** from bench.

#### Execute Benchmarks
```
$ ./bench/{algorithm_type}/bench_{algorithm_type}
```
#### Arguments can be provided in above bench as
```
$ ./bench/digest/bench_digest --benchmark_filter=SHA2_<SHA SCHEME>_<Block Size>
$ ./bench/digest/bench_digest --benchmark_filter=SHA2_512_16 (runs SHA256 schemes for 16 block size)
$ ./bench/digest/bench_digest --benchmark_filter=SHA2 (runs for all SHA2 schemes and block sizes)
```

#### Build Tests (using KAT vectors) {#tests}
To enable tests, append `-DALCP_ENABLE_TESTS=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_TESTS=ON ../
```
Test executables can be found inside `tests/{algorithm_type}` directory 

For more details see **[README.md](md_tests_README.html)** from tests.

#### Execute Tests
 ```  shell
 $ ./tests/{algorithm_type}/test_{algorithm_type}
 ```


### Documentation

#### To enable all PDF documentation {#internal-doc}
These documentations include design documents, Provider documentation etc in PDF format which will be generated.
```sh
$ cmake -DALCP_ENABLE_DOCS=ON ../
```

#### To enable both Doxygen and Sphinx{#doxygen}
```sh
$ cmake -DALCP_ENABLE_HTML=ON ../
```

To generate only the Doxygen html documentation without Sphinx documentation
```sh
$ cmake -DALCP_ENABLE_HTML=ON  -DALCP_ENABLE_DOXYGEN=ON -DALCP_ENABLE_SPHINX=OFF ../ 
```

### To enable Dynamic compiler selection while building{#dyncompile}
If this option is enabled it will dynamically select between gcc/clang for compiling certain files to improve performance.
```sh
$ cmake -DALCP_ENABLE_DYNAMIC_COMPILER_PICK=ON  ../ 
```

### To disable assembly implementation and use intrinsics Kernels{#assembly}
```sh
$ cmake -DALCP_DISABLE_ASSEMBLY=ON  ../ 
```

### Disabling/Enabling Specific Features 
- To enable multi update feature for all supported ciphers append `-DALCP_ENABLE_CIPHER_MULTI_UPDATE=ON` to build flags. By default its off.
- To Enable CCM multi update feature append flag `-DALCP_ENABLE_CCM_MULTI_UPDATE=ON` to build flags. By default its off.
- To Enable OFB multi update feature append flag `-DALCP_ENABLE_OFB_MULTI_UPDATE=ON` to build flags. By default its off