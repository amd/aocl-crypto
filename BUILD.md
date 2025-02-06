# AOCL Cryptography Library Build

AOCL-Cryptography uses CMAKE as a build system generator and supports make and Ninja build systems. This document explains the different build flags which can be used to disable/enable specific features for the project. For a quick start into AOCL-Cryptography, please refer to [AOCL-Cryptography Linux Quick Starter](./docs/resources/Quick_Start.md).

#### Build
`Run from build directory`

```sh
$ cmake  -DOPENSSL_INSTALL_DIR=[path_to_openssl_install_dir]  -DAOCL_UTILS_INSTALL_DIR=[path_to_utils_install_dir] ../
$ make -j 
```
#### Using Ninja build System

```sh
$ cmake -G "Ninja" -DOPENSSL_INSTALL_DIR=[path_to_openssl_install_dir]  -DAOCL_UTILS_INSTALL_DIR=[path_to_utils_install_dir] ../
$ ninja 
```
#### Enabling Features of AOCL Cryptography

1. [Enable Examples - To compile example/demo code.](#enable-examples)
2. [Enable AOCL-UTILS - To dispatch correct kernel with CPU identification.](#enable-aocl-utils)
3. [Enable DEBUG Build - To compile code in Debug Mode.](#build-debug-configuration)
4. [Enable Address Sanitizer Support ](#for-compiling-with-address-sanitizer-support)
5. [Enable Valgrind Memcheck Support ](#for-compiling-with-valgrind-memcheck)
6. [Enable Bench - To compile bench code.](#build-benches)
7. [Enable Tests - To compile test code](#build-tests-using-kat-vectors)
8. [Build Doxygen and Sphinx docs](#to-enable-both-doxygen-and-sphinx)
9. [Build with dynamic compiler selection ](#to-enable-dynamic-compiler-selection-while-building)
10. [Build with assembly disabled](#to-disable-assembly-implementation-and-use-intrinsics-kernels)
11. [Disabling/Enabling Optional Features](#disablingenabling-optional-features)

#### Enable Examples

To enable examples, append `-DALCP_ENABLE_EXAMPLES=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_EXAMPLES=ON ../
```
ALCP_ENABLE_EXAMPLES is ON by default

#### Enable AOCL-UTILS

To enable aocl utils checks, append `-DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source` and `-DENABLE_AOCL_UTILS=ON` to the cmake configuration command.
```bash
$ cmake -DENABLE_AOCL_UTILS=ON -DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source ../
```
ENABLE_AOCL_UTILS is ON by default

#### Build Debug Configuration

To build in debug mode, append `-DCMAKE_BUILD_TYPE=DEBUG` to the cmake configuration command.
```sh
$ cmake -DCMAKE_BUILD_TYPE=DEBUG ../
```
CMAKE_BUILD_TYPE is set to RELEASE by default

#### For Compiling with Address Sanitizer Support

To enable sanitizers (asan, tsan etc), append `-DALCP_SANITIZE=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_SANITIZE=ON ../
```
ENABLE_AOCL_UTILS is OFF by default

#### For Compiling with Valgrind Memcheck

In order to build ALCP to run binaries with valgrind to detect any memory leaks
```sh
$ cmake -DALCP_MEMCHECK_VALGRIND=ON ../
```
ALCP_MEMCHECK_VALGRIND is OFF by default

<span style="color:red"> __Note__: </span> Due to a known limitation in AOCL-Utils, any executables exercising RSA / EC routines might fail when ran with valgrind.

#### Build Benches

To build benchmarking support with alcp library, append `-DALCP_ENABLE_BENCH=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_BENCH=ON ../
```
ALCP_ENABLE_BENCH is OFF by default

Benchmarks will be built into `bench/{algorithm_type}/`

Please look into **[ README.md ](./bench/README.md)** from bench.

Note: ALCP_ENABLE_TESTS has to be enabled to compile benchmarks.

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

#### Build Tests (using KAT vectors)
To enable tests, append `-DALCP_ENABLE_TESTS=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_TESTS=ON ../
```
ALCP_ENABLE_TESTS is OFF by default

Test executables can be found inside `tests/{algorithm_type}` directory 

For more details see **[README.md](./tests/README.md)** from tests.

#### Execute Tests
 ```  shell
 $ ./tests/{algorithm_type}/test_{algorithm_type}
 ```


### Documentation

#### To enable both Doxygen and Sphinx

To enable sphinx documentation before running the CMAKE command install the required python dependencies by

```sh
cd aocl-crypto
pip install -r sphinx/requirements.txt
```
To enable the HTML documentations - Sphinx and doxygen
```sh
$ cmake -DALCP_ENABLE_HTML=ON ../
```
ALCP_ENABLE_HTML is OFF by default

To generate only the Doxygen html documentation without Sphinx documentation
```sh
$ cmake -DALCP_ENABLE_HTML=ON  -DALCP_ENABLE_DOXYGEN=ON -DALCP_ENABLE_SPHINX=OFF ../ 
```
ALCP_ENABLE_DOXYGEN, ALCP_ENABLE_SPHINX both are OFF by default 

### To enable Dynamic compiler selection while building
If this option is enabled it will dynamically select between gcc/clang for compiling certain files to improve performance.
```sh
$ cmake -DALCP_ENABLE_DYNAMIC_COMPILER_PICK=ON  ../ 
```
ALCP_ENABLE_DYNAMIC_COMPILER_PICK is on by default 

### To disable assembly implementation and use intrinsics Kernels
```sh
$ cmake -DALCP_DISABLE_ASSEMBLY=ON  ../ 
```
ALCP_DISABLE_ASSEMBLY is OFF by default 

### Disabling/Enabling Optional Features
By default all of the below features are OFF and they can be enabled optionally by setting their corresponding flags to ON

- To enable multi update feature for all supported ciphers append `-DALCP_ENABLE_CIPHER_MULTI_UPDATE=ON` to build flags. 
- To Enable CCM multi update feature append flag `-DALCP_ENABLE_CCM_MULTI_UPDATE=ON` to build flags. 
- To Enable OFB multi update feature append flag `-DALCP_ENABLE_OFB_MULTI_UPDATE=ON` to build flags.
- To Enable GCM always compute table option to boost performance uplift in applications, append `-DALCP_ENABLE_GCM_ALWAYS_COMPUTE_TABLE=ON` to build flags.