# Build and Installation

To Build AOCL Cryptography for different platforms please refer to the document related to your platform
    - [ Linux ](#md_BUILD)
    - [ Windows ](#md_BUILD_Windows)

## Build Instruction for Linux Platform {#md_BUILD}

AOCL-Cryptography uses CMAKE as a build system generator and supports make and Ninja build systems. This document explains the different build flags which can be used to disable/enable specific features for the project. For a quick start into AOCL-Cryptography, please refer to [AOCL-Cryptography Linux Quick Starter](md_docs_resources_Quick_Start.html).

#### Build
`Run from build directory`

```sh
$ cmake  -DOPENSSL_INSTALL_DIR=[path_to_openssl_install_dir]  -DAOCL_UTILS_INSTALL_DIR=[path_to_aoclutils_install_dir] ../
$ make -j 
```
#### Using Ninja build System

```sh
$ cmake -G "Ninja" -DOPENSSL_INSTALL_DIR=[path_to_openssl_install_dir]  -DAOCL_UTILS_INSTALL_DIR=[path_to_aoclutils_install_dir] ../
$ ninja 
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
12. [Disabling/Enabling Optional Features](#optional)


#### Enable Examples {#example}

To enable examples, append `-DALCP_ENABLE_EXAMPLES=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_EXAMPLES=ON ../
```
ALCP_ENABLE_EXAMPLES is ON by default

#### Enable AOCL-UTILS {#aocl-utils}

To enable aocl utils checks, append `-DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source` and `-DENABLE_AOCL_UTILS=ON` to the cmake configuration command.
```bash
$ cmake -DENABLE_AOCL_UTILS=ON -DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source ../
```
ENABLE_AOCL_UTILS is ON by default

#### Build Debug Configuration {#debug}

To build in debug mode, append `-DCMAKE_BUILD_TYPE=DEBUG` to the cmake configuration command.
```sh
$ cmake -DCMAKE_BUILD_TYPE=DEBUG ../
```
CMAKE_BUILD_TYPE is set to RELEASE by default

#### For Compiling with Address Sanitizer Support {#asan}

To enable sanitizers (asan, tsan etc), append `-DALCP_SANITIZE=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_SANITIZE=ON ../
```
ENABLE_AOCL_UTILS is OFF by default

#### For Compiling with Valgrind Memcheck {#memcheck}

In order to build ALCP to run binaries with valgrind to detect any memory leaks
```sh
$ cmake -DALCP_MEMCHECK_VALGRIND=ON ../
```
ALCP_MEMCHECK_VALGRIND is OFF by default

<span style="color:red"> __Note__: </span> Due to a known limitation in AOCL-Utils, any executables exercising RSA / EC routines might fail when ran with valgrind.

#### Build Benches {#bench}

To build benchmarking support with alcp library, append `-DALCP_ENABLE_BENCH=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_BENCH=ON ../
```
ALCP_ENABLE_BENCH is OFF by default

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
ALCP_ENABLE_TESTS is OFF by default

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
ALCP_ENABLE_DOCS is OFF by default

#### To enable both Doxygen and Sphinx{#doxygen}
```sh
$ cmake -DALCP_ENABLE_HTML=ON ../
```
ALCP_ENABLE_HTML is OFF by default

To generate only the Doxygen html documentation without Sphinx documentation
```sh
$ cmake -DALCP_ENABLE_HTML=ON  -DALCP_ENABLE_DOXYGEN=ON -DALCP_ENABLE_SPHINX=OFF ../ 
```
ALCP_ENABLE_DOXYGEN, ALCP_ENABLE_SPHINX both are OFF by default 

### To enable Dynamic compiler selection while building{#dyncompile}
If this option is enabled it will dynamically select between gcc/clang for compiling certain files to improve performance.
```sh
$ cmake -DALCP_ENABLE_DYNAMIC_COMPILER_PICK=ON  ../ 
```
ALCP_ENABLE_DYNAMIC_COMPILER_PICK is on by default 

### To disable assembly implementation and use intrinsics Kernels{#assembly}
```sh
$ cmake -DALCP_DISABLE_ASSEMBLY=ON  ../ 
```
ALCP_DISABLE_ASSEMBLY is OFF by default 

### Disabling/Enabling Optional Features {#optional}
By default all of the below features are OFF and they can be enabled optionally by setting their corresponding flags to ON

- To enable multi update feature for all supported ciphers append `-DALCP_ENABLE_CIPHER_MULTI_UPDATE=ON` to build flags. 
- To Enable CCM multi update feature append flag `-DALCP_ENABLE_CCM_MULTI_UPDATE=ON` to build flags. 
- To Enable OFB multi update feature append flag `-DALCP_ENABLE_OFB_MULTI_UPDATE=ON` to build flags.

## Build Instruction for Windows Platform {#md_BUILD_Windows}

### Following software should be installed prior to build AOCL Cryptography

- MS Visual Studio (2019 or greater)
- Clang 15.0 or above
- Cmake 3.21 or greater
- Git
- Ninja(Alternative to Visual Studio Build System)

### Environment Setup:

1. Install visual Studio with workload: *Desktop development with c++*
	- Enable Clang/cl tools(required) & Address Santizer(if require)
2. If using LLVM/Clang as external toolset:
	- Install LLVM
	- Install plugin: *llvm2019.vsix* :https://marketplace.visualstudio.com/items?itemName=MarekAniola.mangh-llvm2019
	- Install VS19 version 16.10	

### Windows Build with LLVM/Clang:

Using Powershell:

1. Checkout the latest code.
2. Open the powershell.exe (as administrator)
3. Set path to current working directory/cmake_source_directory

### Build

#### Using VS-Studio Generator

`Run from source directory`
```
PS > cmake -A [platform: x86/x64] -B [build_directory] [Enable features] -DCMAKE_BUILD_TYPE=[RELEASE] -G "[generator: Visual Studio 17 2022]" -T [toolset:ClangCl/LLVM]
```
Default set values: 
- Generator:'Visual Studio Generator'
- platform: 'x64' if external LLVM toolset use: -T LLVM (otherwise,ClangCl)
- Available features: EXAMPLES, ADDRESS SANITIZER, TESTS, BENCH

#### Using Ninja build System
```
PS > cmake -B [build_directory] [Enable features] -DCMAKE_BUILD_TYPE=[RELEASE/DEBUG] -DCMAKE_C_COMPILER:FILEPATH=[path to C compiler] -DCMAKE_CXX_COMPILER:FILEPATH=[path_to_cxx_compiler] -G "Ninja"
```

`Powershell`
```
* 1. cmake -A x64 -DCMAKE_BUILD_TYPE=RELEASE -B build -T ClangCl
		`-Build binaries will be written to cmake_source_directory/build`
* 2. cmake --build .\build --config=release
```

### Enabling features of AOCL Cryptography

1. [Enable Examples - To compile example/demo code.](#win-ex)
2. [Enable AOCL-UTILS - To dispatch correct kernel with CPU identification.](#win-cpu)
3. [Enable DEBUG Build - To compile code in Debug Mode.](#win-debug)
4. [Enable Address Sanitizer Support ](#win-asan)
5. [Enable Tests - To compile test code](#win-tests)
6. [Enable Bench - To compile bench code.](#win-bench)
7. [Enable Compat - To compare with compat libs.](#win-compat)
8. [Disabling/Enabling Optional Features](#win-optional)


#### Steps to find binaries/dll's by setting an environment variable

After build, alcp & gtests dll's are not found by feature's *.exe.
Run the batch file(Set_Env_Path.bat) to set the environment path required by examples, tests & bench.
```
PS> scripts\Set_Env_Path.bat
-Restart the powershell & run any feature .exe from build directory or directly.
```


#### Enable Examples {#win-ex}

```
PS> cmake -DALCP_ENABLE_EXAMPLES=ON -B build 
PS> cmake --build .\build --config=release
```
#### Run Examples
Run from build directory after setting an environment path.
```
$ .\examples\{algorithm_type}\release\*.exe
```


#### Enable AOCL-UTILS {#win-cpu}
```
PS> cmake -DENABLE_AOCL_UTILS=ON -DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source -B build
PS> cmake --build .\build --config=release
```

#### For Debug Build {#win-debug}

```
PS> cmake -DCMAKE_BUILD_TYPE=DEBUG -B build
PS> cmake --build .\build --config=debug
```

#### For Compiling with Address Sanitizer Support {#win-asan}

```
PS> cmake -DALCP_SANITIZE=ON -B build
PS> cmake --build .\build --config=release
```

`Running from build directory
PS>cd build

#### To Build Tests (using KAT vectors) {#win-tests}
```
$ Append the argument '-DALCP_ENABLE_TESTS=ON'

PS> cmake -DALCP_ENABLE_TESTS=ON ./
PS> cmake --build . --config=release
```
 This will create test executable:
```
 .\build\tests\{algorithm_type}\release\*.exe
```
For more details see **[README.md](md_tests_README.html)** from tests.

#### To Run Tests:
 ``` PS
 $ .\tests\{algorithm_type}\release\test_{algorithm_type}
 ```
```For running all tests
PS> ctest -C release
```

#### Build Benchmarks {#win-bench}

##### To Build Bench
```
$ Append the argument -DALCP_ENABLE_BENCH=ON
PS> cmake -DALCP_ENABLE_BENCH=ON ./
PS> cmake --build . --config=release
```
  This will create bench executable into:
```
  .\build\bench\{algorithm_type}\{build_type}\*.exe
```
##### To Run Bench:
```
$ .\bench\{algorithm_type}\release\bench_{algorithm_type}
```
##### Arguments can be provided as:

``` PS
$ .\bench\{algorithm_type}\release\bench_{algorithm_type} --benchmark_filter=SHA2_<SHA SCHEME>_<Block Size>
$ .\bench\{algorithm_type}\release\bench_{algorithm_type} --benchmark_filter=SHA2_512 (runs SHA512 schemes for all block size)
$ .\bench\{algorithm_type}\release\bench_{algorithm_type} --benchmark_filter=SHA2 (runs for all SHA2 schemes and block sizes)
```

### Disabling/Enabling Optional Features {#win-optional}
By default all of the below features are OFF and they can be enabled optionally by setting their corresponding flags to ON
- To enable multi update feature for all supported ciphers append `-DALCP_ENABLE_CIPHER_MULTI_UPDATE=ON` to build flags. 
- To Enable CCM multi update feature append flag `-DALCP_ENABLE_CCM_MULTI_UPDATE=ON` to build flags. 
- To Enable OFB multi update feature append flag `-DALCP_ENABLE_OFB_MULTI_UPDATE=ON` to build flags.


## Enabling compat libs{#win-compat}


1. [Enable OpenSSL - To compare performance .](#win-OSSL)
2. [Enable IPPCP - To compare performance.](#win-IPPCP)

### Build after enabling compat libs

#### Building OpenSSL Compatibility Libs {#win-OSSL}


Enabling openSSL
```
PS> cd aocl-crypto/build
PS> cmake -DAOCL_COMPAT_LIBS=openssl ../
PS> cmake --build build --config=release
```
After running all the above commands you should see a `openssl-compat.dll` in \lib\compat\openssl\Release directory

#### Benchmarking
	To bench using provider path, use the following example assuming you are executing command from openssl bin directory.

	``` .\openssl.exe speed -provider-path {path_to_openssl-compat} -provider openssl-compat -evp aes-128-cbc```

#### Building IPP-CP Compatibility Libs {#win-IPPCP}

Enabling IPP-Crypto
```
PS> cd aocl-crypto/build
PS> cmake --DAOCL_COMPAT_LIBS=ipp ../
PS> cmake --build build --config=release
```

#### NOTES:
```
1. Use '-o' for OpenSSL & '-i' for IPPCP to run tests & bench for them. And also set bin path of compat libs in PATH variable.
2. Run *scripts\Set_Env_Path.bat* to set the path of binaries in environment variable.
3. To Enable examples, tests & bench:
>cmake -A x64 -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_TESTS=ON -DALCP_ENABLE_BENCH=ON -DCMAKE_BUILD_TYPE=RELEASE -B build -T ClangCl
4. Few non-critical warnings are expected in Windows build with Clang while integrating other libs.
```