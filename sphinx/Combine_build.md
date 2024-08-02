# Build and Installation

To Build AOCL Cryptography for different platforms please refer to the document related to your platform

- [ Linux ](#md_BUILD)
- [ Windows ](#md_BUILD_Windows)

(md_BUILD)=
## Build Instruction for Linux Platform 

AOCL-Cryptography uses CMAKE as a build system generator and supports make and Ninja build systems. This document explains the different build flags which can be used to disable/enable specific features for the project. For a quick start into AOCL-Cryptography, please refer to [AOCL-Cryptography Linux Quick Starter](Quick_Start).

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

(example)=
#### Enable Examples

To enable examples, append `-DALCP_ENABLE_EXAMPLES=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_EXAMPLES=ON ../
```
ALCP_ENABLE_EXAMPLES is ON by default

(aocl-utils)=
#### Enable AOCL-UTILS

To enable aocl utils checks, append `-DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source` and `-DENABLE_AOCL_UTILS=ON` to the cmake configuration command.
```bash
$ cmake -DENABLE_AOCL_UTILS=ON -DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source ../
```
ENABLE_AOCL_UTILS is ON by default

(debug)=
#### Build Debug Configuration 

To build in debug mode, append `-DCMAKE_BUILD_TYPE=DEBUG` to the cmake configuration command.
```sh
$ cmake -DCMAKE_BUILD_TYPE=DEBUG ../
```
CMAKE_BUILD_TYPE is set to RELEASE by default

(asan)=
#### For Compiling with Address Sanitizer Support 

To enable sanitizers (asan, tsan etc), append `-DALCP_SANITIZE=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_SANITIZE=ON ../
```
ENABLE_AOCL_UTILS is OFF by default

(memcheck)=
#### For Compiling with Valgrind Memcheck 

In order to build ALCP to run binaries with valgrind to detect any memory leaks
```sh
$ cmake -DALCP_MEMCHECK_VALGRIND=ON ../
```
ALCP_MEMCHECK_VALGRIND is OFF by default

(bench)=
#### Build Benches 

To build benchmarking support with alcp library, append `-DALCP_ENABLE_BENCH=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_BENCH=ON ../
```
ALCP_ENABLE_BENCH is OFF by default

Benchmarks will be built into `bench/{algorithm_type}/`

Please look into **[ README.md ](bench_README)** from bench.

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

(tests)=
#### Build Tests (using KAT vectors) 
To enable tests, append `-DALCP_ENABLE_TESTS=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_TESTS=ON ../
```
ALCP_ENABLE_TESTS is OFF by default

Test executables can be found inside `tests/{algorithm_type}` directory 

For more details see **[README.md](tests_README)** from tests.

#### Execute Tests
 ```  shell
 $ ./tests/{algorithm_type}/test_{algorithm_type}
 ```


### Documentation

(internal)=
#### To enable all PDF documentation doc
These documentations include design documents, Provider documentation etc in PDF format which will be generated.
```sh
$ cmake -DALCP_ENABLE_DOCS=ON ../
```
ALCP_ENABLE_DOCS is OFF by default

(doxygen)=
#### To enable both Doxygen and Sphinx
```sh
$ cmake -DALCP_ENABLE_HTML=ON ../
```
ALCP_ENABLE_HTML is OFF by default

To generate only the Doxygen html documentation without Sphinx documentation
```sh
$ cmake -DALCP_ENABLE_HTML=ON  -DALCP_ENABLE_DOXYGEN=ON -DALCP_ENABLE_SPHINX=OFF ../ 
```
ALCP_ENABLE_DOXYGEN, ALCP_ENABLE_SPHINX both are OFF by default 

(dyncompile)=
### To enable Dynamic compiler selection while building
If this option is enabled it will dynamically select between gcc/clang for compiling certain files to improve performance.
```sh
$ cmake -DALCP_ENABLE_DYNAMIC_COMPILER_PICK=ON  ../ 
```
ALCP_ENABLE_DYNAMIC_COMPILER_PICK is on by default 

(assembly)=
### To disable assembly implementation and use intrinsics Kernels
```sh
$ cmake -DALCP_DISABLE_ASSEMBLY=ON  ../ 
```
ALCP_DISABLE_ASSEMBLY is OFF by default 

(optional)=
### Disabling/Enabling Optional Features 
By default all of the below features are OFF by default and they can be enabled optionally by setting their corresponding flags to ON

- To enable multi update feature for all supported ciphers append `-DALCP_ENABLE_CIPHER_MULTI_UPDATE=ON` to build flags. 
- To Enable CCM multi update feature append flag `-DALCP_ENABLE_CCM_MULTI_UPDATE=ON` to build flags. 
- To Enable OFB multi update feature append flag `-DALCP_ENABLE_OFB_MULTI_UPDATE=ON` to build flags.

(md_BUILD_Windows)=
## Build Instruction for Windows Platform 

### Following software should be installed prior to build AOCL Cryptography

- MS Visual Studio (2019 or greater)
- Clang 15.0 or above
- Python 3.7 or greater
- Cmake 3.21 or greater
- Git

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

`Run from source directory`
```
PS > cmake -A [platform: x86/x64] -B [build_directory] [Enable features] -DCMAKE_BUILD_TYPE=[RELEASE] -G "[generator: Visual Studio 17 2022]" -T [toolset:ClangCl/LLVM]
```
Default set values: 
- Generator:'Visual Studio Generator'
- platform: 'x64' if external LLVM toolset use: -T LLVM (otherwise,ClangCl)
- Available features: EXAMPLES, ADDRESS SANITIZER, TESTS, BENCH

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
5. [Enable Bench - To compile bench code.](#win-bench)
6. [Enable Tests - To compile test code](#win-tests)


#### Steps to find binaries/dll's by setting an environment variable

After build, alcp & gtests dll's are not found by feature's *.exe.
Run the batch file(Set_Env_Path.bat) to set the environment path required by examples, tests & bench.
```
PS> scripts\Set_Env_Path.bat
-Restart the powershell & run any feature .exe from build directory or directly.
```



(win-ex)=
#### Enable Examples

```
PS> cmake -DALCP_ENABLE_EXAMPLES=ON -B build 
PS> cmake --build .\build --config=release
```
#### Run Examples
Run from build directory after setting an environment path.
```
$ .\examples\{algorithm_type}\release\{algorithm_type}\*.exe
```


(win-cpu)=
#### Enable AOCL-UTILS cpu
```
PS> cmake -DENABLE_AOCL_UTILS=ON -DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source -B build
PS> cmake --build .\build --config=release
```

(win-debug-asan)=
#### For Debug Build debug

```
PS> cmake -DCMAKE_BUILD_TYPE=DEBUG -B build
PS> cmake --build .\build --config=debug
```

(win-bench)=
#### For Compiling with Address Sanitizer Support asan

```
PS> cmake -DALCP_SANITIZE=ON -B build
PS> cmake --build .\build --config=release
```

`Running from build directory
PS>cd build

(win-tests)=
#### To Build Tests (using KAT vectors) tests
```
$ Append the argument '-DALCP_ENABLE_TESTS=ON'

PS> cmake -DALCP_ENABLE_TESTS=ON ./
PS> cmake --build . --config=release
```
 This will create test executable:
```
 .\build\tests\{algorithm_type}\release\*.exe
```

#### To Run Tests:
 ``` PS
 $ .\tests\{algorithm_type}\release\test_{algorithm_type}
 ```
```For running all tests
PS> ctest -C release
```

(win-bench)=
#### Build Benchmarks bench

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

### Enabling compat libs


1. [Enable OpenSSL - To compare performance .](#win-OSSL)
2. [Enable IPPCP - To compare performance.](#win-IPPCP)

## Build after enabling compat libs

(win-OSSL)=
#### Building OpenSSL Compatibility Libs OSSL


Enabling openSSL
```
PS> cmake -DENABLE_TESTS_OPENSSL_API=ON -DOPENSSL_INSTALL_DIR=path/to/openssl ./
PS> cmake --build build/ --config=release
```

(win-IPPCP)=
#### Building IPP-CP Compatibility Libs IPPCP

Enabling IPP-Crypto
```
PS> cmake -DENABLE_TESTS_IPP_API=ON -DIPP_INSTALL_DIR=path/to/ipp_crypto ./
PS> cmake --build build/ --config=release
```

#### NOTES:
```
1. Use '-o' for OpenSSL & '-i' for IPPCP to run tests & bench for them. And also set bin path of compat libs in PATH variable.
2. Run *scripts\Set_Env_Path.bat* to set the path of binaries in environment variable.
3. To Enable examples, tests & bench:
>cmake -A x64 -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_TESTS=ON -DALCP_ENABLE_BENCH=ON -DCMAKE_BUILD_TYPE=RELEASE -B build -T ClangCl
4. Few non-critical warnings are expected in Windows build with Clang while integrating other libs.
```