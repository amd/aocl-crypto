# Build and Installation

To Build AOCL-Crypto for Different Platform Please refer to Document Related your Platform
    - [ Linux ](#md_BUILD)
    - [ Windows ](#md_BUILD_Windows)

<div  style="padding: 10px 0 0px 0" id="md_BUILD"></div>
<div id="md_BUILD"></div>

## Build Instruction for Linux Platform

### Building

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

#### Enabling Features of AOCL-Crypto

1. [Enable Examples - To compile example/demo code.](#example)
2. [Enable CPUID - To dispatch correct kernel with CPU identification.](#cpuid)
3. [Enable DEBUG Build - To compile code in Debug Mode.](#debug)
4. [Enable Address Sanitizer Support ](#asan)
5. [Enable Bench - To compile bench code.](#bench)
6. [Enable Tests - To compile test code](#tests)

<div id = "example"> </div>

#### Enable Examples

To enable examples, append `-DALCP_ENABLE_EXAMPLES=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_EXAMPLES=ON ../
```

<div id = "cpuid"> </div>

#### Enable CPUID

To enable cpuid, append `-DAOCL_CPUID_INSTALL_DIR=path/to/aocl/cpuid/source` and `-DENABLE_AOCL_CPUID=ON` to the cmake configuration command.
```bash
$ cmake -DENABLE_AOCL_CPUID=ON -DAOCL_CPUID_INSTALL_DIR=path/to/aocl/cpuid/source ../
```

<div id = "debug"> </div>

#### Build Debug Configuration

To build in debug mode, append `-DCMAKE_BUILD_TYPE=DEBUG` to the cmake configuration command.
```sh
$ cmake -DCMAKE_BUILD_TYPE=DEBUG ../
```
<div id = "asan"> </div>

#### For Compiling with Address Sanitizer Support

To enable sanitizers (asan, tsan etc), append `-DALCP_SANITIZE=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_SANITIZE=ON ../
```
<div id = "bench"> </div>

#### Build Benches

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
<div id = "tests"> </div>

#### Build Tests (using KAT vectors)
To enable sanitizers (asan, tsan etc), append `-DALCP_ENABLE_TESTS=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_TESTS=ON ../
```
Test executables can be found inside `tests/{algorithm_type}` directory 

For more details see **[README.md](md_tests_README.html)** from tests.

#### Execute Tests
 ```  shell
 $ ./tests/{algorithm_type}/test_{algorithm_type}
 ```


<br>
<div  style="padding: 10px 0 10px 0" id="md_BUILD_Windows"></div>

## Build Instrucrion for Windows Platform

### Following software should be installed prior to build AOCL-CRYPTO 

=> MS Visual Studio (2019 or greater)
=> Git
=> Python 3.7 or greater
=> Cmake

### AOCL Crypto Library in Windows

1. After git checkout the latest Crypto_Lib for windows.
2. Open the powershell.exe as administrator.
3. cd to current working directory/cmake_source_directory

### Building

`you can enable EXAMPLES, TESTS & BENCH & generate the Project Files. Here you are specify cmake generator, by default 'Visual Studio': platform: 'x64' (by default): and for toolset current configuration use 'ClangCl'

```Powershell

> cmake -A x64 -B build -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_TESTS=ON -DALCP_ENABLE_BENCH=ON -DCMAKE_BUILD_TYPE=RELEASE -T ClangCl
 
 ---Build binaries will be written to cmake_source_directory/build
 
 To build the cmake projects->
> cmake --build build/ --config=release
 

```
### Build after enabling compat libs, CPUID
```Enabling openSSL, IPP-Crypto

> cmake -A x64 -B build -DCMAKE_BUILD_TYPE=RELEASE -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_TESTS=ON -DALCP_ENABLE_BENCH=ON -DENABLE_AOCL_CPUID=ON -DAOCL_CPUID_INSTALL_DIR=path/to/libcpuid 
-DENABLE_TESTS_OPENSSL_API=ON -DOPENSSL_INSTALL_DIR=path/to/openssl -DENABLE_TESTS_IPP_API=ON -DIPP_INSTALL_DIR=path/to/ipp_crypto -T ClangCl
> cmake --build build/ --config=release
```

### Extra steps to found dll's by setting an environment variable
`Try to Run the tests, if alcp & gtests dll's are not found, run the batch file, this batch file set the environment path for tests & bench.

> Set_Env_Path.bat
And restart the powershell & set the path to current cmake source directory.

### For run the Cipher & Digest Tests
> cd build
> ctest -C release

### For run the Cipher & Digest bench
``` For running the benchmarking for cipher & digests, you can run the following batch files
.\bench\digest\release\bench_digest
.\bench\cipher\release\bench_cipher
```

> **Important Notes: ASAN is not configured for Windows yet.**  


### Enabling features of AOCL-Crypto

1. [Enable Examples - To compile example/demo code.](#win-ex)
2. [Enable CPUID - To dispatch correct kernel with CPU identification.](#win-cpu)
3. [Enable DEBUG Build - To compile code in Debug Mode.](#win-debug)
4. [Enable Address Sanitizer Support ](#win-asan)
5. [Enable Bench - To compile bench code.](#win-bench)
6. [Enable Tests - To compile test code](#win-tests)

<div id = "win-ex"></div>

#### Enable Examples Append

```
$ cmake -DALCP_ENABLE_EXAMPLES=ON -B build
```
<div id = "win-cpu"></div>

#### Enable CPUID Append

```
$ cmake -DAOCL_CPUID_INSTALL_DIR=path/to/aocl/cpuid/source ../
```
<div id = "win-debug"></div>

#### For Debug Build

```
$ cmake -DCMAKE_BUILD_TYPE=DEBUG -B build
```
<div id = "win-asan"></div>

#### For Compiling with Address Sanitizer Support
```
ASAN is not configured for windows yet
```
<div id = "win-bench"></div>

#### Build Benchmarks

##### To Build Bench
```
$ Append the argument -DALCP_ENABLE_BENCH=ON
  This will create bench executable:
  .\bench\{alogrithm_type}\ -B build
```
##### To Run Bench:
```
$ .\bench\{alogrithm_type}\release\bench_{alogrithm_type}
```
##### Arguments can be provided as:

``` PS
$ .\bench\{alogrithm_type}\release\bench_{alogrithm_type} --benchmark_filter=SHA2_<SHA SCHEME>_<Block Size>
$ .\bench\{alogrithm_type}\release\bench_{alogrithm_type} --benchmark_filter=SHA2_512 (runs SHA512 schemes for all block size)
$ .\bench\{alogrithm_type}\release\bench_{alogrithm_type} --benchmark_filter=SHA2 (runs for all SHA2 schemes and block sizes)
```
<div id = "win-tests"></div>

#### To Build Tests (using KAT vectors)
```
$ Append the argument '-DALCP_ENABLE_TESTS=ON'
 This will create test executable:
 .\tests\{alogrithm_type}\release
```

#### To Run Tests:
 ```  PS
 $ .\tests\{alogrithm_type}\release\test_{alogrithm_type}
 ```


