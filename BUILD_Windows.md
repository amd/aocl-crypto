## AOCL Crypto Library Build for Windows
<!-- FIXME: use "\" instead of "/" -->
### Following software should be installed prior to build AOCL-CRYPTO 

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

* 1. cmake -A x64 -DCMAKE_BUILD_TYPE=RELEASE -B build -T ClangCl
		`-Build binaries will be written to cmake_source_directory/build`
* 2. cmake --build .\build --config=release


> **Important Notes: ASAN in an experimental phase for Windows.**  

### Enabling features of AOCL-Crypto

1. [Enable Examples - To compile example/demo code.](#win-ex)
2. [Enable CPUID - To dispatch correct kernel with CPU identification.](#win-cpu)
3. [Enable DEBUG Build - To compile code in Debug Mode.](#win-debug)
4. [Enable Address Sanitizer Support ](#win-asan)
5. [Enable Bench - To compile bench code.](#win-bench)
6. [Enable Tests - To compile test code](#win-tests)


#### Steps to found binaries/dll's by setting an environment variable

After build,alcp & gtests dll's are not found by feature's *.exe.
Run the batch file, this .bat file set the environment path required by examples,tests & bench.
```
PS> scripts\Set_Env_Path.bat
-Restart the powershell & run any feature .exe from build directory or directly.
```


<div id = "win-ex"></div>

#### Enable Examples Append

```
PS> cmake -DALCP_ENABLE_EXAMPLES=ON -B build 
PS> cmake --build .\build --config=release
```
#### Run Examples
Run from build directory after setting an environment path.
```
$ .\examples\{algorithm_type}\release\{algorithm_type}\*.exe
```
<div id = "win-cpu"></div>


#### Enable CPUID Append
```
PS> cmake -DENABLE_AOCL_CPUID=ON -DAOCL_CPUID_INSTALL_DIR=path/to/aocl/cpuid/source -B build
PS> cmake --build .\build --config=release
```
<div id = "win-debug"></div>


#### For Debug Build

```
PS> cmake -DCMAKE_BUILD_TYPE=DEBUG -B build
PS> cmake --build .\build --config=debug
```
<div id = "win-asan"></div>

#### For Compiling with Address Sanitizer Support

ASAN(Experimental)
```
PS> cmake -DALCP_SANITIZE=ON -B build
PS> cmake --build .\build --config=release
```
<div id = "win-tests"></div>

`Running from build directory
PS>cd build

#### To Build Tests (using KAT vectors)
```
$ Append the argument '-DALCP_ENABLE_TESTS=ON'

PS> cmake -DALCP_ENABLE_TESTS=ON ./
PS> cmake --build . --config=release
```
 This will create test executable:
 .\build\tests\{algorithm_type}\release\*.exe

#### To Run Tests:
 ``` PS
 $ .\tests\{algorithm_type}\release\test_{algorithm_type}
 ```
```For running all tests
PS> ctest -C release
```
<div id = "win-bench"></div>

#### Build Benchmarks

##### To Build Bench
```
$ Append the argument -DALCP_ENABLE_BENCH=ON
PS> cmake -DALCP_ENABLE_BENCH=ON ./
PS> cmake --build . --config=release
```
  This will create bench executable into:
  .\build\bench\{algorithm_type}\{build_type}\*.exe

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
2. [Enable IPPCP - To dcompare performance.](#win-IPPCP)

### Build after enabling compat libs

<div id = "win-OSSL"> </div>
```
Enabling openSSL

PS> cmake -DENABLE_TESTS_OPENSSL_API=ON -DOPENSSL_INSTALL_DIR=path/to/openssl ./
PS> cmake --build build/ --config=release
```
<div id = "win-IPPCP"> </div>

```
Enabling IPP-Crypto
PS> cmake -DENABLE_TESTS_IPP_API=ON -DIPP_INSTALL_DIR=path/to/ipp_crypto ./
PS> cmake --build build/ --config=release
```

#### NOTES:

1. Use '-o' for OpenSSL & '-i' for IPPCP to run tests & bench for them. And also set bin path of compat libs in PATH variable.
2. Run *scripts\Set_Env_Path.bat* to set the path of binaries in environment variable.
3. To Enable examples tests & bench:
>cmake -A x64 -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_TESTS=ON -DALCP_ENABLE_BENCH=ON -DCMAKE_BUILD_TYPE=RELEASE -B build -T ClangCl
4. Few non-critical warnings are expected in Windows build with Clang while integrating other libs.
