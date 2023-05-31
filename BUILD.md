# Build and Installation

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

<br>
<div  style="padding: 10px 0 10px 0" id="md_BUILD_Windows"></div>

## Build Instruction for Windows Platform

### Following software should be installed prior to build AOCL-CRYPTO

- MS Visual Studio (2019 or greater)
- Clang 15.0 or above
- Python 3.7 or greater
- Cmake 3.21 or greater
- Git

### Environment Setup:

1. Install visual Studio with workload: *Desktop development with c++*
	- Enable Clang/cl tools(required)
2. If using LLVM/Clang as external toolset:
	- Install LLVM
	- Install plugin: *llvm2019.vsix* :https://marketplace.visualstudio.com/items?itemName=MarekAniola.mangh-llvm2019
	- Install VS19 version 16.10	
3. Add OPENSSL\bin path to 'PATH' environment variables.

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
- Available features: EXAMPLES

`Powershell`

* 1. cmake -A x64 -DCMAKE_BUILD_TYPE=RELEASE -B build -T ClangCl
		`-Build binaries will be written to cmake_source_directory/build`
* 2. cmake --build .\build --config=release


### Enabling features of AOCL-Crypto

1. [Enable Examples - To compile example/demo code.](#win-ex)
2. [Enable CPUID - To dispatch correct kernel with CPU identification.](#win-cpu)
3. [Enable DEBUG Build - To compile code in Debug Mode.](#win-debug)


#### Steps to found binaries/dll's by setting an environment variable

After build,alcp dll's are not found by feature's *.exe.
Run the batch file, this .bat file set the environment path required by examples.
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

#### NOTES:

1. Run *scripts\Set_Env_Path.bat* to set the path of binaries in environment variable.
2. To Enable examples:
>cmake -A x64 -DALCP_ENABLE_EXAMPLES=ON -DCMAKE_BUILD_TYPE=RELEASE -B build -T ClangCl
4. Few non-critical warnings are expected in Windows build with Clang while integrating other libs.
