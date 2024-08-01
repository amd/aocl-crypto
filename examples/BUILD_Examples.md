# Build and run AOCL-Cryptography examples

The example snippets can be found in the source code and the package under `aocl-crypto/examples/`

**An example [snippet](https://github.com/amd/aocl-crypto/blob/main/examples/cipher/aes-cfb.c) for AES CFB Cipher**

To compile AOCL-Cryptography with examples, refer to
    - [ Linux ](md_Combine_build.html#md_BUILD)
    - [ Windows ](md_Combine_build.html#md_BUILD_Windows)

The examples executables for each module will be generated in aocl-crypto/build/examples/

**NOTE:**  
The AOCL-Cryptography has a dependency on OpenSSL libcrypto library and also AOCL Utils library.
Please make sure the below paths are added to the environment variables 

[//]: # (There are spaces intentionaly left to break line below)

**Execute Examples On Linux OS**  
Export the following paths:  

```bash
export LD_LIBRARY_PATH=\<path to openssl crypto lib\>:$LD_LIBRARY_PATH;
export LD_LIBRARY_PATH=\<path to AOCL Utils lib\>:$LD_LIBRARY_PATH;
```

Now to run any executable:  
`./examples/cipher/aes-cfb`


**Execute Examples On Windows OS**  
Run the script:  
`.\scripts\Set_Env_Path.bat`


Now to run any executable:  
`.\examples\cipher\release\aes-cfb.exe`


## Build and Run AOCL-Cryptography examples from the AOCL Crypto release package (Linux)

**Download the tar package from https://www.amd.com/en/developer/aocl/cryptography.html (under the downloads section)**

**NOTE:**  
The AOCL-Cryptography library has a dependency on OpenSSL libcrypto library and also AOCL Utils library.
Please make sure these library paths are added to the environment variables LIBRARY_PATH and LD_LIBRARY_PATH

Also, please ensure the variable OPENSSL_INSTALL_DIR is set.  
`export OPENSSL_INSTALL_DIR=\<path to openssl installation/lib64/\>;`


**To run the examples linking to AOCL-Cryptography shared library:**  

```bash
# Ensure OpenSSL is available with linker
export LIBRARY_PATH=/path/to/openssl_install/lib:$LIBRARY_PATH; 
# Ensure AOCL-Utils is available with linker
export LIBRARY_PATH=/path/to/aocl-utils/lib:$LIBRARY_PATH; 
# Ensure OpenSSL is available with loader
export LD_LIBRARY_PATH=/path/to/openssl_install/lib:$LD_LIBRARY_PATH; 
# Ensure AOCL-Utils is available with loader
export LD_LIBRARY_PATH=/path/to/aocl-utils/lib:$LD_LIBRARY_PATH; 
cd amd-crypto;
make;
```


**To run the examples linking to AOCL-Cryptography static library:**  

```bash
cd amd-crypto;
make LIB_TYPE=static;
```


## To compile and run the examples from the AOCL-Cryptography installed directory:  
```bash
cd /path/to/amd-crypto;
export C_INCLUDE_PATH=$PWD/include:$C_INCLUDE_PATH;
make -j;
```

**Run the Examples:**  
`./bin/cipher/aes-cfb;`
