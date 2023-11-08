# Build and run AOCL-Cryptography examples

The example snippets can be found at aocl-crypto/examples/

## Example snippet for AES Cipher CFB
\include{lineno} cipher/aes-cfb.c

To compile AOCL-Cryptography with examples, refer to
    - [ Linux ](md_Combine_build.html#md_BUILD)
    - [ Windows ](md_Combine_build.html#md_BUILD_Windows)

The examples executables for each module will be generated in aocl-crypto/build/examples/

## NOTE:
The AOCL-Cryptography has a dependency on OpenSSL libcrypto library and also AOCL Utils library.
Please make sure the below paths are added to the environment variables 

## To run the examples on linux:
<code>
export LIBRARY_PATH=\<path to openssl lib path\>:$LIBRARY_PATH;<br>
export LIBRARY_PATH=\<path to AOCL Utils lib\>:$LIBRARY_PATH;<br>
export LD_LIBRARY_PATH=\<path to openssl lib path\>:$LD_LIBRARY_PATH;<br>
export LD_LIBRARY_PATH=\<path to AOCL Utils lib\>:$LD_LIBRARY_PATH;<br>
</code>

## To run AES-Cipher (GCM) example, run the executable:
<code>
./examples/cipher/aes-gcm;
</code>

## To run the examples on windows:
Run the script aocl-crypto/scripts/Set_Env_Path.bat

## To run AES-Cipher (GCM) example, run the executable:
<code>
.\examples\cipher\release\aes-gcm.exe
</code>

# Build and Run Crypto Examples from the AOCL Crypto release package

## Build
<b>Download the tar package from https://www.amd.com/en/developer/aocl/cryptography.html (under the downloads section)</b>

## NOTE:
The AOCL Crypto has a dependency on OpenSSL libcrypto library and also AOCL Utils library.
Please make sure the above library paths are added to the environment variable LIBRARY_PATH 

Also, please ensure the variable OPENSSL_INSTALL_DIR is set.
<code>
export OPENSSL_INSTALL_DIR=\<path to openssl installation/lib64/\>;<br>
</code>

To run the examples linking to AOCL Crypto shared library:
<code>
export LIBRARY_PATH=\<path to AOCL Utils lib\>:$LIBRARY_PATH;<br>
cd amd-crypto;<br>
make;<br>
export LD_LIBRARY_PATH=${PWD}/lib:\<path to AOCL Utils lib\>:${OPENSSL_INSTALL_DIR}:$LD_LIBRARY_PATH;<br>
</code>

To run the examples linking to AOCL Crypto static library:
<code>
cd amd-crypto;<br>
make LIB_TYPE=static;<br>
</code>

## NOTE:
To compile and run the examples from the AOCL installed directory
<code>
cd \<AOCL_Installation_Dir\>/amd-crypto/;<br>
export C_INCLUDE_PATH=\<AOCL_Installation_Dir\>/include/:$C_INCLUDE_PATH;<br>
make -j;<br>
</code>

## Run the Examples:
<code>
$PWD/bin/cipher/aes-speed-cipher;<br>
</code>