# Build and run AOCL-Cryptography examples

The example snippets can be found in the source code and the package under aocl-crypto/examples/

<b>An example [snippet](https://github.com/amd/aocl-crypto/blob/main/examples/cipher/aes-cfb.c) for AES CFB Cipher example</b><br>

To compile AOCL-Cryptography with examples, refer to
    - [ Linux ](md_Combine_build.html#md_BUILD)
    - [ Windows ](md_Combine_build.html#md_BUILD_Windows)

The examples executables for each module will be generated in aocl-crypto/build/examples/

<b>NOTE:</b><br>
The AOCL-Cryptography has a dependency on OpenSSL libcrypto library and also AOCL Utils library.
Please make sure the below paths are added to the environment variables 

<b>To run the examples on linux:</b><br>
Export the following paths:<br>
<code>
export LIBRARY_PATH=\<path to openssl crypto lib\>:$LIBRARY_PATH;<br>

export LIBRARY_PATH=\<path to AOCL Utils lib\>:$LIBRARY_PATH;<br>

export LD_LIBRARY_PATH=\<path to openssl crypto lib\>:$LD_LIBRARY_PATH;<br>

export LD_LIBRARY_PATH=\<path to AOCL Utils lib\>:$LD_LIBRARY_PATH;
</code>

Now to run any executable:<br>
<code>
./examples/cipher/aes-gcm;
</code>

<b>To run the examples on windows:</b><br>
Run the script:<br>
<code>
./scripts/Set_Env_Path.bat
</code>

Now to run any executable:<br>
<code>
.\examples\cipher\release\aes-gcm.exe
</code>

# Build and Run AOCL-Cryptography examples from the AOCL Crypto release package (Linux)

<b>Download the tar package from https://www.amd.com/en/developer/aocl/cryptography.html (under the downloads section) </b>

<b>NOTE:</b><br>
The AOCL-Cryptography library has a dependency on OpenSSL libcrypto library and also AOCL Utils library.
Please make sure these library paths are added to the environment variables LIBRARY_PATH and LD_LIBRARY_PATH

Also, please ensure the variable OPENSSL_INSTALL_DIR is set.<br>
<code>
export OPENSSL_INSTALL_DIR=\<path to openssl installation/lib64/\>;<br>
</code>

<b>To run the examples linking to AOCL-Cryptography shared library:</b><br>
<code>
export LIBRARY_PATH=\<path to openssl crypto lib\>:$LIBRARY_PATH;<br>

export LIBRARY_PATH=\<path to AOCL Utils lib\>:$LIBRARY_PATH;<br>

export LD_LIBRARY_PATH=\<path to openssl crypto lib\>:$LD_LIBRARY_PATH;<br>

export LD_LIBRARY_PATH=\<path to AOCL Utils lib\>:$LD_LIBRARY_PATH;<br>

cd amd-crypto;<br>

make;
</code>

<b>To run the examples linking to AOCL-Cryptography static library:</b><br>
<code>
cd amd-crypto;<br>

make LIB_TYPE=static;
</code>

# To compile and run the examples from the AOCL-Cryptography installed directory:
<code>
cd \<AOCL_Installation_Dir\>/amd-crypto/;<br>

export C_INCLUDE_PATH=\<AOCL_Installation_Dir\>/include/:$C_INCLUDE_PATH;<br>

make -j;
</code>

<b>Run the Examples:</b><br>
<code>
./bin/cipher/aes-gcm;<br>
</code>