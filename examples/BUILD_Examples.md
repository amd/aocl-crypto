# Build and Run Crypto Examples from the AOCL Crypto release package

## Build
Download the tar package from [amd-crypto](https://www.amd.com/en/developer/aocl/cryptography.html) (under the downloads section).

## NOTE:
The AOCL Crypto has a dependency on OpenSSL libcrypto library and also AOCL Utils library.
Please make sure the above library paths are added to the environment variable LIBRARY_PATH 

Also, please ensure the variable OPENSSL_INSTALL_DIR is set.
<code>
export OPENSSL_INSTALL_DIR=<path to openssl installation/lib64/>;<br>
</code>

To run the examples linking to AOCL Crypto shared library:
<code>
export LIBRARY_PATH=<path to AOCL Utils lib>:$LIBRARY_PATH;<br>
cd amd-crypto;<br>
make;<br>
export LD_LIBRARY_PATH=${PWD}/lib:<path to AOCL Utils lib>:${OPENSSL_INSTALL_DIR}:$LD_LIBRARY_PATH;<br>
</code>

To run the examples linking to AOCL Crypto static library:
<code>
cd amd-crypto;<br>
make LIB_TYPE=static;<br>
</code>

## NOTE:
To compile and run the examples from the AOCL installed directory
cd <AOCL_Installation_Dir>/amd-crypto/;
export C_INCLUDE_PATH=<AOCL_Installation_Dir>/include/$C_INCLUDE_PATH;
make -j;

## Run the Examples:
<code>
$PWD/bin/cipher/aes-speed-cipher;
</code>
