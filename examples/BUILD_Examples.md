# Build and Run Crypto Examples from the AOCL Crypto release package

## Build
Download the tar package from [amd-crypto](https://developer.amd.com/amd-aocl/aocl-cryptography/) (under the downloads section).

<code>
cd amd-crypto;<br>
make;<br>
export LD_LIBRARY_PATH=$PWD/lib:$LD_LIBRARY_PATH;<br>
</code>

## NOTE:
To compile and run the examples from the AOCL installed directory
cd <AOCL_Installation_Dir>/amd-crypto/;
export C_INCLUDE_PATH=<AOCL_Installation_Dir>/include/$C_INCLUDE_PATH;
make -j;

## Run the Examples:
<code>
$PWD/bin/cipher/aes-demo;
</code>
