# Instructions to Build/Use OpenSSL plugin


## Building

```
git clone <repo url> aocl-crypto
mkdir aocl-crypto/build
cd aocl-crypto/build
cmake -DAOCL_COMPAT_LIBS=openssl ../
cmake --build .
```

After running all the above commands you should see a `libopenssl-compat.so` in build directory.

## Usage Instructions

Please refer to `openssl.pdf` which is present in docs.

Summary is given below

### Benchmarking
​   To bench using provider path, use the following example assuming you are executing command from the root of the package directory.

​	```openssl speed -provider-path $PWD/lib  -provider libopenssl-compat -evp aes-128-gcm```

### Using provider in a C program

Instructions to use provider in a C program is given in [this link](https://github.com/openssl/openssl/blob/master/README-PROVIDERS.md)

```c
#include <stdio.h>
#include <stdlib.h>

#include <openssl/provider.h>

int main(void)
{
    OSSL_PROVIDER *alcp_provider;

	OSSL_PROVIDER_set_default_search_path("/path/to/alcp/lib")

    alcp_provider = OSSL_PROVIDER_load(NULL, "libopenssl-compat");
    if (NULL == alcp_provider) {
        printf("Failed to load ALCP provider\n");
        exit(EXIT_FAILURE);
    }

    /* Rest of application */

    OSSL_PROVIDER_unload(alcp_provider);
    exit(EXIT_SUCCESS);
}
```
### Configuring provider to be loaded by default.

For more information please take a look at [this](https://www.openssl.org/docs/manmaster/man5/config.html). Modify or replace openssl.cnf with this.

```sh
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
alcp  = alcp_sect

[default_sect]

[alcp_sect]
module = /path/to/libopenssl-compat.so
activate = 1
```

To find out where openssl looks for `openssl.cnf`, type the command ```openssl info -configdir```.

## Optionally enabling/disabling OpenSSL Provider algorithms during compile time

Certain algorithms within provider are disabled and has to be enabled manually during compilation if required. It is also possible to disable any algorithms if needed.

Feature | Compiler Option|Default value|
:------:|:--------------:|:-----------:|
|Cipher|ALCP_COMPAT_ENABLE_OPENSSL_CIPHER|ON|
|Digest|ALCP_COMPAT_ENABLE_OPENSSL_DIGEST|OFF|
|MAC   |ALCP_COMPAT_ENABLE_OPENSSL_MAC   |ON|
|RSA   | ALCP_COMPAT_ENABLE_OPENSSL_RSA  |ON|

Within each module it is possible to disable sub algorithms as well:

*Ciphers:*

Cipher Algorithm | Compiler Option|Default value|
:------:|:--------------:|:-----------:|
|AES-CBC|ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CBC|OFF|
|AES-OFB|ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_OFB|ON|
|AES-CFB|ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CFB|ON|
|AES-CTR|ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CTR|ON|
|AES-XTS|ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_XTS|ON|
|AES-GCM|ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_GCM|ON|
|AES-CCM|ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CCM|OFF|
|AES-SIV|ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_SIV|ON|

*Digests:*

Since ALCP_COMPAT_ENABLE_OPENSSL_DIGEST is OFF by default, first set ALCP_COMPAT_ENABLE_OPENSSL_DIGEST=ON in conjuction with the below flags.

Digest Algorithm | Compiler Option|Default value|
:------:|:--------------:|:-----------:|
|SHA2|ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA2|ON|
|SHA3|ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA3|ON|
|SHAKE|ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHAKE|ON|

*MAC:*

MAC Algorithm | Compiler Option|Default value|
:------:|:--------------:|:-----------:|
|HMAC|ALCP_COMPAT_ENABLE_OPENSSL_MAC_HMAC|OFF|
|CMAC|ALCP_COMPAT_ENABLE_OPENSSL_MAC_CMAC|ON|
|POLY1305|ALCP_COMPAT_ENABLE_OPENSSL_MAC_POLY1305|ON|
