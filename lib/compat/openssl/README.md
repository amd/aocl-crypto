# Instructions to Build/Use OpenSSL plugin
AOCL Cryptography's OpenSSL compat library works as an OpenSSL Provider which will redirect API calls from within OpenSSL to AOCL-Cryptography. Currently provider only supports OpenSSL versions from 3.1.3 to 3.3.0 .
The provider only works when the version of the OpenSSL used to compile provider is greater than or equal to the version of the openssl library currently being loaded. 
 
> <span style="color:red">__Note:__</span> Known issue with test_quick_multistream test

## Building

```
git clone <repo url> aocl-crypto
mkdir aocl-crypto/build
cd aocl-crypto/build
cmake -DOPENSSL_INSTALL_DIR= <path to openssl installation> -DAOCL_COMPAT_LIBS=openssl ../
cmake --build .
```

After running all the above commands you should see a `libopenssl-compat.so` in build directory.

To enable debug logging from within AOCL-Crypto OpenSSL provider, add `-DALCP_COMPAT_ENABLE_DEBUG=ON` during the cmake configuration.

## Usage Instructions

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
alcp  = alcp_sect
default = default_sect

[default_sect]
activate = 1

[alcp_sect]
module = /path/to/libopenssl-compat.so
activate = 1
```

To find out where openssl looks for `openssl.cnf`, type the command ```openssl info -configdir```.

You can also set OPENSSL_CONF environment variable with the full path to the openssl.cnf configured with AOCL-Cryptography openssl compat library as shown above. Thus its possible to use the compat library without modifying the existing openssl.cnf file.

To **Verify the OpenSSL provider has been succesfully loaded**, run ```openssl list -providers``` which should show the following output:

```
Providers:
  alcp
    version: AOCL-Crypto <aocl-crypto version> Build <Build id>
  default
    name: OpenSSL Default Provider
    version: <OpenSSL version>
    status: active
```
This indicates that AOCL-Cryptography OpenSSL compat library has been succesfully loaded.

## Optionally enabling/disabling OpenSSL Provider algorithms during compile time

Certain algorithms within provider are disabled and has to be enabled manually during compilation if required. It is also possible to disable any algorithms if needed.

Feature | Compiler Option|Default value|
:------:|:--------------:|:-----------:|
|Cipher|ALCP_COMPAT_ENABLE_OPENSSL_CIPHER|ON|
|Digest|ALCP_COMPAT_ENABLE_OPENSSL_DIGEST|ON|
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

Digest Algorithm | Compiler Option|Default value|
:------:|:--------------:|:-----------:|
|SHA2|ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA2|OFF|
|SHA3|ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA3|ON|
|SHAKE|ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHAKE|ON|

*MAC:*

MAC Algorithm | Compiler Option|Default value|
:------:|:--------------:|:-----------:|
|HMAC|ALCP_COMPAT_ENABLE_OPENSSL_MAC_HMAC|OFF|
|CMAC|ALCP_COMPAT_ENABLE_OPENSSL_MAC_CMAC|ON|
|POLY1305|ALCP_COMPAT_ENABLE_OPENSSL_MAC_POLY1305|ON|
