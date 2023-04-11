# Instructions to Build/Use OpenSSL plugin


## Building

```
git clone <repo url> aocl-crypto
mkdir aocl-crypto/build
cd aocl-crypto/build
cmake -DAOCL_COMPAT_LIBS=openssl ../
cmake --build .
```

After running all the above commands you should see a `build/libopenssl-compat.so` in build directory.

## Usage Instructions

Please refer to `openssl.pdf` which is present in docs.

Summary is given below

### Benchmarking
​	To bench with the provider, use the following example assuming you are executing command from the root of the package directory.

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