# Configuring OpenSSL

### Configuring provider to be loaded by default.

For more information please take a look at [this](https://www.openssl.org/docs/manmaster/man5/config.html). Modify or replace openssl.cnf with this.

```sh
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
alcp  = alcp_sect
default = default_sect
base = base_sect

[default_sect]
activate = 1

[alcp_sect]
module = /path/to/libopenssl-compat.so
activate = 1

[base_sect]
activate = 1
```

Above configuration will allow you to offload functionalities if supported by AOCL-Cryptography. OpenSSL will still dispatch to it's own implementation for ones we have not implemented yet.
To find out where openssl looks for `openssl.cnf`, type the command ```openssl info -configdir```.

### Code taking advantage of configuration

```c
#include <stdio.h>
#include <stdlib.h>

#include <openssl/provider.h>

int main(void)
{
    OSSL_PROVIDER *alcp_provider;
	
    // Will find the openssl provider shared object from configuration
    alcp_provider = OSSL_PROVIDER_load(NULL, "alcp");
    
    if (NULL == alcp_provider) {
        printf("Failed to load ALCP provider\n");
        exit(EXIT_FAILURE);
    }

    /* Rest of application */

    OSSL_PROVIDER_unload(alcp_provider);
    exit(EXIT_SUCCESS);
}
```

