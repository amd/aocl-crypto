# Configuring OpenSSL

### Configuring provider to be loaded by default.

For more information please take a look at [this](https://www.openssl.org/docs/manmaster/man5/config.html). Modify or replace openssl.cnf with this.

```sh
openssl_conf = provider_sect

[provider_sect]
default = default_sect
alcp  = alcp_sect

[default_sect]

[alcp_sect]
module = /path/to/libopenssl-compat.so
activate = 1
```

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

