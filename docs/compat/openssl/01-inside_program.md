# Using provider in a C program

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

[OSSL_PROVIDER_set_default_search_path](https://www.openssl.org/docs/man3.0/man3/OSSL_PROVIDER_set_default_search_path.html) - Where OpenSSL searches for the provider binary.

[OSSL_PROVIDER_load](https://www.openssl.org/docs/man3.0/man3/OSSL_PROVIDER_load.html) - Name of the provider to load.

[OSSL_PROVIDER_unload](https://www.openssl.org/docs/manmaster/man3/OSSL_PROVIDER_unload.html) - Unload the named provider.