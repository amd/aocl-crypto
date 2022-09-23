//#include <assert.h>

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "ippcp.h"

#define CIPHER_IV_LENGTH_BYTE 16
#define CFB_BLOCK             16

static double
seconds(void)
{
    volatile double d;
    struct timeval  tv;
    // int sts;
    gettimeofday(&tv, NULL);
    //      assert(sts == 0);
    //      assert(tv.tv_usec < 1000000);
    d = (double)tv.tv_sec + (double)tv.tv_usec * 1.0e-6;
    return d;
}

void
get_rand(int* rand_array, int size)
{
    static int seeded = 0;
    int        i;

    if (!seeded) {
        int seed       = 0;
        int dev_random = open("/dev/urandom", O_RDONLY);
        if (dev_random < 0) {
            // something went wrong
        } else {
            unsigned short seed[3];
            read(dev_random, seed, sizeof(seed));
        }
        srand(*(int*)&seed);
        seeded = 1;
    }

    for (i = 0; i < size; i++)
        rand_array[i] = i;

    for (i = size; i > 0; i--) {
        // int pos, tmp;
        rand_array[i] = rand();
        // pos = rand();
        // tmp = rand_array[i-1];
        // rand_array[i-1] = rand_array[pos];
        // rand_array[pos] = tmp;
    }
}

// void handleErrors(void)
//{
//  ERR_print_errors_fp(stderr);
//  abort();
//}
int debug = 0;

void
print_data(const Uint8* data, int len)
{
    int* bp = (int*)data;
    for (int k = 0; k < (len / 4); k++)
        printf("%x", bp[k]);
    printf("\n");
}

struct _config
{
    int    fill_rand;
    int    num_buf;
    int    count;
    int    data_len;
    int    random_key;
    int    random_plaintxt;
    int    random_ciphertxt;
    int    debug;
    double run_target;
} config = {
    .fill_rand        = 0,
    .num_buf          = 1,
    .count            = 1,
    .data_len         = 1024 * 1024,
    .random_key       = 0,
    .random_plaintxt  = 0,
    .random_ciphertxt = 0,
    .debug            = 1,
    .run_target       = 10.0,
};

void
parse_args(int argc, char* argv[])
{
    double run_target = 10.0;

    if (argc >= 3) {
        config.num_buf = atoi(argv[2]);
    }
    if (argc >= 4) {
        config.data_len = atoi(argv[3]);
    }
    if (argc >= 5) {
        config.count = atoi(argv[4]);
    }
    if (argc >= 6) {
        run_target = atof(argv[5]);
    }
    if (argc >= 7) {
        config.debug = atoi(argv[6]);
    }

    return;
}

void
encrypt_demo(const Ipp8u* plaintxt,
             Ipp8u*       ciphertxt,
             int          datalen,
             int          cfb_block,
             IppsAESSpec* aesCtx,
             const Ipp8u* iv)
{
    IppStatus status;

    status = ippsAESEncryptCFB(
        plaintxt, ciphertxt, datalen, cfb_block, aesCtx, (const Ipp8u*)iv);

    if (status != 0) {
        printf("failed to enc\n");
        exit(1);
    }
}

const Uint8 sample_key[] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                             0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

const Uint8 sample_iv[CIPHER_IV_LENGTH_BYTE] = {
    0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8,
    0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0,
};

int
main(int argc, char* argv[])
{
    int num_buf = config.num_buf;
    // int count      = config.count;
    int datalen    = config.data_len;
    int debug      = config.debug;
    int keylen     = sizeof(sample_key);
    int ivlen      = sizeof(sample_iv);
    int run_target = config.run_target;

    printf("Decryption test for CFB, unit buf size: %d, buf num: %d, debug: "
           "%d\n",
           datalen,
           num_buf,
           debug);

    IppStatus status;
    if (0) {
        void print_ipp_features(void);
        print_ipp_features();
    }

    // 128 bit enc key
    Uint8* iv       = calloc(ivlen, 1);
    Uint8* key      = calloc(keylen, 1);
    Uint8* cipertxt = calloc(datalen, num_buf);
    Uint8* output   = calloc(datalen, num_buf);
    int    destlen  = datalen;

    memcpy(key, sample_key, keylen);
    memcpy(iv, sample_iv, ivlen);

    if (config.random_key) {
        Uint8* enc_key = key;
        get_rand((int*)enc_key, keylen / 4);
        printf("Created random key:\n");
    }

    print_data(key, keylen / 4);

    int          aesCtxSize = 0;
    void*        aesCtxBuf  = NULL;
    IppsAESSpec* aesCtx     = NULL;

    { /* Init */
        // new CFB
        status    = ippsAESGetSize(&aesCtxSize);
        aesCtxBuf = malloc(aesCtxSize);
        aesCtx    = (IppsAESSpec*)aesCtxBuf;
        status    = ippsAESInit((Ipp8u*)key, keylen, aesCtx, aesCtxSize);
    }

    /*
     *  PLAINTEXT, override for demo
     */
    // const char* plaintxt = "Hello World from AOCL Crypto !!!";
    const char* plaintxt = "Happy and Fantastic New Year from AOCL Crypto !!";
    datalen              = strlen(plaintxt);
    num_buf              = 1;

    if (config.random_plaintxt) {
        // initialize the random arrays
        plaintxt = calloc(datalen, num_buf);

        Uint8* tmpBuf = (Uint8*)plaintxt;
        for (int j = 0; j < num_buf; j++) {
            get_rand((int*)tmpBuf, (datalen) / 4);
            tmpBuf += datalen;
        }
        printf("Created random plaintxt.\n");
    }

    // encryption first and then do decrption in a loop
    for (int j = 0; j < num_buf; j++) {
        Uint8* cipher = cipertxt;
        destlen       = datalen;

        encrypt_demo((Uint8*)plaintxt, cipher, destlen, CFB_BLOCK, aesCtx, iv);

        if (debug) {
            printf("After enc data [%d]:\n", j);
            print_data(cipher, datalen);
        }

        if ((j + 1) < num_buf) {
            plaintxt += datalen;
            cipher += datalen;
        }
    }

    long double delta = 0;
    int         index = 0;
    long        cnt   = 0;

    struct timespec t1, t2;
    double          starttime = seconds();
    double          stoptime  = seconds();

    long double totalSizeByte = 0;

    clock_gettime(CLOCK_REALTIME, &t1);
    while (run_target > (stoptime - starttime)) {
        // wrap around
        if (index >= num_buf) {
            index = 0;
        }
        //      int index = i;// randomIndex[i];
        Uint8* cipher   = (cipertxt + (datalen * index));
        Uint8* dest_new = (output + (datalen * index));

        status = ippsAESDecryptCFB((Ipp8u*)cipher,
                                   (Ipp8u*)dest_new, // dest,
                                   datalen,
                                   CFB_BLOCK,
                                   aesCtx,
                                   (const Ipp8u*)iv);
        if (status != 0) {
            printf("failed to dec\n");
            exit(1);
        }

        if (debug) {
            printf("\nVerifying data [%d]: ", index);
            Uint8* plntxt = (Uint8*)plaintxt + (index * datalen);
            Uint8* out    = dest_new;
            if (memcmp(plntxt, out, datalen)) {
                printf("\n");
                print_data(plntxt, 20);
                print_data(out, 20);
                printf("Data did not match\n");
            } else {
                printf("All good\n");
            }
        }

        totalSizeByte += (long double)datalen;
        index++;
        cnt++;
        //      gettimeofday(&stop_tv, 0);
        stoptime = seconds();
    } // count

    clock_gettime(CLOCK_REALTIME, &t2);
    delta = t2.tv_sec * 1000000000 + t2.tv_nsec - t1.tv_sec * 1000000000
            - t1.tv_nsec;
    //    stoptime = seconds();
    double runningTimeInSec = (double)delta / (double)1000000000;
    //    (stop_tv.tv_sec - start_tv.tv_sec);
    //    stoptime - starttime;//(double)deltat/(double)1000000000;
    double avgLatency =
        runningTimeInSec / ((double)cnt); //((double)(loopcnt*count));
    //    long double totalSizeByte = (long double)datalen*(long
    //    double)loopcnt*(long double)count;
    long double bytesProcessedPerSec = totalSizeByte / runningTimeInSec;
    long double MBPerSec = bytesProcessedPerSec / (long double)(1024 * 1024);
    printf("\n\ntotal time: %fs (%Lf), data unit size: %dbyte, total bytes "
           "processed: %Lf,"
           " avg time to process one unit:%f s, MB processed per sec:%Lf\n",
           runningTimeInSec,
           delta,
           datalen,
           totalSizeByte,
           avgLatency,
           MBPerSec);

    if (config.random_plaintxt)
        free(plaintxt);

    free(cipertxt);
    free(output);
    return 0;
}
