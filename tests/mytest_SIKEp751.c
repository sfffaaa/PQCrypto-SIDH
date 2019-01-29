/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key encapsulation mechanism
*********************************************************************************************/


#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mytest/cpucycles.h"
#include "mytest/speed.h"
#include "test_extras.h"
#include "../src/P751/P751_api.h"

#define SCHEME_NAME    "SIKEp751"

#define crypto_pke_keypair            crypto_pke_keypair_SIKEp751
#define crypto_pke_enc                crypto_pke_enc_SIKEp751
#define crypto_pke_dec                crypto_pke_dec_SIKEp751
#define crypto_kem_keypair            crypto_kem_keypair_SIKEp751
#define crypto_kem_enc                crypto_kem_enc_SIKEp751
#define crypto_kem_dec                crypto_kem_dec_SIKEp751

#define MYCRYPTO_SK_LENGTH CRYPTO_SECRETKEYBYTES
#define MYCRYPTO_PK_LENGTH CRYPTO_PUBLICKEYBYTES
#define MYCRYPTO_MSG_LENGTH CRYPTO_BYTES
#define MYCRYPTO_CIPHER_MSG_LENGTH CRYPTO_CIPHERTEXTBYTES


#define JAYPAN_DEBUG

// Benchmark and test parameters
#if defined(OPTIMIZED_GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM)
    #define BENCH_LOOPS        5      // Number of iterations per bench
    #define TEST_LOOPS         50      // Number of iterations per test
#else
    #define BENCH_LOOPS       100
    #define TEST_LOOPS        50
#endif

#define TEST_JSON_PLAINTEXT "{\n" \
"        body: {\n" \
"                \"from\": \"pub_key_generated_by_library_in_testing_1\",\n" \
"                \"to\": \"pub_key_generated_by_library_in_testing_2\",\n" \
"                \"amount\": 3,1415,\n" \
"                \"itemHash\": \"bdad5ccb7a52387f5693eaef54aeee6de73a6ada7acda6d93a665abbdf954094\"\n" \
"                \"seed\": \"2953135335240383704\"\n" \
"        },\n" \
"        \"fee\": 0,7182,\n" \
"        \"network_id\": 7,\n" \
"        \"protocol_version\": 0,\n" \
"        \"service_id\": 5,\n" \
"}"

unsigned long long timing_overhead;

int mycryptotest_pke()
{ // Testing KEM
    unsigned int i;
    unsigned char sk[MYCRYPTO_SK_LENGTH] = {0};
    unsigned char pk[MYCRYPTO_PK_LENGTH] = {0};
    bool passed = true;

    unsigned int encTimes = (strlen(TEST_JSON_PLAINTEXT) + 1) / MYCRYPTO_MSG_LENGTH + 1;
    unsigned int myMsgLen = encTimes * MYCRYPTO_MSG_LENGTH;
    unsigned int myCtLen = encTimes * MYCRYPTO_CIPHER_MSG_LENGTH;
    unsigned int encdecIdx = 0;

    unsigned char* myMsg = NULL;
    unsigned char* myMsg_ = NULL;
    unsigned char* myCt = NULL;

    if (NULL == (myMsg = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myMsg_ = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myCt = (unsigned char*)calloc(myCtLen, sizeof(unsigned char)))) {
        printf("Cannot get the memory\n");
        return FAILED;
    }

    printf("\n\nTESTING ISOGENY-BASED PUBLIC KEY ENCRYPTION %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    for (i = 0; i < TEST_LOOPS; i++)
    {
        memset(myMsg, 0, myMsgLen);
        memset(myMsg_, 0, myMsgLen);
        memset(myCt, 0, myCtLen);

        snprintf((char*)myMsg, myMsgLen, TEST_JSON_PLAINTEXT);

#ifdef JAYPAN_DEBUG
        printf("start test %d\n", i);
#endif
        crypto_pke_keypair(pk, sk);
#ifdef JAYPAN_DEBUG
        printf("start encrypt\n");
#endif
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            crypto_pke_enc(myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH, myMsg + encdecIdx * MYCRYPTO_MSG_LENGTH, pk);
        }
#ifdef JAYPAN_DEBUG
        printf("after encrypt %s\n", (char*)myMsg);
#endif
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            crypto_pke_dec(myMsg_ + encdecIdx * MYCRYPTO_MSG_LENGTH, myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH, sk);
        }
#ifdef JAYPAN_DEBUG
        printf("after decrypt %s\n", (char*)myMsg_);
#endif

        if (memcmp(myMsg, myMsg_, myMsgLen) != 0) {
            passed = false;
            break;
        }
    }

    if (myMsg) {
        free(myMsg);
    }
    if (myMsg_) {
        free(myMsg_);
    }
    if (myCt) {
        free(myCt);
    }

    if (passed == true) printf("  PKE tests .................................................... PASSED");
    else { printf("  PKE tests ... FAILED"); printf("\n"); return FAILED; }
    printf("\n");


    return PASSED;
}

int mycryptorun_pke()
{ // Testing KEM
    unsigned int i;
    unsigned char sk[MYCRYPTO_SK_LENGTH] = {0};
    unsigned char pk[MYCRYPTO_PK_LENGTH] = {0};
    bool passed = true;

    unsigned int encTimes = (strlen(TEST_JSON_PLAINTEXT) + 1) / MYCRYPTO_MSG_LENGTH + 1;
    unsigned int myMsgLen = encTimes * MYCRYPTO_MSG_LENGTH;
    unsigned int myCtLen = encTimes * MYCRYPTO_CIPHER_MSG_LENGTH;
    unsigned int encdecIdx = 0;

    unsigned char* myMsg = NULL;
    unsigned char* myMsg_ = NULL;
    unsigned char* myCt = NULL;

    unsigned long long tkeygen[TEST_LOOPS], tsign[TEST_LOOPS], tverify[TEST_LOOPS];
    timing_overhead = cpucycles_overhead();

    if (NULL == (myMsg = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myMsg_ = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myCt = (unsigned char*)calloc(myCtLen, sizeof(unsigned char)))) {
        printf("Cannot get the memory\n");
        return FAILED;
    }

    printf("\n\nTESTING ISOGENY-BASED PUBLIC KEY ENCRYPTION %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    for (i = 0; i < TEST_LOOPS; i++)
    {
        memset(myMsg, 0, myMsgLen);
        memset(myMsg_, 0, myMsgLen);
        memset(myCt, 0, myCtLen);

        snprintf((char*)myMsg, myMsgLen, TEST_JSON_PLAINTEXT);

        printf("start genkey\n");
        tkeygen[i] = cpucycles_start();
        crypto_pke_keypair(pk, sk);
        tkeygen[i] = cpucycles_stop() - tkeygen[i] - timing_overhead;

        printf("start encrypt\n");
        tsign[i] = cpucycles_start();
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            crypto_pke_enc(myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH, myMsg + encdecIdx * MYCRYPTO_MSG_LENGTH, pk);
        }
        tsign[i] = cpucycles_stop() - tsign[i] - timing_overhead;

        printf("start decrypt\n");
        tverify[i] = cpucycles_start();
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            crypto_pke_dec(myMsg_ + encdecIdx * MYCRYPTO_MSG_LENGTH, myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH, sk);
        }
        tverify[i] = cpucycles_stop() - tverify[i] - timing_overhead;

        if (memcmp(myMsg, myMsg_, myMsgLen) != 0) {
            passed = false;
            break;
        }
    }

    if (myMsg) {
        free(myMsg);
    }
    if (myMsg_) {
        free(myMsg_);
    }
    if (myCt) {
        free(myCt);
    }

    if (passed == true) printf("  PKE tests .................................................... PASSED");
    else { printf("  PKE tests ... FAILED"); printf("\n"); return FAILED; }
    printf("\n");

    print_results("keygen:", tkeygen, TEST_LOOPS);
    print_results("sign: ", tsign, TEST_LOOPS);
    print_results("verify: ", tverify, TEST_LOOPS);
	printf("average length: %u\n", myCtLen);

    return PASSED;
}

int main()
{
    int Status = PASSED;

    Status = mycryptotest_pke();             // Test public key encryption
    if (Status != PASSED) {
        printf("\n\n   Error detected: KEM_ERROR_PKE \n\n");
        return FAILED;
    }

    Status = mycryptorun_pke();             // Test public key encryption
    if (Status != PASSED) {
        printf("\n\n   Error detected: KEM_ERROR_PKE \n\n");
        return FAILED;
    }

    return Status;
}
