/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key encapsulation mechanism
*********************************************************************************************/


#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cpucycles.h"

#define JAYPAN_DEBUG

// Benchmark and test parameters
#if defined(OPTIMIZED_GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM)
    #define BENCH_LOOPS        5      // Number of iterations per bench
    #define TEST_LOOPS         5      // Number of iterations per test
#else
    #define BENCH_LOOPS       100
    #define TEST_LOOPS        10
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

int cryptotest_pke()
{ // Testing KEM
    unsigned int i;
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0};
    unsigned char m[CRYPTO_BYTES] = {0};
    unsigned char m_[CRYPTO_BYTES] = {0};
    bool passed = true;

    printf("\n\nTESTING ISOGENY-BASED PUBLIC KEY ENCRYPTION %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    snprintf((char*)m, CRYPTO_BYTES, "12345");

    for (i = 0; i < TEST_LOOPS; i++)
    {
        crypto_pke_keypair(pk, sk);
        crypto_pke_enc(ct, m, pk);
        crypto_pke_dec(m_, ct, sk);

        if (memcmp(m, m_, CRYPTO_BYTES) != 0) {
            passed = false;
            break;
        }
    }

    if (passed == true) printf("  PKE tests .................................................... PASSED");
    else { printf("  PKE tests ... FAILED"); printf("\n"); return FAILED; }
    printf("\n");

    return PASSED;
}

int cryptorun_pke()
{ // Benchmarking key exchange
    unsigned int n;
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0};
    unsigned char m[CRYPTO_BYTES] = {0};
    unsigned char m_[CRYPTO_BYTES] = {0};
    unsigned long long cycles, cycles1, cycles2;

    printf("\n\nBENCHMARKING ISOGENY-BASED PUBLIC KEY ENCRYPTION %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    // Benchmarking key generation
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        crypto_pke_keypair(pk, sk);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  Key generation runs in ....................................... %10lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // Benchmarking encapsulation
    snprintf((char*)m, CRYPTO_BYTES, "12345");
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        crypto_pke_enc(ct, m, pk);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  Encapsulation runs in ........................................ %10lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // Benchmarking decapsulation
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        crypto_pke_dec(m_, ct, sk);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  Decapsulation runs in ........................................ %10lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    return PASSED;
}

int mycryptotest_pke()
{ // Testing KEM
    unsigned int i;
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    bool passed = true;

    unsigned int encTimes = (strlen(TEST_JSON_PLAINTEXT) + 1) / CRYPTO_BYTES + 1;
    unsigned int myMsgLen = encTimes * CRYPTO_BYTES;
    unsigned int myCtLen = encTimes * CRYPTO_CIPHERTEXTBYTES;
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
            crypto_pke_enc(myCt + encdecIdx * CRYPTO_CIPHERTEXTBYTES, myMsg + encdecIdx * CRYPTO_BYTES, pk);
        }
#ifdef JAYPAN_DEBUG
		printf("after encrypt %s\n", (char*)myMsg);
#endif
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            crypto_pke_dec(myMsg_ + encdecIdx * CRYPTO_BYTES, myCt + encdecIdx * CRYPTO_CIPHERTEXTBYTES, sk);
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
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    bool passed = true;

    unsigned int encTimes = (strlen(TEST_JSON_PLAINTEXT) + 1) / CRYPTO_BYTES + 1;
    unsigned int myMsgLen = encTimes * CRYPTO_BYTES;
    unsigned int myCtLen = encTimes * CRYPTO_CIPHERTEXTBYTES;
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
            crypto_pke_enc(myCt + encdecIdx * CRYPTO_CIPHERTEXTBYTES, myMsg + encdecIdx * CRYPTO_BYTES, pk);
        }
#ifdef JAYPAN_DEBUG
		printf("after encrypt %s\n", (char*)myMsg);
#endif
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            crypto_pke_dec(myMsg_ + encdecIdx * CRYPTO_BYTES, myCt + encdecIdx * CRYPTO_CIPHERTEXTBYTES, sk);
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


int cryptotest_kem()
{ // Testing KEM
    unsigned int i;
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0};
    unsigned char ss[CRYPTO_BYTES] = {0};
    unsigned char ss_[CRYPTO_BYTES] = {0};
    bool passed = true;

    printf("\n\nTESTING ISOGENY-BASED KEY ENCAPSULATION MECHANISM %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    for (i = 0; i < TEST_LOOPS; i++)
    {
        crypto_kem_keypair(pk, sk);
        crypto_kem_enc(ct, ss, pk);
        crypto_kem_dec(ss_, ct, sk);

        if (memcmp(ss, ss_, CRYPTO_BYTES) != 0) {
            passed = false;
            break;
        }
    }

    if (passed == true) printf("  KEM tests .................................................... PASSED");
    else { printf("  KEM tests ... FAILED"); printf("\n"); return FAILED; }
    printf("\n");

    return PASSED;
}


int cryptorun_kem()
{ // Benchmarking key exchange
    unsigned int n;
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES] = {0};
    unsigned char ss[CRYPTO_BYTES] = {0};
    unsigned char ss_[CRYPTO_BYTES] = {0};
    unsigned long long cycles, cycles1, cycles2;

    printf("\n\nBENCHMARKING ISOGENY-BASED KEY ENCAPSULATION MECHANISM %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    // Benchmarking key generation
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        crypto_kem_keypair(pk, sk);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  Key generation runs in ....................................... %10lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // Benchmarking encapsulation
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        crypto_kem_enc(ct, ss, pk);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  Encapsulation runs in ........................................ %10lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    // Benchmarking decapsulation
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        crypto_kem_dec(ss_, ct, sk);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  Decapsulation runs in ........................................ %10lld ", cycles/BENCH_LOOPS); print_unit;
    printf("\n");

    return PASSED;
}


int main()
{
    int Status = PASSED;

/*     Status = cryptotest_pke();             // Test public key encryption */
    /* if (Status != PASSED) { */
        /* printf("\n\n   Error detected: KEM_ERROR_PKE \n\n"); */
        /* return FAILED; */
    /* } */

    Status = mycryptotest_pke();             // Test public key encryption
    if (Status != PASSED) {
        printf("\n\n   Error detected: KEM_ERROR_PKE \n\n");
        return FAILED;
    }

/*     Status = cryptorun_pke();             // Benchmark public key encryption */
    /* if (Status != PASSED) { */
        /* printf("\n\n   Error detected: KEM_ERROR_PKE \n\n"); */
        /* return FAILED; */
    /* } */

/*     Status = cryptotest_kem();             // Test key encapsulation mechanism */
    /* if (Status != PASSED) { */
        /* printf("\n\n   Error detected: KEM_ERROR_SHARED_KEY \n\n"); */
        /* return FAILED; */
    /* } */

    /* Status = cryptorun_kem();              // Benchmark key encapsulation mechanism */
    /* if (Status != PASSED) { */
        /* printf("\n\n   Error detected: KEM_ERROR_SHARED_KEY \n\n"); */
        /* return FAILED; */
    /* } */

    return Status;
}
