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


#define JAYPAN_DEBUG

// Benchmark and test parameters
#if defined(OPTIMIZED_GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM)
    #define BENCH_LOOPS        5      // Number of iterations per bench
    #define TEST_LOOPS         3      // Number of iterations per test
#else
    #define BENCH_LOOPS       100
    #define TEST_LOOPS        3
#endif
#define NTESTS TEST_LOOPS

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

	unsigned long long tkeygen[NTESTS], tsign[NTESTS], tverify[NTESTS];
	timing_overhead = cpucycles_overhead();

	if (NULL == (myMsg = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
		NULL == (myMsg_ = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
		NULL == (myCt = (unsigned char*)calloc(myCtLen, sizeof(unsigned char)))) {
		printf("Cannot get the memory\n");
		return FAILED;
	}
	printf("test for\n");

	printf("\n\nTESTING ISOGENY-BASED PUBLIC KEY ENCRYPTION %s\n", SCHEME_NAME);
	printf("--------------------------------------------------------------------------------------------------------\n\n");

	for (i = 0; i < NTESTS; i++)
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
			crypto_pke_enc(myCt + encdecIdx * CRYPTO_CIPHERTEXTBYTES, myMsg + encdecIdx * CRYPTO_BYTES, pk);
		}
		tsign[i] = cpucycles_stop() - tsign[i] - timing_overhead;

		printf("start decrypt\n");
		tverify[i] = cpucycles_start();
		for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
			crypto_pke_dec(myMsg_ + encdecIdx * CRYPTO_BYTES, myCt + encdecIdx * CRYPTO_CIPHERTEXTBYTES, sk);
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

	print_results("keygen:", tkeygen, NTESTS);
	print_results("sign: ", tsign, NTESTS);
	print_results("verify: ", tverify, NTESTS);

	return PASSED;
}

int main()
{
    int Status = PASSED;

    /* Status = mycryptotest_pke();             // Test public key encryption */
    /* if (Status != PASSED) { */
        /* printf("\n\n   Error detected: KEM_ERROR_PKE \n\n"); */
        /* return FAILED; */
    /* } */

    Status = mycryptorun_pke();             // Test public key encryption
    if (Status != PASSED) {
        printf("\n\n   Error detected: KEM_ERROR_PKE \n\n");
        return FAILED;
    }

    return Status;
}
