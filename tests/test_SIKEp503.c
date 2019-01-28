/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key encapsulation mechanism SIKEp503
*********************************************************************************************/

#include <stdio.h>
#include <string.h>
#include "test_extras.h"
#include "../src/P503/P503_api.h"


#define SCHEME_NAME    "SIKEp503"

#define crypto_pke_keypair            crypto_pke_keypair_SIKEp503
#define crypto_pke_enc                crypto_pke_enc_SIKEp503
#define crypto_pke_dec                crypto_pke_dec_SIKEp503
#define crypto_kem_keypair            crypto_kem_keypair_SIKEp503
#define crypto_kem_enc                crypto_kem_enc_SIKEp503
#define crypto_kem_dec                crypto_kem_dec_SIKEp503

#include "test_sike.c"
