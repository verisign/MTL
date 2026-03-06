/*
    Copyright (c) 2026, VeriSign, Inc.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted (subject to the limitations in the disclaimer
    below) provided that the following conditions are met:

        * Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.

        * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

        * Neither the name of the copyright holder nor the names of its
        contributors may be used to endorse or promote products derived from this
        software without specific prior written permission.

    NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
    THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
    CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
    PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
    IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef __MTL_LIB_SCHEMES_H__
#define __MTL_LIB_SCHEMES_H__

#include <stddef.h>
#include <stdint.h>
#include "mtllib.h"

// Flag definition that indicates if randomization is desired.
// Note: This is set when SPHNICS+ is built with liboqs so it must match


MTL_ALGORITHM_PROPS sig_algos[] = {
    {"SLH-DSA-SHAKE-128s-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_shake_128s_simple},
    {"SLH-DSA-SHAKE-128f-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_shake_128f_simple},
    {"SLH-DSA-SHAKE-192s-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_shake_192s_simple},
    {"SLH-DSA-SHAKE-192f-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_shake_192f_simple},
    {"SLH-DSA-SHAKE-256s-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_shake_256s_simple},
    {"SLH-DSA-SHAKE-256f-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_shake_256f_simple},
    {"SLH-DSA-SHA2-128s-MTL-SHA2-128", 16, '\0', HASH_SHA2, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_sha2_128s_simple},
    {"SLH-DSA-SHA2-128f-MTL-SHA2-128", 16, '\0', HASH_SHA2, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_sha2_128f_simple},
    {"SLH-DSA-SHA2-192s-MTL-SHA2-192", 24, '\0', HASH_SHA2, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_sha2_192s_simple},
    {"SLH-DSA-SHA2-192f-MTL-SHA2-192", 24, '\0', HASH_SHA2, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_sha2_192f_simple},
    {"SLH-DSA-SHA2-256s-MTL-SHA2-256", 32, '\0', HASH_SHA2, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_sha2_256s_simple},
    {"SLH-DSA-SHA2-256f-MTL-SHA2-256", 32, '\0', HASH_SHA2, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_sphincs_sha2_256f_simple},
    {"ML-DSA-44-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_ml_dsa_44},
    {"ML-DSA-65-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_ml_dsa_65},
    {"ML-DSA-87-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_ml_dsa_87},
    //{"Falcon-512-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_falcon_512},
    {"Falcon-padded-512-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_falcon_padded_512},
    //{"Falcon-1024-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_falcon_1024},
    {"Falcon-padded-1024-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_falcon_padded_1024},
    {"MAYO-1-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_mayo_1},
    {"MAYO-2-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_mayo_2},
    {"MAYO-3-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_mayo_3},
    {"MAYO-5-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_mayo_5},
    {"cross-rsdp-128-balanced-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdp_128_balanced},
    {"cross-rsdp-128-fast-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdp_128_fast},
    {"cross-rsdp-128-small-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdp_128_small},
    {"cross-rsdp-192-balanced-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdp_192_balanced},
    {"cross-rsdp-192-fast-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdp_192_fast},
    {"cross-rsdp-192-small-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdp_192_small},
    {"cross-rsdp-256-balanced-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdp_256_balanced},
    {"cross-rsdp-256-fast-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdp_256_fast},
    {"cross-rsdp-256-small-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdp_256_small},
    {"cross-rsdpg-128-balanced-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdpg_128_balanced},
    {"cross-rsdpg-128-fast-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdpg_128_fast},
    {"cross-rsdpg-128-small-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdpg_128_small},
    {"cross-rsdpg-192-balanced-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdpg_192_balanced},
    {"cross-rsdpg-192-fast-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdpg_192_fast},
    {"cross-rsdpg-192-small-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdpg_192_small},
    {"cross-rsdpg-256-balanced-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdpg_256_balanced},
    {"cross-rsdpg-256-fast-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdpg_256_fast},
    {"cross-rsdpg-256-small-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_cross_rsdpg_256_small},
    {"OV-Is-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_Is},
    {"OV-Ip-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_Ip},
    {"OV-III-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_III},
    {"OV-V-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_V},
    {"OV-Is-pkc-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_Is_pkc},
    {"OV-Ip-pkc-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_Ip_pkc},
    {"OV-III-pkc-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_III_pkc},
    {"OV-V-pkc-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_V_pkc},
    {"OV-Is-pkc-skc-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_Is_pkc_skc},
    {"OV-Ip-pkc-skc-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_Ip_pkc_skc},
    {"OV-III-pkc-skc-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_III_pkc_skc},
    {"OV-V-pkc-skc-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_uov_ov_V_pkc_skc},
    {"SNOVA_24_5_4-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_24_5_4},
    {"SNOVA_24_5_4_SHAKE-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_24_5_4_SHAKE},
    {"SNOVA_24_5_4_esk-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_24_5_4_esk},
    {"SNOVA_24_5_4_SHAKE_esk-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_24_5_4_SHAKE_esk},
    {"SNOVA_37_17_2-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_37_17_2},
    {"SNOVA_25_8_3-MTL-SHAKE-128", 16, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_25_8_3},
    {"SNOVA_56_25_2-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_56_25_2},
    {"SNOVA_49_11_3-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_49_11_3},
    {"SNOVA_37_8_4-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_37_8_4},
    {"SNOVA_24_5_5-MTL-SHAKE-192", 24, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_24_5_5},
    {"SNOVA_60_10_4-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_60_10_4},
    {"SNOVA_29_6_5-MTL-SHAKE-256", 32, '\0', HASH_SHAKE, RANDOMIZER_SAMPLED , LIBOQS, OQS_SIG_alg_snova_SNOVA_29_6_5},
    {NULL, 0, '\0', HASH_NONE, RANDOMIZER_PRF, NONE, ""}};

#endif // __MTL_SCHEMES_H__
