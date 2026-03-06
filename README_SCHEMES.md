# MTL SCHEMES
The following signature schemes are supported by this library:

## Supported algorithm strings
* SLH-DSA-SHAKE-128s-MTL-SHAKE-128
* SLH-DSA-SHAKE-128f-MTL-SHAKE-128
* SLH-DSA-SHAKE-192s-MTL-SHAKE-192
* SLH-DSA-SHAKE-192f-MTL-SHAKE-192
* SLH-DSA-SHAKE-256s-MTL-SHAKE-256
* SLH-DSA-SHAKE-256f-MTL-SHAKE-256
* SLH-DSA-SHA2-128s-MTL-SHA2-128
* SLH-DSA-SHA2-128f-MTL-SHA2-128
* SLH-DSA-SHA2-192s-MTL-SHA2-192
* SLH-DSA-SHA2-192f-MTL-SHA2-192
* SLH-DSA-SHA2-256s-MTL-SHA2-256
* SLH-DSA-SHA2-256f-MTL-SHA2-256
* ML-DSA-44-MTL-SHAKE-128
* ML-DSA-65-MTL-SHAKE-192
* ML-DSA-87-MTL-SHAKE-256
* Falcon-padded-512-MTL-SHAKE-128
* Falcon-padded-1024-MTL-SHAKE-256
* MAYO-1-MTL-SHAKE-128
* MAYO-2-MTL-SHAKE-128
* MAYO-3-MTL-SHAKE-192
* MAYO-5-MTL-SHAKE-256
* cross-rsdp-128-balanced-MTL-SHAKE-128
* cross-rsdp-128-fast-MTL-SHAKE-128
* cross-rsdp-128-small-MTL-SHAKE-128
* cross-rsdp-192-balanced-MTL-SHAKE-192
* cross-rsdp-192-fast-MTL-SHAKE-192
* cross-rsdp-192-small-MTL-SHAKE-192
* cross-rsdp-256-balanced-MTL-SHAKE-256
* cross-rsdp-256-fast-MTL-SHAKE-256
* cross-rsdp-256-small-MTL-SHAKE-256
* cross-rsdpg-128-balanced-MTL-SHAKE-128
* cross-rsdpg-128-fast-MTL-SHAKE-128
* cross-rsdpg-128-small-MTL-SHAKE-128
* cross-rsdpg-192-balanced-MTL-SHAKE-192
* cross-rsdpg-192-fast-MTL-SHAKE-192
* cross-rsdpg-192-small-MTL-SHAKE-192
* cross-rsdpg-256-balanced-MTL-SHAKE-256
* cross-rsdpg-256-fast-MTL-SHAKE-256
* cross-rsdpg-256-small-MTL-SHAKE-256
* OV-Is-MTL-SHAKE-128
* OV-Ip-MTL-SHAKE-128
* OV-III-MTL-SHAKE-192
* OV-V-MTL-SHAKE-256
* OV-Is-pkc-MTL-SHAKE-128
* OV-Ip-pkc-MTL-SHAKE-128
* OV-III-pkc-MTL-SHAKE-192
* OV-V-pkc-MTL-SHAKE-256
* OV-Is-pkc-skc-MTL-SHAKE-128
* OV-Ip-pkc-skc-MTL-SHAKE-128
* OV-III-pkc-skc-MTL-SHAKE-192
* OV-V-pkc-skc-MTL-SHAKE-256
* SNOVA_24_5_4-MTL-SHAKE-128
* SNOVA_24_5_4_SHAKE-MTL-SHAKE-128
* SNOVA_24_5_4_esk-MTL-SHAKE-128
* SNOVA_24_5_4_SHAKE_esk-MTL-SHAKE-128
* SNOVA_37_17_2-MTL-SHAKE-128
* SNOVA_25_8_3-MTL-SHAKE-128
* SNOVA_56_25_2-MTL-SHAKE-192
* SNOVA_49_11_3-MTL-SHAKE-192
* SNOVA_37_8_4-MTL-SHAKE-192
* SNOVA_24_5_5-MTL-SHAKE-192
* SNOVA_60_10_4-MTL-SHAKE-256
* SNOVA_29_6_5-MTL-SHAKE-256

## Definitions
Signature schemes are defined in the src/mtllib_schemes.h header file.

## Adding new signature schemes
Adding new signature schemes requires these steps
1. Create the appropriate implementations of the hash_msg, hash_leaf, and hash_int functions.
2. Update the src/mtllib_schemes.h to include the new signature scheme identifiers and properties.
3. Update the src/mtllib_util.c if needed to define new hash algorithm schemes.
4. Update the src/mtllib_util.c if needed to define new underlying signature library bindings.