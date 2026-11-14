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

## Definitions
Signature schemes are defined in the src/mtllib_schemes.h header file.

## Adding new signature schemes
Adding new signature schemes requires these steps
1. Create the appropriate implementations of the hash_msg, hash_leaf, and hash_int functions.
2. Update the src/mtllib_schemes.h to include the new signature scheme identifiers and properties.
3. Update the src/mtllib_util.c if needed to define new hash algorithm schemes.
4. Update the src/mtllib_util.c if needed to define new underlying signature library bindings.