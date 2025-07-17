# MTL SCHEMES
The following signature schemes are supported by this library:

## Supported algorithm strings
* SLH-DSA-MTL-SHAKE-128S
* SLH-DSA-MTL-SHAKE-128F
* SLH-DSA-MTL-SHAKE-192S
* SLH-DSA-MTL-SHAKE-192F
* SLH-DSA-MTL-SHAKE-256S
* SLH-DSA-MTL-SHAKE-256F
* SLH-DSA-MTL-SHA2-128S
* SLH-DSA-MTL-SHA2-128F
* SLH-DSA-MTL-SHA2-192S
* SLH-DSA-MTL-SHA2-192F
* SLH-DSA-MTL-SHA2-256S
* SLH-DSA-MTL-SHA2-256F

## Definitions
Signature schemes are defined in the src/mtllib_schemes.h header file.

## Adding new signature schemes
Adding new signature schemes requires these steps
1. Create the appropriate implementations of the hash_msg, hash_leaf, and hash_int functions.
2. Update the src/mtllib_schemes.h to include the new signature scheme identifiers and properties.
3. Update the src/mtllib_util.c if needed to define new hash algorithm schemes.
4. Update the src/mtllib_util.c if needed to define new underlying signature library bindings.