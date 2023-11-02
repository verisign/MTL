# MTL SCHEMES
The following signature schemes are suported by this library:

## Supported algorithm strings
* SPHINCS+-MTL-SHAKE-128S-SIMPLE
* SPHINCS+-MTL-SHAKE-128S-ROBUST
* SPHINCS+-MTL-SHAKE-128F-SIMPLE
* SPHINCS+-MTL-SHAKE-128F-ROBUST
* SPHINCS+-MTL-SHAKE-192S-SIMPLE
* SPHINCS+-MTL-SHAKE-192S-ROBUST
* SPHINCS+-MTL-SHAKE-192F-SIMPLE
* SPHINCS+-MTL-SHAKE-192F-ROBUST
* SPHINCS+-MTL-SHAKE-256S-SIMPLE
* SPHINCS+-MTL-SHAKE-256S-ROBUST
* SPHINCS+-MTL-SHAKE-256F-SIMPLE
* SPHINCS+-MTL-SHAKE-256F-ROBUST
* SPHINCS+-MTL-SHA2-128S-SIMPLE
* SPHINCS+-MTL-SHA2-128S-ROBUST
* SPHINCS+-MTL-SHA2-128F-SIMPLE
* SPHINCS+-MTL-SHA2-128F-ROBUST
* SPHINCS+-MTL-SHA2-192S-SIMPLE
* SPHINCS+-MTL-SHA2-192S-ROBUST
* SPHINCS+-MTL-SHA2-192F-SIMPLE
* SPHINCS+-MTL-SHA2-192F-ROBUST
* SPHINCS+-MTL-SHA2-256S-SIMPLE
* SPHINCS+-MTL-SHA2-256S-ROBUST
* SPHINCS+-MTL-SHA2-256F-SIMPLE
* SPHINCS+-MTL-SHA2-256F-ROBUST

## Definitions
Signature schemes are defined in the example/schemes.h directory.

## Adding new signature schemes
Adding new signature schemes requires these steps
1. Create the appropriate implementations of the hash_msg, hash_leaf, and hash_int functions.
2. Update the examples/schemes.h to include the new signature scheme identifiers and properties.
3. Update the examples/mtltool.c `// Algorithm Selection` sections to set the algorithm functions.
4. Update the examples/mtltool.h to add any scheme specific #defines
5. Update the examples/mtltool_io.c `// Create the scheme specific parameters` sections to create the appropriate parameters for the new scheme.
