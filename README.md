# MTL
MTL Reference Library Implementation based on [draft-harvey-cfrg-mtl-mode-00](https://datatracker.ietf.org/doc/draft-harvey-cfrg-mtl-mode/)

## Dependencies
* libcrypto from openssl version 3.1.0 or newer (or substitute crypto operations to replace the spx_funcs.c functions)
* liboqs version 0.7.2 or newer (for the examples).  To include the liboqs library as a statically linked library change the -loqs to -l:_path_/liboqs.a in the examples/Makefile.am. 
* Applications using the MTL Reference Library should also link with the C math library (-lm)

## Configuring the build environment
1. Setup the auto tools: `autoreconf --install`
2. configure the project: `./configure`
3. build the library and tools: `make`

## Running the test application
(After building the library and tools) Run the mtltool test tool in the test directory `test/mtltest`.
Alternatively, `make check` can be run to exercise the mtltest tool.

## Running the example application
(After building the library and tools) run the mtltool application `examples/mtltool` with one of the three supported commands
* `mtltool keygen <key file> <key string>`
* `mtltool sign   <key file> <data file> <signature file>`
* `mtltool verify <key file> <data file> <signature file>`

Where key file is the private/public key pair to generate/use, data file is an ascii file for which each line in the file will be signed, and signature file is a  binary file that will have one signature for each record signed.
Key string is one of the supported algorithm strings [README_SCHEMES.md](README_SCHEMES.md)

## Randomization
Randomization is defined in the schemes table. It needs to match the underlying signature scheme randomization strategy, which can be a compile time decision for some libraries.

## MTL Tree Sizes
The page and record sizes for MTL mode are defined in the src/mtl_node_set.h file. Larger sizes allows for larger trees but requires more resources.  This value can be tailored to support smaller instances if desired.  The default values are 1 Megabyte per page with 1024 pages resulting in 1 Gigabyte of hashes in memory.  For a 128 bit hash this results in a max of 67,108,864 hashes (~33,554,432 messages signed) and for a 256 bit hash this results in 33,554,432 hashes (~16,777,216 messages signed)

## Open Items
* MTL Provider is tested through the application in the test folder and the example application. These applications are to demonstrate the capability and are not production worthy.  Some code paths are not implemented or are not fully tested. 

## About MTL Mode
Merkle Tree Ladder (MTL) mode is a technique for using an underlying signature scheme to authenticate an evolving series of messages that can reduce the signature scheme's operational impact.  Rather than signing messages individually, MTL mode signs structures called "Merkle tree ladders" that are derived from the messages to be authenticated.  Individual messages are then authenticated relative to the ladder using a Merkle tree authentication path and the ladder is authenticated using the public key of the underlying signature scheme.  The size and computational cost of the underlying signatures are thereby amortized across multiple messages, reducing the scheme's operational impact.  The reduction can be particularly beneficial when MTL mode is applied to a post-quantum signature scheme that has a large signature size or computational cost.  Like other Merkle tree techniques, MTL mode's security is based only on cryptographic hash functions, so the mode is quantum-safe based on the quantum-resistance of its cryptographic hash functions.
 
MTL mode is described in more detail in this paper co-authored by Verisign researchers:  Fregly, A., Harvey, J., Kaliski Jr., B.S., Sheth, S. (2023). Merkle Tree Ladder Mode: Reducing the Size Impact of NIST PQC Signature Algorithms in Practice. In: Rosulek, M. (ed) Topics in Cryptology – CT-RSA 2023. Lecture Notes in Computer Science, vol 13871. Springer, Cham. https://doi.org/10.1007/978-3-031-30872-7_16.
 
Verisign has announced public, royalty-free licenses to certain intellectual property related to MTL mode in furtherance of IETF standardization which helps support the security, stability and resiliency of the Domain Name System (DNS) and the internet. For more information about the licenses, see the following IETF IPR declarations or updates thereto:

* https://datatracker.ietf.org/ipr/6176/
* https://datatracker.ietf.org/ipr/6175/
* https://datatracker.ietf.org/ipr/6174/
* https://datatracker.ietf.org/ipr/6173/
* https://datatracker.ietf.org/ipr/6172/
* https://datatracker.ietf.org/ipr/6171/
* https://datatracker.ietf.org/ipr/6170/

Subject to the licenses referenced above and conditions thereof:
 
"This product is licensed under patents and/or patent applications owned by VeriSign, Inc. in furtherance of IETF standardization which helps support the security, stability and resiliency of the Domain Name System (DNS) and the internet. For more information about the patents, visit www.verisign.com/Declarations."
 