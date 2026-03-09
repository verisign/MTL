# MTL
MTL Reference Library Implementation based on [draft-harvey-cfrg-mtl-mode-00](https://datatracker.ietf.org/doc/draft-harvey-cfrg-mtl-mode/)

## Dependencies
* libcrypto from openssl version 3.1.0 or newer (or substitute crypto operations to replace the spx_funcs.c functions)
* liboqs version 0.14.0 or newer (for the examples).  To include the liboqs library as a statically linked library change the -loqs to -l:_path_/liboqs.a in the examples/Makefile.am. 
* Applications using the MTL Reference Library should also link with the C math library (-lm)

## Configuring the build environment
1. Setup the auto tools: `autoreconf --install`
2. configure the project: `./configure`
3. build the library and tools: `make`

## Running the test application
(After building the library and tools) Run the mtltool test tool in the test directory `test/mtltest`.
Alternatively, `make check` can be run to exercise the mtltest tool.

## Running the example application
(After building the library and tools) run the mtl example applications `cd examples; ./test.sh` or use one of the three utities:
* `mtlkeygen [options] filename algorithm_str`
* `mtlsign [options] key_file msg_file_1 msg_file_2 ...`
* `mtlverify [options] algorithm_str key_file message_file signature_file [ladder_file]`

Running each tool with -h (or no parameters) will give the help output which describes the parameters for that utility.
Note: Algorithm should be one of the supported algorithm strings [README_SCHEMES.md](README_SCHEMES.md)

### MTLKEYGEN
```
Usage: mtlkeygen filename algorithm_str

    RETURN VALUE
      0 on success or number for error

    OPTIONS
      -h    Print this tool usage help message

    PARAMETERS
      filename      The name to use for key files
      algorithm_str The algorithm string for type of key to generate
                    See the list of supported algorithm strings below

    EXAMPLE USAGE
      mtlkeygen my_key SLH-DSA-SHAKE-128s-MTL-SHAKE-128

    SUPPORTED ALGORITHMS
      SLH-DSA-SHAKE-128s-MTL-SHAKE-128
      SLH-DSA-SHAKE-128f-MTL-SHAKE-128
      SLH-DSA-SHAKE-192s-MTL-SHAKE-192
      SLH-DSA-SHAKE-192f-MTL-SHAKE-192
      SLH-DSA-SHAKE-256s-MTL-SHAKE-256
      SLH-DSA-SHAKE-256f-MTL-SHAKE-256
      SLH-DSA-SHA2-128s-MTL-SHA2-128
      SLH-DSA-SHA2-128f-MTL-SHA2-128
      SLH-DSA-SHA2-192s-MTL-SHA2-192
      SLH-DSA-SHA2-192f-MTL-SHA2-192
      SLH-DSA-SHA2-256s-MTL-SHA2-256
      SLH-DSA-SHA2-256f-MTL-SHA2-256
      ML-DSA-44-MTL-SHAKE-128
      ML-DSA-65-MTL-SHAKE-192
      ML-DSA-87-MTL-SHAKE-256
      Falcon-padded-512-MTL-SHAKE-128
      Falcon-padded-1024-MTL-SHAKE-256
      MAYO-1-MTL-SHAKE-128
      MAYO-2-MTL-SHAKE-128
      MAYO-3-MTL-SHAKE-192
      MAYO-5-MTL-SHAKE-256
      cross-rsdp-128-balanced-MTL-SHAKE-128
      cross-rsdp-128-fast-MTL-SHAKE-128
      cross-rsdp-128-small-MTL-SHAKE-128
      cross-rsdp-192-balanced-MTL-SHAKE-192
      cross-rsdp-192-fast-MTL-SHAKE-192
      cross-rsdp-192-small-MTL-SHAKE-192
      cross-rsdp-256-balanced-MTL-SHAKE-256
      cross-rsdp-256-fast-MTL-SHAKE-256
      cross-rsdp-256-small-MTL-SHAKE-256
      cross-rsdpg-128-balanced-MTL-SHAKE-128
      cross-rsdpg-128-fast-MTL-SHAKE-128
      cross-rsdpg-128-small-MTL-SHAKE-128
      cross-rsdpg-192-balanced-MTL-SHAKE-192
      cross-rsdpg-192-fast-MTL-SHAKE-192
      cross-rsdpg-192-small-MTL-SHAKE-192
      cross-rsdpg-256-balanced-MTL-SHAKE-256
      cross-rsdpg-256-fast-MTL-SHAKE-256
      cross-rsdpg-256-small-MTL-SHAKE-256
      OV-Is-MTL-SHAKE-128
      OV-Ip-MTL-SHAKE-128
      OV-III-MTL-SHAKE-192
      OV-V-MTL-SHAKE-256
      OV-Is-pkc-MTL-SHAKE-128
      OV-Ip-pkc-MTL-SHAKE-128
      OV-III-pkc-MTL-SHAKE-192
      OV-V-pkc-MTL-SHAKE-256
      OV-Is-pkc-skc-MTL-SHAKE-128
      OV-Ip-pkc-skc-MTL-SHAKE-128
      OV-III-pkc-skc-MTL-SHAKE-192
      OV-V-pkc-skc-MTL-SHAKE-256
      SNOVA_24_5_4-MTL-SHAKE-128
      SNOVA_24_5_4_SHAKE-MTL-SHAKE-128
      SNOVA_24_5_4_esk-MTL-SHAKE-128
      SNOVA_24_5_4_SHAKE_esk-MTL-SHAKE-128
      SNOVA_37_17_2-MTL-SHAKE-128
      SNOVA_25_8_3-MTL-SHAKE-128
      SNOVA_56_25_2-MTL-SHAKE-192
      SNOVA_49_11_3-MTL-SHAKE-192
      SNOVA_37_8_4-MTL-SHAKE-192
      SNOVA_24_5_5-MTL-SHAKE-192
      SNOVA_60_10_4-MTL-SHAKE-256
      SNOVA_29_6_5-MTL-SHAKE-256
```

### MTLSIGN
```
 Usage: mtlsign [options] key_file msg_file_1 msg_file_2 ...

    RETURN VALUE
      0 on success or number for error

    OPTIONS
      -h            Print this help message
      -r            Reconstruct full signatures from the same ladder rather
                      than generating a fresh signed ladder each time

    PARAMETERS
      key_file      The key_file name/path where the generated key should be read
      msg_file_x    File that contains the message to sign (in binary or base64 format)

    EXAMPLE USAGE
      mtlsign ./testkey.key ./message1.bin ./message2.bin
```

### MTLVERIFY
```
Usage: mtlverify [options] algorithm_str key_file message_file signature_file [ladder_file]

    RETURN VALUE
      0 on success or number for error

    OPTIONS
      -h              Print this help message
      -t              Trust the cached ladder (do not verify the signature on it)
      -v              Use verbose output

    PARAMETERS
      algorithm_str  The algorithms string identifying the algorithm to verify
      pubkey_file    The file name/path where the public key should be read
      message_file   File holding the message to verify
      signature_file File holding the signature on the message (full or condensed)
      ladder_file    (Optional) holds the signed ladder on the message. Required if signature_file contains a condensed signature

    EXAMPLE USAGE
      mtlverify ML-DSA-44-MTL-SHAKE-128 keyfile.pub message.txt message.condensed_sig keyfile.ladder

    SUPPORTED ALGORITHMS
      SLH-DSA-SHAKE-128s-MTL-SHAKE-128
      SLH-DSA-SHAKE-128f-MTL-SHAKE-128
      SLH-DSA-SHAKE-192s-MTL-SHAKE-192
      SLH-DSA-SHAKE-192f-MTL-SHAKE-192
      SLH-DSA-SHAKE-256s-MTL-SHAKE-256
      SLH-DSA-SHAKE-256f-MTL-SHAKE-256
      SLH-DSA-SHA2-128s-MTL-SHA2-128
      SLH-DSA-SHA2-128f-MTL-SHA2-128
      SLH-DSA-SHA2-192s-MTL-SHA2-192
      SLH-DSA-SHA2-192f-MTL-SHA2-192
      SLH-DSA-SHA2-256s-MTL-SHA2-256
      SLH-DSA-SHA2-256f-MTL-SHA2-256
      ML-DSA-44-MTL-SHAKE-128
      ML-DSA-65-MTL-SHAKE-192
      ML-DSA-87-MTL-SHAKE-256
      Falcon-padded-512-MTL-SHAKE-128
      Falcon-padded-1024-MTL-SHAKE-256
      MAYO-1-MTL-SHAKE-128
      MAYO-2-MTL-SHAKE-128
      MAYO-3-MTL-SHAKE-192
      MAYO-5-MTL-SHAKE-256
      cross-rsdp-128-balanced-MTL-SHAKE-128
      cross-rsdp-128-fast-MTL-SHAKE-128
      cross-rsdp-128-small-MTL-SHAKE-128
      cross-rsdp-192-balanced-MTL-SHAKE-192
      cross-rsdp-192-fast-MTL-SHAKE-192
      cross-rsdp-192-small-MTL-SHAKE-192
      cross-rsdp-256-balanced-MTL-SHAKE-256
      cross-rsdp-256-fast-MTL-SHAKE-256
      cross-rsdp-256-small-MTL-SHAKE-256
      cross-rsdpg-128-balanced-MTL-SHAKE-128
      cross-rsdpg-128-fast-MTL-SHAKE-128
      cross-rsdpg-128-small-MTL-SHAKE-128
      cross-rsdpg-192-balanced-MTL-SHAKE-192
      cross-rsdpg-192-fast-MTL-SHAKE-192
      cross-rsdpg-192-small-MTL-SHAKE-192
      cross-rsdpg-256-balanced-MTL-SHAKE-256
      cross-rsdpg-256-fast-MTL-SHAKE-256
      cross-rsdpg-256-small-MTL-SHAKE-256
      OV-Is-MTL-SHAKE-128
      OV-Ip-MTL-SHAKE-128
      OV-III-MTL-SHAKE-192
      OV-V-MTL-SHAKE-256
      OV-Is-pkc-MTL-SHAKE-128
      OV-Ip-pkc-MTL-SHAKE-128
      OV-III-pkc-MTL-SHAKE-192
      OV-V-pkc-MTL-SHAKE-256
      OV-Is-pkc-skc-MTL-SHAKE-128
      OV-Ip-pkc-skc-MTL-SHAKE-128
      OV-III-pkc-skc-MTL-SHAKE-192
      OV-V-pkc-skc-MTL-SHAKE-256
      SNOVA_24_5_4-MTL-SHAKE-128
      SNOVA_24_5_4_SHAKE-MTL-SHAKE-128
      SNOVA_24_5_4_esk-MTL-SHAKE-128
      SNOVA_24_5_4_SHAKE_esk-MTL-SHAKE-128
      SNOVA_37_17_2-MTL-SHAKE-128
      SNOVA_25_8_3-MTL-SHAKE-128
      SNOVA_56_25_2-MTL-SHAKE-192
      SNOVA_49_11_3-MTL-SHAKE-192
      SNOVA_37_8_4-MTL-SHAKE-192
      SNOVA_24_5_5-MTL-SHAKE-192
      SNOVA_60_10_4-MTL-SHAKE-256
      SNOVA_29_6_5-MTL-SHAKE-256

```


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
 