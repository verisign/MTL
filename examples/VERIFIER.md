# MTL Verification Tool
## Overview
The mtlverify tool allows for command line verification of MTL signatures base on either a hex string or base64 encoded string of bytes.  

## Return Codes
The tool will return 0 on success or a error number on failure 

## Usage

```mtlverify [OPTIONS] algorithm key message signature <ladder>```

	printf("    PARAMETERS\n");
	printf("      algorithm (required)\tAlgorithm string for MTL key used to sign message\n");
	printf("      key (required)\t\tpublic key value to use for validation\n");
	printf("      message (required)\tmessage to verify\n");
	printf("      signature (required)\tsignature on message\n");
	printf("      ladder (optional)\t\tLadder for use with condensed signatures\n");


## Options

```
	-b    Inputs are base64 encoded rather than hex strings
	-h    Print this help message
	-s    Ouptut the ladder signature with the validated ladder
	-v    Use verbose output
```

## Use with files
With Bash shell, files can be used for the input parameters using $(cat <filelname>) on the command line (or in scripts).  
For example, to use the file verifier.key, verifier.msg, and verifier.sig (encoded in Base64) the command would look like:

```./mtlverify -b SPHINCS+-MTL-SHA2-128S-SIMPLE "$(cat verifier.key)" "$(cat verifier.msg)" "$(cat verifier.sig)"```
