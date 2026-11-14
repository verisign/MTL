import ctypes

# ML-DSA signature algorithm
sig_alg = "ML-DSA-44"

# Security parameter
n = 16


## ------------------ Import and Types -------------------- ##
libcrypto = ctypes.CDLL("/usr/local/lib64/libcrypto.so.3")

EVP_PKEY_p = ctypes.c_void_p
EVP_PKEY_CTX_p = ctypes.c_void_p
EVP_SIGNATURE_p = ctypes.c_void_p

# EVP_PKEY_CTX_new_from_name
libcrypto.EVP_PKEY_CTX_new_from_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
libcrypto.EVP_PKEY_CTX_new_from_name.restype = EVP_PKEY_CTX_p

# EVP_PKEY_keygen_init
libcrypto.EVP_PKEY_keygen_init.argtypes = [EVP_PKEY_CTX_p]
libcrypto.EVP_PKEY_keygen_init.restype = ctypes.c_int

# EVP_PKEY_keygen
libcrypto.EVP_PKEY_keygen.argtypes = [EVP_PKEY_CTX_p, ctypes.POINTER(EVP_PKEY_p)]
libcrypto.EVP_PKEY_keygen.restype = ctypes.c_int

# EVP_PKEY_CTX_new_from_pkey
libcrypto.EVP_PKEY_CTX_new_from_pkey.argtypes = [ctypes.c_void_p, EVP_PKEY_p, ctypes.c_char_p]
libcrypto.EVP_PKEY_CTX_new_from_pkey.restype = EVP_PKEY_CTX_p

# EVP_SIGNATURE_fetch
libcrypto.EVP_SIGNATURE_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
libcrypto.EVP_SIGNATURE_fetch.restype = EVP_SIGNATURE_p

# EVP_PKEY_sign_message_init
libcrypto.EVP_PKEY_sign_message_init.argtypes = [EVP_PKEY_CTX_p, EVP_SIGNATURE_p, ctypes.c_void_p]
libcrypto.EVP_PKEY_sign_message_init.restype = ctypes.c_int

# EVP_PKEY_verify_message_init
libcrypto.EVP_PKEY_verify_message_init.argtypes = [EVP_PKEY_CTX_p, EVP_SIGNATURE_p, ctypes.c_void_p]
libcrypto.EVP_PKEY_verify_message_init.restype = ctypes.c_int

# EVP_PKEY_sign
libcrypto.EVP_PKEY_sign.argtypes = [
    EVP_PKEY_CTX_p, 
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), 
    ctypes.c_char_p, ctypes.c_size_t
]
libcrypto.EVP_PKEY_sign.restype = ctypes.c_int

# EVP_PKEY_verify
libcrypto.EVP_PKEY_verify.argtypes = [
    EVP_PKEY_CTX_p, 
    ctypes.c_char_p, ctypes.c_size_t, 
    ctypes.c_char_p, ctypes.c_size_t
]
libcrypto.EVP_PKEY_verify.restype = ctypes.c_int

libcrypto.EVP_PKEY_get_raw_public_key.argtypes = [
    EVP_PKEY_p,                  # pkey
    ctypes.c_char_p,             # buffer
    ctypes.POINTER(ctypes.c_size_t) # sizeof pointer
]
libcrypto.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int

libcrypto.i2d_PUBKEY.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
libcrypto.i2d_PUBKEY.restype = ctypes.c_int

libcrypto.d2i_PUBKEY.argtypes = [ctypes.POINTER(EVP_PKEY_p), ctypes.POINTER(ctypes.c_void_p), ctypes.c_long]
libcrypto.d2i_PUBKEY.restype = EVP_PKEY_p 


EVP_PKEY_KEYPAIR = 3
OSSL_PARAM_OCTET_STRING = 5

class OSSL_PARAM(ctypes.Structure):
    _fields_ = [
        ("key", ctypes.c_char_p),
        ("data_type", ctypes.c_uint),
        ("data", ctypes.c_void_p),
        ("data_size", ctypes.c_size_t),
        ("return_size", ctypes.c_size_t)
    ]

# EVP_PKEY_CTX_new_from_name
libcrypto.EVP_PKEY_CTX_new_from_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
libcrypto.EVP_PKEY_CTX_new_from_name.restype = ctypes.c_void_p

# EVP_PKEY_Q_keygen
libcrypto.EVP_PKEY_Q_keygen.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
libcrypto.EVP_PKEY_Q_keygen.restype = ctypes.c_void_p

# EVP_MD_CTX_new
libcrypto.EVP_MD_CTX_new.argtypes = []
libcrypto.EVP_MD_CTX_new.restype = ctypes.c_void_p

# EVP_DigestSignInit
libcrypto.EVP_DigestSignInit.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p 
]
libcrypto.EVP_DigestSignInit.restype = ctypes.c_int

# EVP_DigestSign
libcrypto.EVP_DigestSign.argtypes = [
    ctypes.c_void_p, 
    ctypes.c_char_p, 
    ctypes.POINTER(ctypes.c_size_t), 
    ctypes.c_char_p,
    ctypes.c_size_t 
]
libcrypto.EVP_DigestSign.restype = ctypes.c_int

# EVP_PKEY_fromdata_init
libcrypto.EVP_PKEY_fromdata_init.argtypes = [ctypes.c_void_p]
libcrypto.EVP_PKEY_fromdata_init.restype = ctypes.c_int

# EVP_PKEY_fromdata
libcrypto.EVP_PKEY_fromdata.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_int,
    ctypes.POINTER(OSSL_PARAM)
]
libcrypto.EVP_PKEY_fromdata.restype = ctypes.c_int

# EVP_DigestVerifyInit
libcrypto.EVP_DigestVerifyInit.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p
]
libcrypto.EVP_DigestVerifyInit.restype = ctypes.c_int

# EVP_DigestVerify
libcrypto.EVP_DigestVerify.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t
]
libcrypto.EVP_DigestVerify.restype = ctypes.c_int


# Cleanup
libcrypto.EVP_PKEY_free.argtypes = [EVP_PKEY_p]
libcrypto.EVP_PKEY_CTX_free.argtypes = [EVP_PKEY_CTX_p]
libcrypto.EVP_SIGNATURE_free.argtypes = [EVP_SIGNATURE_p]

libcrypto.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]



## ------------------ Generate ML-DSA Key Pair -------------------- ##
def generate_ml_dsa_keypair(sig_alg) -> EVP_PKEY_p:
    """
    Generate an ML-DSA key pair context.
    """
    print(f"\033[1;34mGenerating key pair for {sig_alg}...\033[0m")
    #print(f"Generating key pair for {sig_alg}...")

    # Create keygen context
    ctx = libcrypto.EVP_PKEY_CTX_new_from_name(None, sig_alg.encode("utf-8"), None)
    if not ctx:
        raise RuntimeError(f"Could not create context for {sig_alg}.")
    
    try:
        if libcrypto.EVP_PKEY_keygen_init(ctx) <= 0:
            raise RuntimeError("Keygen initialization failed.")
        
        pkey = EVP_PKEY_p()
        if libcrypto.EVP_PKEY_keygen(ctx, ctypes.byref(pkey)) <= 0:
            raise RuntimeError("Key generation failed.")

        print("\033[1;34mSuccessfully generated ML-DSA key pair.\033[0m")
        return pkey
    finally:
        libcrypto.EVP_PKEY_CTX_free(ctx)



## ------------------ Export Public Key -------------------- ##
def export_public_key(pkey: ctypes.c_void_p) -> bytes:
    """
    Serialize the EVP_PKEY public key into standard X.509 SPKI DER bytes.
    """
    pubkey_len = ctypes.c_size_t(0)
    res = libcrypto.EVP_PKEY_get_raw_public_key(pkey, None, ctypes.byref(pubkey_len))
    
    # OpenSSL returns 1 on success
    if res <= 0 or pubkey_len.value == 0:
        raise RuntimeError("Failed to determine public key size.")
    
    # Allocatebuffer size
    buf = ctypes.create_string_buffer(pubkey_len.value)
    
    # Fetch key bytes into the buffer
    if libcrypto.EVP_PKEY_get_raw_public_key(pkey, buf, ctypes.byref(pubkey_len)) <= 0:
        raise RuntimeError("Failed to extract public key bytes.")
        
    return buf.raw[:pubkey_len.value]




## ------------------ Sign -------------------- ##
def sign_message(keypair: EVP_PKEY_p, sig_alg: str, message: bytes) -> bytes:
    """
    Sign a message.
    """
    # Context bound to the key
    sctx = libcrypto.EVP_PKEY_CTX_new_from_pkey(None, keypair, None)
    # Fetch the ML-DSA signature engine instance
    alg_encode = libcrypto.EVP_SIGNATURE_fetch(None, sig_alg.encode("utf-8"), None)
    
    if not sctx or not alg_encode:
        raise RuntimeError("Failed to set up signature structure.")
        
    try:
        # FIPS 204 requires message-level initialization
        if libcrypto.EVP_PKEY_sign_message_init(sctx, alg_encode, None) <= 0:
            raise RuntimeError("Signature message init failed.")
            
        # Get signature buffer size
        sig_len = ctypes.c_size_t(0)
        if libcrypto.EVP_PKEY_sign(sctx, None, ctypes.byref(sig_len), message, len(message)) <= 0:
            raise RuntimeError("Failed to determine signature buffer size.")
            
        # Get signature
        sig_buf = ctypes.create_string_buffer(sig_len.value)
        if libcrypto.EVP_PKEY_sign(sctx, sig_buf, ctypes.byref(sig_len), message, len(message)) <= 0:
            raise RuntimeError("Signing failed.")

        print("\033[1;34mSuccessfully created ML-DSA signature.\033[0m")
        return sig_buf.raw[:sig_len.value]
    finally:
        libcrypto.EVP_SIGNATURE_free(sig_alg)
        libcrypto.EVP_PKEY_CTX_free(sctx)



## ------------------ Test: Signature Verification Using the Generated Key Pair -------------------- ##
def test_verify_signature(key_pair: EVP_PKEY_p, sig_alg: str, message: bytes, signature: bytes) -> bool:
    """
    Verify an ML-DSA signature against the given message.
    """
    vctx = libcrypto.EVP_PKEY_CTX_new_from_pkey(None, key_pair, None)
    alg_encode = libcrypto.EVP_SIGNATURE_fetch(None, sig_alg.encode("utf-8"), None)
    
    if not vctx or not alg_encode:
        return False
        
    try:
        if libcrypto.EVP_PKEY_verify_message_init(vctx, alg_encode, None) <= 0:
            return False
            
        # EVP_PKEY_verify returns 1 for valid, 0 for invalid, or negative values on error
        res = libcrypto.EVP_PKEY_verify(vctx, signature, len(signature), message, len(message))
        return res == 1
    finally:
        libcrypto.EVP_SIGNATURE_free(alg_encode)
        libcrypto.EVP_PKEY_CTX_free(vctx)



## ------------------ Test: Public Key Reconstruction -------------------- ##
def reconstruct_pubkey(pubkey: bytes, sig_alg: str) -> EVP_PKEY_p:
    """
    Construct a public key back into an OpenSSL public-only EVP_PKEY.
    """        
    ctx = libcrypto.EVP_PKEY_CTX_new_from_name(None, sig_alg.encode("utf-8"), None)
    if not ctx:
        raise RuntimeError(f"Could not build context for {sig_alg}.")
    
    tmp_pkey = EVP_PKEY_p()
    pubkey_len = len(pubkey)
    try:
        if libcrypto.EVP_PKEY_keygen_init(ctx) <= 0 or libcrypto.EVP_PKEY_keygen(ctx, ctypes.byref(tmp_pkey)) <= 0:
            raise RuntimeError(f"Failed to compile metadata for {sig_alg}.")
        
        # Get structure length
        expected_der_len = libcrypto.i2d_PUBKEY(tmp_pkey, None)
        
        # Allocate buffer 
        buf = ctypes.create_string_buffer(expected_der_len)
        buf_ptr = ctypes.cast(buf, ctypes.c_void_p)
        buf_ref = ctypes.byref(buf_ptr)
        libcrypto.i2d_PUBKEY(tmp_pkey, buf_ref)
        
        # Extract ASN.1 header block
        # X.509 SPKI container has a metadata footprint of size (total DER size - key payload)
        header_size = expected_der_len - pubkey_len
        dynamic_header = buf.raw[:header_size]
        
    finally:
        # Free pointers
        if tmp_pkey:
            libcrypto.EVP_PKEY_free(tmp_pkey)
        libcrypto.EVP_PKEY_CTX_free(ctx)

    # Put together
    wrapped_pubkey = dynamic_header + pubkey

    # Feed the X.509 DER package into OpenSSL's d2i engine
    total_len = len(wrapped_pubkey)
    res_buf = ctypes.create_string_buffer(wrapped_pubkey)
    res_buf_ptr = ctypes.cast(res_buf, ctypes.c_void_p)
    res_buf_ref = ctypes.byref(res_buf_ptr)
    
    pubkey_construct = libcrypto.d2i_PUBKEY(None, res_buf_ref, total_len)
    if not pubkey_construct:
        raise RuntimeError(f"OpenSSL failed to parse spliced X.509 bytes for {sig_alg}.")
        
    return pubkey_construct



## ------------------ Test: Signature Verification Using Constructed Public Key -------------------- ##
def verify_signature(pubkey: EVP_PKEY_p, sig_alg: str, message: bytes, signature: bytes) -> bool:
    """
    Verifies a signature using the loaded public key structure.
    """
    vctx = libcrypto.EVP_PKEY_CTX_new_from_pkey(None, pubkey, None)
    alg_encode = libcrypto.EVP_SIGNATURE_fetch(None, sig_alg.encode("utf-8"), None)

    if not vctx or not alg_encode:
        if vctx: libcrypto.EVP_PKEY_CTX_free(vctx)
        if alg_encode: libcrypto.EVP_SIGNATURE_free(alg_encode)
        return False

    try:
        if libcrypto.EVP_PKEY_verify_message_init(vctx, alg_encode, None) <= 0:
            return False
            
        res = libcrypto.EVP_PKEY_verify(vctx, signature, len(signature), message, len(message))
        return res == 1
        
    finally:
        libcrypto.EVP_SIGNATURE_free(alg_encode)
        libcrypto.EVP_PKEY_CTX_free(vctx)
        if pubkey:
            libcrypto.EVP_PKEY_free(pubkey)



## --------------------------------------- SLH-DSA --------------------------------------- ##
        
## ------------------ Generate ML-DSA Key Pair -------------------- ##
def generate_slh_dsa_keypair(sig_alg: str):
    """
    Generate an SLH-DSA key pair context.
    """
    # Generate a private key using quick keygen
    priv_key = libcrypto.EVP_PKEY_Q_keygen(None, None, sig_alg.encode('utf-8'), None)
    if not priv_key:
        # Try alternate name formatting variants
        alt_algo = sig_alg.lower().replace("-", "_").encode('utf-8')
        priv_key = libcrypto.EVP_PKEY_Q_keygen(None, None, alt_algo, None)
    
    if not priv_key:
        print("NO SLH-DSA compiled in.")
    else:
        # Extract the raw public key bytes
        pub_len = ctypes.c_size_t(0)
        libcrypto.EVP_PKEY_get_raw_public_key(priv_key, None, ctypes.byref(pub_len))
        
        pub_buf = ctypes.create_string_buffer(pub_len.value)
        libcrypto.EVP_PKEY_get_raw_public_key(priv_key, pub_buf, ctypes.byref(pub_len))
        extracted_public_key = pub_buf.raw[:pub_len.value]

        print("Successfully generated SLH-DSA key pair.")
        print(f"Extracted Public Key Size: {len(extracted_public_key)} bytes.")
        return extracted_public_key, priv_key



## ------------------ Sign -------------------- ##
def slhdsa_sign_message(priv_key, ladder):
    """
    Create a signature using the private key.
    """
    sctx = libcrypto.EVP_MD_CTX_new()
    libcrypto.EVP_DigestSignInit(sctx, None, None, None, priv_key)

    try:
        sig_len = ctypes.c_size_t(0)
        libcrypto.EVP_DigestSign(sctx, None, ctypes.byref(sig_len), ladder.val, len(ladder.val))
        
        sig_buf = ctypes.create_string_buffer(sig_len.value)
        libcrypto.EVP_DigestSign(sctx, sig_buf, ctypes.byref(sig_len), ladder.val, len(ladder.val))
        generated_signature = sig_buf.raw[:sig_len.value]
        print(f"SUCCESS: Created Signature Size: {len(generated_signature)} bytes.")
        
        return generated_signature

    finally:
        libcrypto.EVP_MD_CTX_free(sctx)
        libcrypto.EVP_PKEY_free(priv_key)



## ------------------ SLH-DSA: Signature Verification -------------------- ##
def verify_slhdsa_signature(algorithm: str, public_key: bytes, ladder_sig: bytes, ladder: bytes) -> bool:
    """
    Verifies SLH-DSA using provided initialization. 
    """
    ctx_name = algorithm.encode("utf-8")
    pctx = libcrypto.EVP_PKEY_CTX_new_from_name(None, ctx_name, None)
    
    if not pctx:
        alt_name = algorithm.lower().replace("-", "_").encode("utf-8")
        pctx = libcrypto.EVP_PKEY_CTX_new_from_name(None, alt_name, None)
    if not pctx:
        raise RuntimeError(f"Algorithm {algorithm} not available in this OpenSSL environment.")

    pkey = ctypes.c_void_p(None)
    try:
        # Build memory parameters for the raw 32-byte public key string
        if libcrypto.EVP_PKEY_fromdata_init(pctx) != 1:
            raise RuntimeError("fromdata init failed")

        params = (OSSL_PARAM * 2)()
        params[0].key = b"pub"
        params[0].data_type = OSSL_PARAM_OCTET_STRING
        params[0].data = ctypes.cast(ctypes.c_char_p(public_key), ctypes.c_void_p)
        params[0].data_size = len(public_key)
        
        # Zero out array terminator
        params[1].key = None
        params[1].data_type = 0
        params[1].data = None
        params[1].data_size = 0

        if libcrypto.EVP_PKEY_fromdata(pctx, ctypes.byref(pkey), 1, params) != 1:
            raise RuntimeError("Failed to build key template.")

        # Setup context
        vctx = libcrypto.EVP_MD_CTX_new()
        if not vctx:
            raise RuntimeError("Failed to build verification environment.")

        try:
            # PQC signatures pass NULL/None as the digest algorithm type
            if libcrypto.EVP_DigestVerifyInit(vctx, None, None, None, pkey) != 1:
                return False

            res = libcrypto.EVP_DigestVerify(vctx, ladder_sig, len(ladder_sig), ladder, len(ladder))
            return res == 1
            
        finally:
            if vctx:
                libcrypto.EVP_MD_CTX_free(vctx)
    finally:
        if pctx:
            libcrypto.EVP_PKEY_CTX_free(pctx)
        if pkey:
            libcrypto.EVP_PKEY_free(pkey)



## ------------------ Verify a SigTag -------------------- ##
def verify_sigtag(serv_sigtag: bytes, client_sigtag: bytes, n: int, target_leaf_index: int) -> bool:
    # Guard
    if target_leaf_index < 0:
        return False
    if serv_sigtag == client_sigtag:
        return True
    # if SID matches: check if backward compatibility holds
    elif serv_sigtag[:(2*n)] == client_sigtag[:(2*n)]:
        if target_leaf_index <= int.from_bytes(client_sigtag[(2*n):], byteorder="big"):
            return True
    else:
        return False