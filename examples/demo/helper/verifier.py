import ctypes
import struct
import hashlib

# -------------------------- OpenSSL for Signature Verification -------------------------- #
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

libcrypto = ctypes.CDLL("/usr/local/lib64/libcrypto.so.3")

# Map OpenSSL handlers to ctypes

# EVP_PKEY_CTX_new_from_name
libcrypto.EVP_PKEY_CTX_new_from_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
libcrypto.EVP_PKEY_CTX_new_from_name.restype = ctypes.c_void_p

libcrypto.EVP_PKEY_fromdata_init.argtypes = [ctypes.c_void_p]
libcrypto.EVP_PKEY_fromdata_init.restype = ctypes.c_int

libcrypto.EVP_PKEY_fromdata.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_int, ctypes.POINTER(OSSL_PARAM)]
libcrypto.EVP_PKEY_fromdata.restype = ctypes.c_int

libcrypto.EVP_MD_CTX_new.restype = ctypes.c_void_p

libcrypto.EVP_DigestVerifyInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
libcrypto.EVP_DigestVerifyInit.restype = ctypes.c_int

libcrypto.EVP_DigestVerify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
libcrypto.EVP_DigestVerify.restype = ctypes.c_int

libcrypto.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
libcrypto.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
libcrypto.EVP_PKEY_CTX_free.argtypes = [ctypes.c_void_p]

EVP_PKEY_p = ctypes.c_void_p
EVP_PKEY_CTX_p = ctypes.c_void_p
EVP_SIGNATURE_p = ctypes.c_void_p

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

# EVP_PKEY_verify_message_init
libcrypto.EVP_PKEY_verify_message_init.argtypes = [EVP_PKEY_CTX_p, EVP_SIGNATURE_p, ctypes.c_void_p]
libcrypto.EVP_PKEY_verify_message_init.restype = ctypes.c_int

# EVP_PKEY_verify
libcrypto.EVP_PKEY_verify.argtypes = [
    EVP_PKEY_CTX_p, 
    ctypes.c_char_p, ctypes.c_size_t, 
    ctypes.c_char_p, ctypes.c_size_t
]
libcrypto.EVP_PKEY_verify.restype = ctypes.c_int

# Extract raw public key component
libcrypto.EVP_PKEY_get_raw_public_key.argtypes = [
    EVP_PKEY_p,                  # pkey
    ctypes.c_char_p,             # buffer
    ctypes.POINTER(ctypes.c_size_t) # sizeof pointer
]
libcrypto.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int

# i2d_PUBKEY
libcrypto.i2d_PUBKEY.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
libcrypto.i2d_PUBKEY.restype = ctypes.c_int

# d2i_PUBKEY: Reconstruct public key
libcrypto.d2i_PUBKEY.argtypes = [ctypes.POINTER(EVP_PKEY_p), ctypes.POINTER(ctypes.c_void_p), ctypes.c_long]
libcrypto.d2i_PUBKEY.restype = EVP_PKEY_p

# Cleanup
libcrypto.EVP_PKEY_CTX_free.argtypes = [EVP_PKEY_CTX_p]
libcrypto.EVP_SIGNATURE_free.argtypes = [EVP_SIGNATURE_p]



# -------------------- For SLH-DSA -------------------- #
def slhdsa_verify_signature(algorithm: str, public_key: bytes, ladder_sig: bytes, ladder: bytes) -> bool:
    """
    Verifies an SLH-DSA signature using the public key. 
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


# -------------------- For ML-DSA  -------------------- #
def mldsa_verify_signature(algorithm:str, public_key: bytes, ladder_sig: bytes, ladder: bytes) -> bool:
    """
    Verifies an ML-DSA signature using the public key.
    """
    # Rebuild the public key structure
    ctx = libcrypto.EVP_PKEY_CTX_new_from_name(None, algorithm.encode("utf-8"), None)
    if not ctx:
        raise RuntimeError(f"Could not build context for {algorithm}.")
    
    tmp_pkey = EVP_PKEY_p()
    pubkey_len = len(public_key)
    try:
        if libcrypto.EVP_PKEY_keygen_init(ctx) <= 0 or libcrypto.EVP_PKEY_keygen(ctx, ctypes.byref(tmp_pkey)) <= 0:
            raise RuntimeError(f"Failed to compile metadata for {algorithm}.")
        
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
    wrapped_pubkey = dynamic_header + public_key

    # Feed the X.509 DER package into OpenSSL d2i engine
    total_len = len(wrapped_pubkey)
    res_buf = ctypes.create_string_buffer(wrapped_pubkey)
    res_buf_ptr = ctypes.cast(res_buf, ctypes.c_void_p)
    res_buf_ref = ctypes.byref(res_buf_ptr)
    
    pubkey_construct = libcrypto.d2i_PUBKEY(None, res_buf_ref, total_len)
    if not pubkey_construct:
        raise RuntimeError(f"OpenSSL failed to parse spliced X.509 bytes for {algorithm}.")


    # Verify the signature
    vctx = libcrypto.EVP_PKEY_CTX_new_from_pkey(None, pubkey_construct, None)
    alg_encode = libcrypto.EVP_SIGNATURE_fetch(None, algorithm.encode("utf-8"), None)

    if not vctx or not alg_encode:
        if vctx: 
            libcrypto.EVP_PKEY_CTX_free(vctx)
        if alg_encode: 
            libcrypto.EVP_SIGNATURE_free(alg_encode)
        return False

    try:
        if libcrypto.EVP_PKEY_verify_message_init(vctx, alg_encode, None) <= 0:
            return False
            
        res = libcrypto.EVP_PKEY_verify(vctx, ladder_sig, len(ladder_sig), ladder, len(ladder))
        return res == 1
        
    finally:
        libcrypto.EVP_SIGNATURE_free(alg_encode)
        libcrypto.EVP_PKEY_CTX_free(vctx)  
        if pubkey_construct:
            libcrypto.EVP_PKEY_free(pubkey_construct)
# ---------------------------------------------------------------------------------------- #


            
# -------------------------------------- Node Hash --------------------------------------- #
class LEAFADRS:
    def __init__(self):
        self._index = 0  # 64-bit

    def set_indexes(self, leaf: int):
        """
        Set leaf index.
        """
        self._index = leaf

    def serialize(self) -> bytes:
        """
        Serializes the address block to 16 bytes.
        >: Big Endian
        Q: 64-bit unsigned integer - 8 bytes
        """
        return struct.pack(">Q", self._index)


class ADRS:
    def __init__(self):
        self.min_index = 0  # L: 64-bit
        self.max_index = 0  # R: 64-bit

    def set_indexes(self, left: int, right: int):
        """
        Set left and right index.
        """
        self.min_index = left
        self.max_index = right

    def serialize(self) -> bytes:
        """
        Serializes the address block to 16 bytes.
        >: Big Endian
        Q: 64-bit unsigned integer - 8 bytes
        """
        return struct.pack(">QQ", self.min_index, self.max_index)


def calculate_hash(payload: bytes, hash_alg: str, n: int) -> bytes:
    """
    To call Python hashlib to calculate hash values. 
    :param payload: payload in bytes
    :param hash_alg: hash algorithm
    :param n: security parameter
    """
    if hash_alg == "sha2":
        hasher = hashlib.sha256()

        # The customization string is NEEDED for the SHA2 implementation
        MTL_FIXED_CSTR = bytes([1, 6, ord("M"), ord("T"), ord("L"), ord("O"), ord("I"), ord("D")])
        block_size = hasher.block_size
        block_padded_cstr = MTL_FIXED_CSTR.ljust(block_size, b"\x00")
        
        hasher.update(block_padded_cstr)
        hasher.update(payload)
        # Truncate to first n bytes
        return hasher.digest()[:n]

    # The customization string is currently disabled as cSHAKE is not yet supported by OpenSSL stable versions
    elif hash_alg == "shake":
        if n == 16:
            hasher = hashlib.shake_128()
        elif n in (24, 32):
            hasher = hashlib.shake_256()
        else:
            raise ValueError("Unsupported security parameter.")
        
        hasher.update(payload)
        # Truncate to first n bytes
        return hasher.digest(n)

    else:
        raise ValueError("Unsupported hash algorithm.")


# -------------------------- Leaf Node -------------------------- #
def generate_payload_leaf(sid: bytes, rand: bytes, adrs: ADRS, ctx_msg: bytes, leaf_message: bytes) -> bytes:
    """
    Reference: draft-kaizer-dnsop-ml-dsa-mtl-dnssec-01 Section 5-2.
    cSHAKE(SID || Rand || leaf_index || OLEN(ctx_msg) || ctx_msg || msg)
    """
    # Byte buffer
    payload = bytearray()
    
    # Concatenate inputs
    payload.extend(sid)
    payload.extend(rand)
    # LEAFADRS contains (leaf_index)
    payload.extend(adrs.serialize())   
    # Packs the length as exactly 1 single byte: BUFFER_APPEND(buffer, buffer_offset, &ctx_len, 1);
    payload.extend(struct.pack("B", len(ctx_msg)))
    payload.extend(ctx_msg)
    payload.extend(leaf_message)
    
    return payload


def hash_leaf(sid: bytes, randomizer: bytes, leaf_index: int, ctx_msg: bytes, message: bytes, hash_alg: str, n: int) -> bytes:
    """
    To hash a message to produce a leaf node.
    :param sid: series identifier SID
    :param leaf_index: index of the leaf node
    :param randomizer: randomizer in bytes
    :param ctx_msg: context string (keeps empty in this demo)
    :param message: message to be signed and verified
    :param hash_alg: hash algorithm to use to generate node hashes
    :param n: security parameter
    """
    mtlleafADRS = LEAFADRS()
    mtlleafADRS.set_indexes(leaf_index)
    leaf_payload = generate_payload_leaf(sid, randomizer, mtlleafADRS, ctx_msg, message)
    leaf_hash = calculate_hash(leaf_payload, hash_alg, n)
    
    return leaf_hash


# -------------------------- Internal Nodes -------------------------- #
def generate_payload_internal(sid: bytes, adrs: ADRS, left_hash: bytes, right_hash: bytes) -> bytes:
    """
    Reference: draft-kaizer-dnsop-ml-dsa-mtl-dnssec-01 Section 5-2. 
    cSHAKE(SID || Left_Index || Right_Index || H_L || H_R)
    """
    payload = bytearray()

    # Concatenate
    payload.extend(sid)
    # ADRS contains (left,right)
    payload.extend(adrs.serialize())
    payload.extend(left_hash)
    payload.extend(right_hash)
    
    return payload


def hash_internal(sid: bytes, left_index: int, right_index: int, left_hash: bytes, right_hash: bytes, hash_alg: str, n: int) -> bytes:
    """
    To hash two child nodes to produce an internal node hash.
    :param sid: series identifier SID
    :param left_index: index of the left child node
    :param right_index: index of the right child node
    :param left_hash: hash value of the left child node
    :param right_hash: hash value of the right child node
    :param hash_alg: hash algorithm to use to generate node hashes
    :param n: security parameter
    """
    mtlinternalADRS = ADRS()
    mtlinternalADRS.set_indexes(left_index, right_index)
    internal_payload = generate_payload_internal(sid, mtlinternalADRS, left_hash, right_hash)
    internal_hash = calculate_hash(internal_payload, hash_alg, n)
    return internal_hash


def calculate_internal_nodes(sid: bytes, 
                             leaf_index: int, 
                             leaf_hash: bytes, 
                             sibling_list: list[dict[str, int | bytes]],
                             hash_alg: str,
                             n: int) -> list[dict[str, tuple | bytes]]:
    """
    To generate a list of internal nodes. 
    :param sid: series identifier SID
    :param leaf_index: index of the leaf node
    :param leaf_hash: hash value of the leaf node
    :param sibling_list: list of leaf node siblings
    :param hash_alg: hash algorithm to use to generate node hashes
    :param n: security parameter
    """
    num_internal = len(sibling_list)
    internal_nodes = []

    # Construct a dict for the leaf node
    leaf = {}
    leaf["left_index"] = int(leaf_index.hex(), 16)
    leaf["right_index"] = int(leaf_index.hex(), 16)
    leaf["hash"] = leaf_hash
    
    # Parents of internal nodes:
    for i in range(num_internal):
        internal = {}
        if i == 0:
            child1 = leaf
            child2 = sibling_list[i]
        else:
            child1 = internal_nodes[i-1]
            child2 = sibling_list[i]
            
        # No overlap in child1 and child2 index range
        if child1["right_index"] < child2["left_index"]:
            internal["left_index"] = child1["left_index"]
            internal["right_index"] = child2["right_index"]
            internal["left_hash"] = child1["hash"]
            internal["right_hash"] = child2["hash"]
        elif child2["right_index"] < child1["left_index"]:
            internal["left_index"] = child2["left_index"]
            internal["right_index"] = child1["right_index"]
            internal["left_hash"] = child2["hash"]
            internal["right_hash"] = child1["hash"]
        else:
            raise ValueError("Incorrect child node index.")
            
        internal["hash"] = hash_internal(
            sid=sid,
            left_index=internal["left_index"],
            right_index=internal["right_index"],
            left_hash=internal["left_hash"],
            right_hash=internal["right_hash"],
            hash_alg=hash_alg,
            n=n
        )
        internal_nodes.append(internal)

    return internal_nodes
# ---------------------------------------------------------------------------------------- #



# ----------------------------- Target Match with Ladder Rung ---------------------------- #
def compare_with_rung(internal_nodes, 
                      target_rung_lindex, 
                      target_rung_rindex,
                      rungs):
    """
    To compare the topmost internal node with the target rung. 
    :param internal_nodes: list of internal nodes
    :param target_rung_lindex: left index of the authentication path target rung
    :param target_rung_rindex: right index of the authentication path target rung
    :param rungs: list of rungs in a ladder
    """
    topmost = internal_nodes[-1]
    rung = None

    # Find the target rung hash
    for i in range(len(rungs)):
        if (rungs[i]["left_index"] == target_rung_lindex) and (rungs[i]["right_index"] == target_rung_rindex):
            rung = rungs[i]
            break

    if rung is None:
        raise ValueError("No rung found in ladder.")

    if topmost["hash"] == rung["hash"]:
        return True
    else:
        return False
# ---------------------------------------------------------------------------------------- #