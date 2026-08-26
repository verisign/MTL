from dataclasses import dataclass, field, InitVar


## ------------------------ SID ----------------------- ##
def parse_mtl_type(fullsig: str, n: int) -> bytes:
    """
    To parse the full signature to obtain the MTL Type
    :param fullsig: full signature in bytes
    :param n: security parameter
    """
    # Signature format: 1 byte
    sig_format = fullsig[:1]

    print("─" * 50)
    print(f"MTL-Type: {sig_format.hex(' ', -4).upper()}    - {len(sig_format)} byte")
    print("─" * 50)
    
    return sig_format
## ------------------------------------------------------##


## ---------------- Authentication Path ---------------- ##
@dataclass
class AuthPath:
    fullsig: InitVar[bytes]
    n: InitVar[int]

    flag: bytes = field(init=False)
    sid: bytes = field(init=False)
    randomizer: bytes = field(init=False)
    leaf_index: bytes = field(init=False)
    rung_lindex: bytes = field(init=False)
    rung_rindex: bytes = field(init=False)
    sibling_cnt: int = field(init=False)
    siblings: list[bytes] = field(init=False)
    end_index: int = field(init=False)
    siblings_withindex: list[dict[str, int | bytes]] = field(init=False)
    leaf_node: bytes = field(init=False)
    internal_nodes: list[dict[str, bytes]] = field(init=False)

    def __post_init__(self, fullsig: bytes, n: int):
        self.flag = self.authpath_get_flag(fullsig, n)
        self.sid = self.authpath_get_sid(fullsig, n)
        self.randomizer = self.authpath_get_randomizer(fullsig, n)
        self.leaf_index = self.authpath_get_leaf_index(fullsig, n)
        self.rung_lindex = self.authpath_get_left_index(fullsig, n)
        self.rung_rindex = self.authpath_get_right_index(fullsig, n)
        self.sibling_cnt = self.authpath_get_sibling_cnt(fullsig, n)
        self.siblings, self.end_index = self.authpath_get_siblings(self.sibling_cnt, fullsig, n)
        temp_sibling_indexes = self.authpath_get_sibling_index(int(self.leaf_index.hex(), 16), self.sibling_cnt)
        self.siblings_withindex = self.authpath_siblings_withindex(temp_sibling_indexes)

    def authpath_get_flag(self, fullsig: bytes, n: int) -> bytes:
        return fullsig[1:3]

    def authpath_get_sid(self, fullsig: bytes, n: int) -> bytes:
        return fullsig[3:2*n+3]

    def authpath_get_randomizer(self, fullsig: bytes, n: int) -> bytes:
        return fullsig[2*n+3:3*n+3]    

    def authpath_get_leaf_index(self, fullsig: bytes, n: int) -> bytes:
        return fullsig[3*n+3:3*n+11]  

    def authpath_get_left_index(self, fullsig: bytes, n: int) -> bytes:
        return fullsig[3*n+11:3*n+19]  

    def authpath_get_right_index(self, fullsig: bytes, n: int) -> bytes:
        return fullsig[3*n+19:3*n+27]                
    
    def authpath_get_sibling_cnt(self, fullsig: bytes, n: int) -> bytes:
        cnt_bytes = fullsig[(n*3+27):(n*3+29)]
        return int(cnt_bytes.hex(), 16)

    
    def authpath_get_siblings(self, siblings_cnt: int, fullsig: bytes, n: int) -> bytes:
        """
        To get the list of sibling hashes.
        :param siblings_cnt: number of siblings
        :param fullsig: full signature in bytes
        :param n: security parameter
        """
        def get_siblings(input_bytes, node_hash_len):
            return [input_bytes[i : i + node_hash_len] for i in range(0, len(input_bytes), node_hash_len)]
    
        # Each node hash is n-byte long
        end_sibling_index = siblings_cnt * n + (n * 3 + 29)
        siblings = get_siblings(fullsig[(n*3+29):end_sibling_index], n)
        return siblings, end_sibling_index

    
    def authpath_get_sibling_index(self, leaf_index, num_siblings):
        """
        To get the list of sibling indexes.
        :param leaf_index: index of the leaf node
        :param num_siblings: number of siblings
        """
        siblings = []
        curr_l = leaf_index
        curr_r = leaf_index
        
        for level in range(num_siblings):
            # Width
            block_size = curr_r - curr_l + 1
            
            # If the left index divided by block size is even, it is a left child
            if (curr_l // block_size) % 2 == 0:
                # Sibling is to the right
                sib_l = curr_r + 1
                sib_r = curr_r + block_size
            else:
                # Sibling is to the left
                sib_l = curr_l - block_size
                sib_r = curr_l - 1
                
            siblings.append((level, sib_l, sib_r))
            
            # Move up
            curr_l = min(curr_l, sib_l)
            curr_r = max(curr_r, sib_r)
            
        return siblings

        
    def authpath_siblings_withindex(self, sibling_indexes):
        pairs = list(zip(sibling_indexes, self.siblings))
        list_siblings_index = []
        for (level, left, right), data in pairs:
            sibling_dict = {}
            sibling_dict["level"] = level
            sibling_dict["left_index"] = left
            sibling_dict["right_index"] = right
            sibling_dict["hash"] = data
            list_siblings_index.append(sibling_dict)
        return list_siblings_index


    def authpath_print(self): 
        print("─" * 50)
        print("Authentication Path:")
        print("-" * 30)
        print(f"  Authentication Flags: {self.flag.hex(' ', -4).upper()}    - {len(self.flag)} bytes")
        print("-" * 30)
        print(f"  Series Identifier SID: {self.sid.hex(' ', -4).upper()}    - {len(self.sid)} bytes")        
        print("-" * 30)
        print(f"  Randomizer: {self.randomizer.hex(' ', -4).upper()}    - {len(self.randomizer)} bytes")
        print("-" * 30)
        print(f"  Leaf Index: {self.leaf_index.hex(' ', -4).upper()}    - {len(self.leaf_index)} bytes")
        print("-" * 30)
        print(f"  Target Rung Left Index: {self.rung_lindex.hex(' ', -4).upper()}    - {len(self.rung_lindex)} bytes")
        print("-" * 30)
        print(f"  Target Rung Right Index: {self.rung_rindex.hex(' ', -4).upper()}    - {len(self.rung_rindex)} bytes")
        print("-" * 30)
        print(f"  Sibling Hash Count: {self.sibling_cnt}")
        print("-" * 30)
        print("  Sibling Node Hash Values:")
        for s in self.siblings:
            print(f"    {s.hex(' ', -4).upper()}    - {len(s)} bytes")
        
        print("─" * 50)
        for sibling in self.siblings_withindex:
            print(f"Level {sibling["level"]} Sibling:")
            print(f"  Left Index: {sibling["left_index"]}")
            print(f"  Right Index: {sibling["right_index"]}")
            print(f"  Hash Value: {sibling["hash"].hex(" ", -4).upper()}")
            print("-" * 30)
        print("─" * 50)
## -------------------------------------------------------##


## ----------------------- Ladder ----------------------- ##
@dataclass
class Ladder:
    fullsig: InitVar[bytes]
    n: InitVar[int]
    authpath_instance: InitVar['AuthPath'] 

    val: bytes = field(init=False)
    flag: bytes = field(init=False)
    sid: bytes = field(init=False)
    rung_cnt: int = field(init=False)
    rungs: list[dict[str, bytes]] = field(init=False)
    end: int = field(init=False)
    sig_len: bytes = field(init=False)
    signature: bytes = field(init=False)
    mtl_structure: list[list[str]] = field(init=False)

    def __post_init__(self, fullsig: bytes, n: int, authpath_instance: "AuthPath"):
        self.start = authpath_instance.end_index
        self.flag = self.ladder_get_flag(fullsig[self.start:], n)
        self.sid = self.ladder_get_sid(fullsig[self.start:], n)
        self.rung_cnt = self.ladder_get_rung_cnt(fullsig[self.start:], n)
        self.rungs, tmp_end_index = self.ladder_get_rungs(self.rung_cnt, fullsig[self.start:], n)
        self.end = tmp_end_index + self.start
        self.val = fullsig[self.start:self.end]
        self.sig_len = self.get_ladder_siglen(fullsig)
        self.signature = self.get_ladder_sig(fullsig)

    def ladder_get_flag(self, ladder: bytes, n: int) -> bytes:
        return ladder[:2]
    
    def ladder_get_sid(self, ladder: bytes, n: int) -> bytes:
        return ladder[2:2*n+2]
    
    def ladder_get_rung_cnt(self, ladder: bytes, n: int) -> bytes:
        cnt_bytes = ladder[(2*n+2):(2*n+4)]
        return int(cnt_bytes.hex(), 16)
    
    def ladder_get_rungs(self, rung_cnt: int, ladder: bytes, n: int) -> bytes:
        """
        To get all rungs.
        :param rung_cnt: number of rungs in a ladder
        :param ladder: ladder
        """
        def get_rungs(rung_cnt, input_bytes, rung_hash_len):
            rung_list = []
            for i in range(rung_cnt):
                rung_dict = {}
                start = (16 + rung_hash_len) * i
                rung_dict["left_index"] = input_bytes[start:start+8]
                rung_dict["left_index_int"] = int(rung_dict["left_index"].hex(), 16)
                rung_dict["right_index"] = input_bytes[start+8:start+16]
                rung_dict["right_index_int"] = int(rung_dict["right_index"].hex(), 16)
                rung_dict["hash"] = input_bytes[(start+16):(start+16+rung_hash_len)]
                rung_list.append(rung_dict)
            return rung_list
    
        # Each ladder index is 8-byte long, each ladder rung hash is n-byte long
        end_rung = (2 * n + 4) + rung_cnt * (8 + 8 + n)
        rungs = get_rungs(rung_cnt, ladder[(2*n+4):end_rung], n)
        return rungs, end_rung

    
    def ladder_print(self):
        print("─" * 50)
        print("Ladder:")
        print("-" * 30)
        print(f"  Ladder Flags: {self.flag.hex(' ', -4).upper()}    - {len(self.flag)} bytes")
        print("-" * 30)
        print(f"  Ladder Series Identifier SID: {self.sid.hex(' ', -4).upper()}    - {len(self.sid)} bytes")
        print("-" * 30)
        print(f"  Ladder Rung Count: {self.rung_cnt}")
        print("-" * 30)
        print("  Ladder Rung:")
        for r in self.rungs:
            print("-" * 30)
            print(f"    Rung Left Index: {r["left_index"].hex(" ", -4).upper()}")
            print(f"    Rung Right Index: {r["right_index"].hex(" ", -4).upper()}")
            print(f"    Rung Hash Value: {r["hash"].hex(" ", -4).upper()}")
        print("─" * 50)


    def get_ladder_siglen(self, fullsig: bytes) -> bytes:
        siglen_start_index = self.end
        ladder_sig_len = fullsig[siglen_start_index:(siglen_start_index+4)]
        return ladder_sig_len
    
    def get_ladder_sig(self, fullsig: bytes) -> bytes: 
        sig_start_index = self.end + 4
        ladder_sig = fullsig[sig_start_index:]
        return ladder_sig
## ------------------------------------------------------ ##