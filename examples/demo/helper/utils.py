from datetime import datetime
import struct

## --------------------------- DNSSEC Signed Data Generation ---------------------------- ##
def create_dnssec_signed_data(rrsig_meta: dict[str, int | str], rrset: list[dict[str, int | str]]) -> bytes:
    """
    To construct the byte object that will be signed for DNSSEC.
    :param rrsig_meta: RRSIG RDATA portion
    :param rrset: RRset
    """
    def encode_domain(domain):
        """
        To encode a domain name into wire format. 
        """
        domain = domain.lower().strip(".")
        components = domain.split(".")
        return b"".join(len(component).to_bytes(1, "big") + \
                        component.encode("ascii") for component in components) + \
                        b"\x00"

    def to_unix_time(dnssec_time):
        """
        To convert YYYYMMDDHHMMSS to Unix timestamp.
        """
        # Convert to string if it was passed as an integer
        time_str = str(dnssec_time)
        dt = datetime.strptime(time_str, "%Y%m%d%H%M%S")
        return int(dt.timestamp())

    # Convert to Unix integers
    exp_unix = to_unix_time(rrsig_meta["sig_expiration"])
    inc_unix = to_unix_time(rrsig_meta["sig_inception"])

    # RRSIG RDATA
    # Type Covered (2), Algorithm (1), Labels (1), Original TTL (4), 
    # Sig Expiration (4), Sig Inception (4), Key Tag (2)
    sig_data = struct.pack(
        "!HBBIIIH",
        rrsig_meta["type_covered"],
        rrsig_meta["algorithm"],
        rrsig_meta["labels"],
        rrsig_meta["original_ttl"],
        exp_unix,
        inc_unix,
        rrsig_meta["key_tag"]
    )
    # Signer's Name
    sig_data += encode_domain(rrsig_meta["signer_name"])

    # Canonicalize and sort RRset
    rrset_sorted = sorted(rrset, key = lambda x: x["rdata"])

    for rr in rrset_sorted:
        # RR: Owner Name | Type | Class | (Original) TTL | RDLENGTH | RDATA
        sig_data += encode_domain(rr["name"])
        sig_data += struct.pack(
            "!HHIH",
            rr["type"],
            rr["class"],
            rrsig_meta["original_ttl"],
            len(rr["rdata"])
        )
        sig_data += rr["rdata"]

    return sig_data



## ------------------------------ MTL Visualization -------------------------------- ##
def calculate_total_leaves(rungs: list[dict[str, bytes]]) -> int:
    if not rungs:
        return 0
    
    max_right_index = max(rung["right_index_int"] for rung in rungs)
    return max_right_index + 1


def get_rung_index(rungs: list[dict[str, bytes]]) -> list[tuple]:
    if not rungs:
        return None

    index_list = []
    for rung in rungs:
        index_list.append((rung["left_index_int"], rung["right_index_int"]))
    return index_list


def generate_merkle_ladder(total_nodes: int, rungs: list[tuple[int, int]]) -> list[list[str]]:
    """
    To get all layers of nodes in a MTL.
    :param total_nodes: number of nodes in a MTL
    :param rungs: list of rungs in the corresponding ladder
    """
    rung_set = set(rungs)
    output_rungs = set()
    
    # Leaf Layer
    current_level = [(i, i) for i in range(total_nodes)]
    
    layers = []
    layers.append([str(i) for i, _ in current_level])

    while len(current_level) > 1:
        next_level = []
        level_strs = []
        i = 0
        
        while i < len(current_level):
            left_node = current_level[i]
            
            # Situation 1: current node is a rung
            if left_node in rung_set:
                if left_node not in output_rungs:
                    level_strs.append(f"{left_node}*")
                    output_rungs.add(left_node)
                    # Stop
                    i += 1
                    continue
                
            # Situation 2: a valid adjacent right node to pair up with
            if i + 1 < len(current_level):
                right_node = current_level[i+1]
                
                if right_node not in rung_set:
                    internal_node = (left_node[0], right_node[1])
                    next_level.append(internal_node)

                    if internal_node not in output_rungs:
                        marker = "*" if internal_node in rung_set else ""
                        level_strs.append(f"{internal_node}{marker}")
                        if internal_node in rung_set:
                            output_rungs.add(internal_node)
                    i += 2
                    continue

            # Situation 3: node cannot merge right
            if left_node not in output_rungs:
                level_strs.append(f"{left_node}")
            next_level.append(left_node)
            i += 1
            
        if level_strs:
            layers.append(level_strs)
            
        # Break if no new internal node can be obtained
        if current_level == next_level or not next_level:
            break
            
        current_level = next_level

    # Reverse to output from top
    return layers[::-1]


def format_tree_ascii(layers):
    """
    Renders a level-by-level node list into an aligned ASCII tree map.
    """
    # Pad rows to make each parent node aligns with children
    max_cols = len(layers[-1])
    padded_tree = []
    for r_idx, level in enumerate(layers):
        padded_level = list(level)
        # Expected nodes at this level if is a perfect binary tree
        expected_count = 2 ** r_idx 
        while len(padded_level) < min(expected_count, max_cols):
            padded_level.append(None)
        padded_tree.append(padded_level)

    # Track offsets based on leaf
    leaf_positions = []
    current_pos = 0
    bottom_row_strs = []
    
    for idx, item in enumerate(padded_tree[-1]):
        val = str(item) if item is not None else ""
        pad_left = " " * 3
        pad_right = " " * 2
        full_str = f"{pad_left}{val}{pad_right}"
        
        # Keep track of center-point index
        if idx % 2 == 0:
            center = current_pos + len(pad_left) + (len(val) // 2) + 1
        else:
            center = current_pos + len(pad_left) + (len(val) // 2) - 1
        leaf_positions.append(center)
        bottom_row_strs.append(full_str)
        current_pos += len(full_str)

    # Output lines container: built from bottom to top
    output_lines = ["".join(bottom_row_strs).rstrip()]
    current_positions = leaf_positions

    # Traverse upward through remaining levels
    for r_idx in range(len(padded_tree) - 2, -1, -1):
        row = padded_tree[r_idx]
        next_positions = []
        
        # Buffers for specific layer block
        branch_line = [" "] * current_pos
        h_line = [" "] * current_pos
        pipe_line = [" "] * current_pos
        node_line = [" "] * current_pos

        for i, node in enumerate(row):
            if node is None:
                next_positions.append(None)
                continue
                
            # Find left and right children column indexes
            left_child_idx = i * 2
            right_child_idx = i * 2 + 1
            
            left_c = current_positions[left_child_idx] if left_child_idx < len(current_positions) else None
            right_c = current_positions[right_child_idx] if right_child_idx < len(current_positions) else None

            # Calculate centering anchors
            if left_c is not None and right_c is not None:
                center = (left_c + right_c) // 2
                
                # Draw connectors between left and right child positions
                branch_line[left_c] = "/"
                branch_line[right_c] = "\\"
                for b in range(left_c + 1, center):
                    branch_line[b] = "-"
                for b in range(center + 1, right_c):
                    branch_line[b] = "-"
                    
            elif left_c is not None:
                center = left_c
                branch_line[center] = "|"
            else:
                # Disconnect right-side node with no children
                # Align it above its bottom leaf position
                center = leaf_positions[min(i * (2**(len(padded_tree)-1-r_idx)), len(leaf_positions)-1)]

            next_positions.append(center)
            
            # Place intermediary H and vertical lines
            h_line[center] = "H"
            pipe_line[center] = "|"

            # Center the string
            node_str = str(node)
            start_x = center - (len(node_str) // 2)
            for char_idx, char in enumerate(node_str):
                if 0 <= start_x + char_idx < len(node_line):
                    node_line[start_x + char_idx] = char

        # Add structural lines
        if any(c != " " for c in branch_line):
            output_lines.append("".join(branch_line).rstrip())
        output_lines.append("".join(h_line).rstrip())
        output_lines.append("".join(pipe_line).rstrip())
        output_lines.append("".join(node_line).rstrip())
        
        current_positions = next_positions

    # Reverse to top-to-bottom
    return "\n".join(reversed(output_lines))
## --------------------------------------------------------------------------------- ##