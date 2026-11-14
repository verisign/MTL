import json


## ----------------------------- Extract From A Given Node Set ----------------------------- ##
def extract_mtl_ladder(node_set_data: dict | str) -> dict:
    """
    To extract the MTL from a given node set using the binary rung strategy.
    """
    # If a string
    if isinstance(node_set_data, str):
        node_set = json.loads(node_set_data)
    # If follows the pre-defined format
    else:
        node_set = node_set_data

    total_leaves = node_set["total_leaves"]
    nodes_by_level = node_set["nodes"]
    
    ladder = []
    current_idx = 0
    
    # Convert total_leaves to binary to find the height
    binary_str = bin(total_leaves)[2:]
    bit_length = len(binary_str)
    
    for i, bit in enumerate(binary_str):
        if bit == "1":
            # The height matches the bit position index
            level = bit_length - 1 - i
            num_covered_leaves = 1 << level
            right_index = current_idx + num_covered_leaves - 1
            
            # Find the matching node at this level
            level_key = f"level_{level}"
            found_rung = None
            
            if level_key in nodes_by_level:
                for node in nodes_by_level[level_key]:
                    if node["left_index"] == current_idx and node["right_index"] == right_index:
                        found_rung = {
                            "level": level,
                            "left_index": node["left_index"],
                            "right_index": node["right_index"],
                            "hash": node["hash"]
                        }
                        break
            
            if found_rung:
                ladder.append(found_rung)
            else:
                raise ValueError(f"Required rung for range ({current_idx}, {right_index}) at level {level} not found in node set.")
            
            # Move the pointer forward to the next leaf subset
            current_idx += num_covered_leaves

    return {
        "treeid": node_set["treeid"],
        "sid": node_set["sid"],
        "total_leaves": total_leaves,
        "ladder": ladder
    }




## ----------------------------- Construct A Ladder In Bytes ----------------------------- ##
def construct_mtl_ladder(ladder_data: dict) -> bytes:
    """
    To construct a MTL ladder in bytes using the extracted MTL ladder data.
    """
    # Ladder flag: must be 0x0000
    ladder_bytes = (0).to_bytes(2, byteorder="big")

    # Ladder SID
    ladder_bytes += bytes.fromhex(ladder_data["sid"])
    # Ladder rung count
    ladder_bytes += len(ladder_data["ladder"]).to_bytes(2, byteorder="big")

    # Ladder rung data
    for rung in ladder_data["ladder"]:
        # Rung left index
        ladder_bytes += rung["left_index"].to_bytes(8, byteorder="big")
        # Rung right index
        ladder_bytes += rung["right_index"].to_bytes(8, byteorder="big")
        # Rung hash
        ladder_bytes += bytes.fromhex(rung["hash"])
        
    return ladder_bytes