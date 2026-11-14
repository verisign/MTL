from dataclasses import dataclass, field, InitVar
import os
import sys
import json
import hashlib
import math
import textwrap
import pandas as pd

from helper.utils import make_html


sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from verifier import hash_internal

## ---------------- Update the Node Set ---------------- ##
def update_nodeset(nodeset_filepath: str, updated_nodeset_path: str, hash_alg: str, n: int, node_rand: bytes, node_hash: bytes) -> dict:
    with open(nodeset_filepath, "r") as f:
        nodeset = json.load(f)

    sid = nodeset["sid"]
    new_index = nodeset["total_leaves"]
    nodeset["total_leaves"] += 1
    
    new_leaf = {
        "left_index": new_index,
        "right_index": new_index,
        "randomizer": node_rand.hex(),
        "hash": node_hash.hex()
    }
    nodeset["nodes"]["level_0"].append(new_leaf)
    
    # Update internal nodes bottom up
    current_level = 0
    while True:
        current_level_key = f"level_{current_level}"
        next_level_key = f"level_{current_level + 1}"
        
        current_level_nodes = nodeset["nodes"][current_level_key]
        
        # A parent node will be generated if the current level has even nodes
        if len(current_level_nodes) % 2 == 0:
            left_child = current_level_nodes[-2]
            right_child = current_level_nodes[-1]

            parent_hash = hash_internal(sid=bytes.fromhex(sid), 
                                        left_index=left_child["left_index"], 
                                        right_index=right_child["right_index"], 
                                        left_hash=bytes.fromhex(left_child["hash"]), 
                                        right_hash=bytes.fromhex(right_child["hash"]),
                                        hash_alg=hash_alg,
                                        n=n)
            
            new_parent = {
                "left_index": left_child["left_index"],
                "right_index": right_child["right_index"],
                "hash": parent_hash.hex()
            }
            
            # Create the next level it doesn't exist yet
            if next_level_key not in nodeset["nodes"]:
                nodeset["nodes"][next_level_key] = []
                
            nodeset["nodes"][next_level_key].append(new_parent)
            current_level += 1
        else:
            # If the current level has odd nodes
            break

    with open(updated_nodeset_path, 'w') as f:
        json.dump(nodeset, f, indent=2)
    print(f"\033[1;34mThe Node Set has been updated and saved.\033[0m")
    return nodeset
    


## ---------------- Get Target Rung ---------------- ##
def find_target_rung(nodeset: dict, leaf_index: int) -> dict:
    """
    Finds the rung that covers a given leaf node.
    """      
    # Validation check
    if leaf_index < 0 or leaf_index >= nodeset["total_leaves"]:
        raise ValueError(f"Leaf index {leaf_index} out of bounds. Total leaves: {nodeset['total_leaves']}")
    
    # Sort keys to start from the highest level down to level 0
    sorted_levels = sorted(nodeset["nodes"].keys(), key=lambda x: int(x.split('_')[1]), reverse=True)
    
    for level_key in sorted_levels:
        nodes_in_level = nodeset["nodes"][level_key]
        
        # Look for the node that covers the leaf_index
        for node in nodes_in_level:
            if node["left_index"] <= leaf_index <= node["right_index"]:
                # Add the level info to the node object for clarity
                result_node = node.copy()
                return result_node
    # If nothing found           
    return {} 



## ---------------- Get All Rungs ---------------- ##
def get_all_rungs(nodeset:dict) -> list[dict]:
    """
    To get rung nodes that collectively cover all leaves in a ladder.
    """
        
    total_leaves = nodeset["total_leaves"]
    if total_leaves == 0:
        return []

    # Sort levels from highest to lowest
    sorted_levels = sorted(nodeset["nodes"].keys(), key=lambda x: int(x.split('_')[1]), reverse=True)
    
    rung_nodes = []
    covered_indexes = set()

    for level_key in sorted_levels:
        nodes_in_level = nodeset["nodes"][level_key]
        
        for node in nodes_in_level:
            cover_range = set(range(node["left_index"], node["right_index"] + 1))
            
            # If this node covers any leaves that haven't been covered by any higher level nodes
            if not cover_range.issubset(covered_indexes):
                result_node = node.copy()
                result_node["level"] = level_key
                rung_nodes.append(result_node)
                
                # Update the covered set with these leaf nodes
                covered_indexes.update(cover_range)
                
        # if all leaves are covered
        if len(covered_indexes) == total_leaves:
            break
            
    rung_nodes.sort(key=lambda x: x["left_index"])

    for rung in rung_nodes:
        rung["left_index_int"] = rung["left_index"]
        rung["right_index_int"] = rung["right_index"]
        rung["left_index"] = rung["left_index"].to_bytes(8, byteorder="big")
        rung["right_index"] = rung["right_index"].to_bytes(8, byteorder="big")
    return rung_nodes



## ---------------- Construct A Leaf Node ---------------- ##
@dataclass
class LeafNode:
    lindex: InitVar[int]
    rindex: InitVar[int]

    message: bytes = field(init=False)
    randomizer: bytes = field(init=False)
    node_hash: bytes = field(init=False)
    rung_lindex: bytes = field(init=False)
    rung_rindex: bytes = field(init=False)
    rung_lindex_int: int = field(init=False)
    rung_rindex_int: int = field(init=False)
    rung_hash: bytes = field(init=False)
    siblings: list[bytes] = field(init=False)
    siblings_withindex: list[dict[str, int | bytes]] = field(init=False)
    authpath: bytes = field(init=False)
    

    def __post_init__(self, lindex: int, rindex: int):
        self.lindex = lindex
        self.rindex = rindex

    def leaf_print(self):
        leaf_data = {
            "Index": self.lindex,
            "Randomizer": self.randomizer.hex(" ", -4).upper(),
            "Hash": self.node_hash.hex(" ", -4).upper(),
            "Hash Length": len(self.node_hash),
        }
        df_leaf = pd.DataFrame(leaf_data.items(), columns=[f"Leaf Node {self.lindex, self.rindex}", "Value"])
        leaf_styled = (
            df_leaf.style.set_properties(
                **{
                    "color": "#000",
                    "background-color": "#d8ede9",
                    "border-color": "#dffaf5",
                    "border-style": "solid",
                    "border-width": "1.5px",
                    "font-family": "Segoe UI, Arial, sans-serif",
                    "padding": "8px",
                }
            )
            .set_properties(
                subset=[f"Leaf Node {self.lindex, self.rindex}"],
                **{"font-weight": "bold", "color": "#111111", "text-align": "left"},
            )
            .set_table_styles(
                [
                    {
                        "selector": "th",
                        "props": [
                            ("background-color", "#62b59d"),
                            ("color", "white"),
                            ("font-weight", "bold"),
                        ],
                    },
                    {
                        "selector": "",  # The outer wrapper
                        "props": [
                            ("border", "2.5px solid #62b59d"),
                            ("border-collapse", "collapse"),
                        ],
                    },
                    {
                        "selector": "th.col_heading:nth-of-type(1)",
                        "props": [("text-align", "left !important")],
                    },
                    {
                        "selector": "th:nth-of-type(2), td:nth-of-type(2)",
                        "props": [("text-align", "left !important")],
                    },
                ]
            )
            .hide(axis="index")
        )
        return make_html(leaf_styled, header_color="#62b59d", align={f"Leaf Node {self.lindex, self.rindex}": "left", 
                                                                     "Value": "left"})

    
    def targetrung_print(self):
        leaf_rung_data = {
            "Rung Left Index": self.rung_lindex_int,
            "Rung Right Index": self.rung_rindex_int,
            "Rung Hash": self.rung_hash.hex(" ", -4).upper(),
            "Rung Hash Length": len(self.rung_hash),
        }
        df_targetrung = pd.DataFrame(leaf_rung_data.items(), columns=[f"Leaf Node {self.lindex, self.rindex} Target Rung", "Value"])
        targetrung_styled = (
            df_targetrung.style.set_properties(
                **{
                    "color": "#000",
                    "background-color": "#dcedd8",
                    "border-color": "#dffaf5",
                    "border-style": "solid",
                    "border-width": "1.5px",
                    "font-family": "Segoe UI, Arial, sans-serif",
                    "padding": "8px",
                }
            )
            .set_properties(
                subset=[f"Leaf Node {self.lindex, self.rindex} Target Rung"],
                **{"font-weight": "bold", "color": "#111111", "text-align": "left"},
            )
            .set_table_styles(
                [
                    {
                        "selector": "th",
                        "props": [
                            ("background-color", "#68a858"),
                            ("color", "white"),
                            ("font-weight", "bold"),
                        ],
                    },
                    {
                        "selector": "",  # The outer wrapper
                        "props": [
                            ("border", "2.5px solid #68a858"),
                            ("border-collapse", "collapse"),
                        ],
                    },
                    {
                        "selector": "th.col_heading:nth-of-type(1)",
                        "props": [("text-align", "left !important")],
                    },
                    {
                        "selector": "th:nth-of-type(2), td:nth-of-type(2)",
                        "props": [("text-align", "left !important")],
                    },
                ]
            )
            .hide(axis="index")
        )
        return make_html(targetrung_styled, header_color="#68a858", align={f"Leaf Node {self.lindex, self.rindex} Target Rung": "left", 
                                                                           "Value": "left"})


    def leafsiblings_print(self):
        rows = []
        for i, row in enumerate(self.siblings_withindex, start=1):
            rows.append({
                f"Leaf Node {self.lindex, self.rindex} Sibling": f"Sibling {i} Left Index",
                "Value": row["left_index"],
            })
            rows.append({
                f"Leaf Node {self.lindex, self.rindex} Sibling": f"Sibling {i} Right Index",
                "Value": row["right_index"],
            }) 
            rows.append({
                f"Leaf Node {self.lindex, self.rindex} Sibling": f"Sibling {i} Hash",
                "Value": row["hash"].hex(" ", -4).upper(),
            })  
            rows.append({
                f"Leaf Node {self.lindex, self.rindex} Sibling": f"Sibling {i} Hash Length",
                "Value": len(row["hash"]),
            })
        df_siblings = pd.DataFrame(rows)

        SIBLING_BLOCK_COLORS = [
            "#edf5f3",
            "#d8ede7",
            "#c8ede3",
            "#b1ebda",
        ]

        def color_by_siblings(data: pd.DataFrame):
            style_df = pd.DataFrame("", index=data.index, columns=data.columns)
            for idx in range(len(data)):
                # Group each sibling for a color
                sibling_group_number = idx // 4
                color = SIBLING_BLOCK_COLORS[
                    sibling_group_number % len(SIBLING_BLOCK_COLORS)
                ]
                style_df.iloc[idx] = f"background-color: {color};"
            return style_df
        
        # Set style
        siblings_styled = (
            df_siblings.style.set_properties(
                **{
                    "color": "#000",
                    "border-color": "#dffaf5",
                    "border-style": "solid",
                    "border-width": "1.5px",
                    "font-family": "Segoe UI, Arial, sans-serif",
                    "padding": "8px",
                }
            )
            .apply(color_by_siblings, axis=None)
            .set_properties(
                subset=[f"Leaf Node {self.lindex, self.rindex} Sibling"],
                **{"font-weight": "bold", "color": "#111111", "text-align": "left"},
            )
            .set_table_styles(
                [
                    {
                        "selector": "th",
                        "props": [
                            ("background-color", "#56a69f"),
                            ("color", "white"),
                            ("font-weight", "bold"),
                        ],
                    },
                    {
                        "selector": "",  # The outer wrapper
                        "props": [
                            ("border", "2.5px solid #56a69f"),
                            ("border-collapse", "collapse"),
                        ],
                    },
                    {
                        "selector": "th.col_heading:nth-of-type(1)",
                        "props": [("text-align", "left !important")],
                    },
                    {
                        "selector": "th:nth-of-type(2), td:nth-of-type(2)",
                        "props": [("text-align", "left !important")],
                    },
                ]
            )
            .hide(axis="index")
        )
        return make_html(siblings_styled, header_color="#56a69f", align={f"Leaf Node {self.lindex, self.rindex} Sibling": "left", 
                                                                         "Value": "left"})


    def authpath_print(self):
        leaf_autnpath_data = {
            "Left Index": self.lindex,
            "Right Index": self.rindex,
            "Authentication Path": self.authpath.hex(" ", -4).upper(),
            "Authentication Path Length": len(self.authpath),
        }
        df_authpath = pd.DataFrame(leaf_autnpath_data.items(), columns=[f"Leaf Node {self.lindex, self.rindex} Authentication Path", "Value"])
        authpath_styled = (
            df_authpath.style.set_properties(
                **{
                    "color": "#000",
                    "background-color": "#d0e8d3",
                    "border-color": "#dffaf5",
                    "border-style": "solid",
                    "border-width": "1.5px",
                    "font-family": "Segoe UI, Arial, sans-serif",
                    "padding": "8px",
                }
            )
            .set_properties(
                subset=[f"Leaf Node {self.lindex, self.rindex} Authentication Path"],
                **{"font-weight": "bold", "color": "#111111", "text-align": "left"},
            )
            .set_table_styles(
                [
                    {
                        "selector": "th",
                        "props": [
                            ("background-color", "#358c41"),
                            ("color", "white"),
                            ("font-weight", "bold"),
                        ],
                    },
                    {
                        "selector": "",  # The outer wrapper
                        "props": [
                            ("border", "2.5px solid #358c41"),
                            ("border-collapse", "collapse"),
                        ],
                    },
                    {
                        "selector": "th.col_heading:nth-of-type(1)",
                        "props": [("text-align", "left !important")],
                    },
                    {
                        "selector": "th:nth-of-type(2), td:nth-of-type(2)",
                        "props": [
                            ("max-width", "400px"),
                            ("white-space", "normal !important"),
                            ("word-break", "break-word"), 
                            ("text-align", "left !important"),
                        ],
                    },
                ]
            )
            .hide(axis="index")
        )
        return make_html(authpath_styled, header_color="#358c41", align={f"Leaf Node {self.lindex, self.rindex} Authentication Path": "left", 
                                                                         "Value": "left"})
        



## ---------------- Find Siblings of the Given Leaf Node ---------------- ##
def get_sibling_nodes(nodeset: dict, leaf_index: int) -> list[dict]:
    """
    To get all sibling nodes for a given leaf node.
    """      
    total_leaves = nodeset["total_leaves"]
    if leaf_index < 0 or leaf_index >= total_leaves:
        raise ValueError(f"Leaf index {leaf_index} out of bounds.")

    siblings = []
    
    # Sort levels from bottom to top
    sorted_levels = sorted(nodeset["nodes"].keys(), key=lambda x: int(x.split('_')[1]))
    
    for level_key in sorted_levels:
        level_nodes = nodeset["nodes"][level_key]
        
        # Find the node at this level that covers the leaf
        target_node_idx = None
        for i, node in enumerate(level_nodes):
            if node["left_index"] <= leaf_index <= node["right_index"]:
                target_node_idx = i
                break
                
        # If no node at this level covers the leaf
        if target_node_idx is None:
            break
            
        # Get the sibling index at this level
        if target_node_idx % 2 == 0:
            # Sibling is to the right
            sibling_idx = target_node_idx + 1
        else:
            # Sibling is to the left
            sibling_idx = target_node_idx - 1
            
        # If the sibling exists at this level
        if 0 <= sibling_idx < len(level_nodes):
            sibling_node = level_nodes[sibling_idx].copy()
            sibling_node["level"] = level_key
            siblings.append(sibling_node)
            
    return siblings



def allrungs_print(rung_list: list[dict]):
    rows = []
    for i, row in enumerate(rung_list, start=1):
        rows.append({
            "Field": f"Rung {i} Left Index",
            "Field Length (bytes)": len(row["left_index"]),
            "Field Data": row["left_index"].hex(" ", -4).upper()
        })
        rows.append({
            "Field": f"Rung {i} Right Index",
            "Field Length (bytes)": len(row["right_index"]),
            "Field Data": row["right_index"].hex(" ", -4).upper()
        }) 
        rows.append({
            "Field": f"Rung {i} Hash Value",
            "Field Length (bytes)": len(bytes.fromhex(row["hash"])),
            "Field Data": {" ".join(textwrap.wrap(row["hash"].upper(), 8))}
        })  
    df_rung = pd.DataFrame(rows)

    # Colors for different rungs
    RUNG_BLOCK_COLORS = [
        "#fcf8e4",
        "#f0ede0",
        "#f7efca",
        "#ebe7d6",
    ]

    # Set each rung a color for clarity
    def color_by_blocks(data: pd.DataFrame):
        style_df = pd.DataFrame("", index=data.index, columns=data.columns)
        for idx in range(len(data)):
           # Group each rung for a color
            rung_group_number = idx // 3
            color = RUNG_BLOCK_COLORS[
                rung_group_number % len(RUNG_BLOCK_COLORS)
            ]
            style_df.iloc[idx] = f"background-color: {color};"
        return style_df
    
    # Set style
    df_styled = (
        df_rung.style
            .set_uuid("rung_printout")
            .set_properties(
            **{
                "color": "#000",
                "border-color": "#dee2e6",
                "border-style": "solid",
                "border-width": "1.5px",
                "font-family": "Segoe UI, Arial, sans-serif",
                "padding": "8px",
            }
        )
        .apply(color_by_blocks, axis=None)
        .set_properties(
            subset=["Field"],
            **{"font-weight": "bold", "color": "#111111", "text-align": "left"},
        )
        .set_table_styles(
            [
                {
                    "selector": "th",
                    "props": [
                        ("background-color", "#bf9d06"),
                        ("color", "white"),
                        ("font-weight", "bold"),
                    ],
                },
                {
                    "selector": "",  # The outer wrapper
                    "props": [
                        ("border", "2.5px solid #bf9d06"),
                        ("border-collapse", "collapse"),
                    ],
                },
                {
                    "selector": "th.col_heading:nth-of-type(1)",
                    "props": [("text-align", "left !important")],
                },
                {
                    # Center-aligned: both header and data
                    "selector": "th:nth-of-type(2), td:nth-of-type(2)",
                    "props": [("text-align", "center !important")],
                },
                {
                    # Left-aligned: both header and data
                    "selector": "th:nth-of-type(3), td:nth-of-type(3)",
                    "props": [("text-align", "left !important")],
                },
            ]
        )
        .hide(axis="index")
    )
    return make_html(df_styled, header_color="#bf9d06", align={"Field": "left", 
                                                               "Field Length (bytes)": "center",
                                                               "Field Data": "left"})
