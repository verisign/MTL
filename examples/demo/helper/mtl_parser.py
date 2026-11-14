from dataclasses import dataclass, field, InitVar
from typing import Optional
import pandas as pd

from helper.utils import make_html


## ------------------------ SID ----------------------- ##
def parse_mtl_type(fullsig: str, n: int) -> bytes:
    """
    To parse the full signature to obtain the MTL Type. 
    Parameters:
    -----------
    fullsig: full signature in bytes
    n      : security parameter
    """
    # Signature format: 1 byte
    return fullsig[:1]

    
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
        Parameters:
        -----------
        siblings_cnt: number of siblings
        fullsig     : full signature in bytes
        n           : security parameter
        """
        def get_siblings(input_bytes, node_hash_len):
            return [input_bytes[i : i + node_hash_len] for i in range(0, len(input_bytes), node_hash_len)]
    
        # Each node hash is n-byte long
        if siblings_cnt == 0:
            return [], n * 3 + 29
        end_sibling_index = siblings_cnt * n + (n * 3 + 29)
        siblings = get_siblings(fullsig[(n*3+29):end_sibling_index], n)
        return siblings, end_sibling_index

    
    def authpath_get_sibling_index(self, leaf_index: int, num_siblings: int) -> list:
        """
        To get the list of sibling indexes. 
        Parameters:
        -----------
        leaf_index  : index of the leaf node
        num_siblings: number of siblings
        """
        siblings = []
        curr_l = leaf_index
        curr_r = leaf_index

        if num_siblings == 0:
            return siblings
        
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

        
    def authpath_siblings_withindex(self, sibling_indexes: list):
        if not sibling_indexes:
            return [] 
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
        authpath_data = {
            "Flag": self.flag,
            "SID": self.sid,
            "Randomizer": self.randomizer,
            "Leaf Index": self.leaf_index,
            "Target Rung Left Index": self.rung_lindex,
            "Target Rung Right Index": self.rung_rindex,
            "Sibling Count": self.sibling_cnt.to_bytes(2, "big"),
        }
        df_authpath = pd.DataFrame(list(authpath_data.items()), columns=["AuthPath Field", "Value"])
        df_authpath["Field Length (bytes)"] = df_authpath["Value"].apply(lambda x: len(x) if isinstance(x, bytes) else "")
        df_authpath["Field Data"] = df_authpath["Value"].apply(lambda x: x.hex(" ", 4).upper() if isinstance(x, bytes) else x)
        df_authpath = df_authpath[["AuthPath Field", "Field Length (bytes)", "Field Data"]]

        # Siblings
        rows = []
        for i, row in enumerate(self.siblings_withindex):
            rows.append({
                "AuthPath Field": f"Level {i} Sibling Left Index",
                "Field Length (bytes)": len(row["left_index"].to_bytes(8, "big")),
                "Field Data": row["left_index"].to_bytes(8, "big").hex(" ", -4).upper()
            })
            rows.append({
                "AuthPath Field": f"Level {i} Sibling Right Index",
                "Field Length (bytes)": len(row["right_index"].to_bytes(8, "big")),
                "Field Data": row["right_index"].to_bytes(8, "big").hex(" ", -4).upper()
            }) 
            rows.append({
                "AuthPath Field": f"Level {i} Sibling Hash Value",
                "Field Length (bytes)": len(row["hash"]),
                "Field Data": row["hash"].hex(" ", -4).upper()
            })  
        df_siblings = pd.DataFrame(rows)

        
        # Combine two DataFrame
        df_combined = pd.concat([df_authpath, df_siblings], ignore_index=True).fillna("")

        # Colors for different siblings
        SIBLING_BLOCK_COLORS = [
            "#edf5f3",
            "#d8ede7",
            "#c8ede3",
            "#b1ebda",
        ]

        # Set each sibling a color for clarity
        NUM_SIBLING_ROWS = len(df_authpath)
        def color_by_blocks(data: pd.DataFrame):
            style_df = pd.DataFrame("", index=data.index, columns=data.columns)
        
            for idx in range(len(data)):
                if idx < NUM_SIBLING_ROWS:
                    # Shared authpath rows
                    style_df.iloc[idx] = "background-color: #ced4f2;"
                else:
                    # Get to the sibling index
                    sibling_row_idx = idx - NUM_SIBLING_ROWS
        
                    # Group each sibling for a color
                    sibling_group_number = sibling_row_idx // 3
                    color = SIBLING_BLOCK_COLORS[
                        sibling_group_number % len(SIBLING_BLOCK_COLORS)
                    ]
                    style_df.iloc[idx] = f"background-color: {color};"
            return style_df
        
        # Set style
        df_styled = (
            df_combined.style
                .set_uuid("authpath_printout")
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
                subset=["AuthPath Field"],
                **{"font-weight": "bold", "color": "#111111", "text-align": "left"},
            )
            .set_table_styles(
                [
                    {
                        "selector": "th",
                        "props": [
                            ("background-color", "#546feb"),
                            ("color", "white"),
                            ("font-weight", "bold"),
                        ],
                    },
                    {
                        "selector": "",  # The outer wrapper
                        "props": [
                            ("border", "2.5px solid #546feb"),
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
        return make_html(df_styled, header_color="#546feb", align={"AuthPath Field": "left", 
                                                                   "Field Length (bytes)": "center",
                                                                   "Field Data": "left"})


    def leaf_print(self):
        leaf_idx = int.from_bytes(self.leaf_index, byteorder='big')
        leaf_data = {
            "Index": int(self.leaf_index.hex(), 16),
            "Randomizer": self.randomizer.hex(" ", -4).upper(),
            "Hash": self.leaf_node.hex(" ", -4).upper(),
            "Hash Length": len(self.leaf_node),
        }
        df_leaf = pd.DataFrame(leaf_data.items(), columns=[f"Leaf Node {leaf_idx, leaf_idx}", "Value"])
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
                subset=[f"Leaf Node {leaf_idx, leaf_idx}"],
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
        return make_html(leaf_styled, header_color="#62b59d", align={f"Leaf Node {leaf_idx, leaf_idx}": "left", 
                                                                     "Value": "left"})


    def internal_print(self):
        leaf_idx = int.from_bytes(self.leaf_index, byteorder='big')
        rows = []
        for i, row in enumerate(self.internal_nodes, start=1):
            rows.append({
                f"Internal Node for Leaf {leaf_idx, leaf_idx}": f"Internal Node {i} Left Index",
                "Value": row["left_index"],
            })
            rows.append({
                f"Internal Node for Leaf {leaf_idx,leaf_idx}": f"Internal Node {i} Right Index",
                "Value": row["right_index"],
            }) 
            rows.append({
                f"Internal Node for Leaf {leaf_idx, leaf_idx}": f"Internal Node {i} Hash",
                "Value": row["hash"].hex(" ", -4).upper(),
            })  
            rows.append({
                f"Internal Node for Leaf {leaf_idx, leaf_idx}": f"Internal Node {i} Hash Length",
                "Value": len(row["hash"]),
            })
        df_internals = pd.DataFrame(rows)

        INTERNAL_BLOCK_COLORS = [
            "#edf5f3",
            "#d8ede7",
            "#c8ede3",
            "#b1ebda",
        ]

        def color_by_internals(data: pd.DataFrame):
            style_df = pd.DataFrame("", index=data.index, columns=data.columns)
            for idx in range(len(data)):
                # Group each internal node for a color
                internal_group_number = idx // 4
                color = INTERNAL_BLOCK_COLORS[
                    internal_group_number % len(INTERNAL_BLOCK_COLORS)
                ]
                style_df.iloc[idx] = f"background-color: {color};"
            return style_df
        
        # Set style
        internals_styled = (
            df_internals.style.set_properties(
                **{
                    "color": "#000",
                    "border-color": "#dffaf5",
                    "border-style": "solid",
                    "border-width": "1.5px",
                    "font-family": "Segoe UI, Arial, sans-serif",
                    "padding": "8px",
                }
            )
            .apply(color_by_internals, axis=None)
            .set_properties(
                subset=[f"Internal Node for Leaf {leaf_idx, leaf_idx}"],
                **{"font-weight": "bold", "color": "#111111", "text-align": "left"},
            )
            .set_table_styles(
                [
                    {
                        "selector": "th",
                        "props": [
                            ("background-color", "#2ba89e"),
                            ("color", "white"),
                            ("font-weight", "bold"),
                        ],
                    },
                    {
                        "selector": "",  # The outer wrapper
                        "props": [
                            ("border", "2.5px solid #2ba89e"),
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
        return make_html(internals_styled, header_color="#2ba89e", align={f"Internal Node for Leaf {leaf_idx,leaf_idx}": "left", 
                                                                         "Value": "left"})
## -------------------------------------------------------##


## ----------------------- Ladder ----------------------- ##
@dataclass
class Ladder:
    fullsig: InitVar[bytes]
    n: InitVar[int]
    
    val: bytes = field(init=False)
    flag: bytes = field(init=False)
    sid: bytes = field(init=False)
    rung_cnt: int = field(init=False)
    rungs: list[dict[str, bytes]] = field(init=False)
    _end: int = field(init=False)
    sig_len: bytes = field(init=False)
    signature: bytes = field(init=False)
    total_leaves: int = field(init=False)
    rindex: bytes = field(init=False)

    authpath_instance: InitVar[Optional["AuthPath"]] = None

    def __post_init__(self, fullsig: bytes, n: int, authpath_instance: Optional["AuthPath"] = None):
        if not authpath_instance: 
            self.start = 0
        else:
            self.start = authpath_instance.end_index 

        self.flag = self.ladder_get_flag(fullsig[self.start:], n)
        self.sid = self.ladder_get_sid(fullsig[self.start:], n)
        self.rung_cnt = self.ladder_get_rung_cnt(fullsig[self.start:], n)
        self.rungs, tmp_end_index = self.ladder_get_rungs(self.rung_cnt, fullsig[self.start:], n)
        self._end = tmp_end_index + self.start
        self.val = fullsig[self.start:self._end]
        self.rindex = self.ladder_get_rightindex()

        if authpath_instance: 
            self.sig_len = self.get_ladder_siglen(fullsig)
            self.signature = self.get_ladder_sig(fullsig)

        else:
            self.sig_len = b""
            self.signature = b""

            
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
        Parameters:
        -----------
        rung_cnt: number of rungs in a ladder
        ladder  : ladder
        """
        def get_rungs(rung_cnt, input_bytes, rung_hash_len):
            rung_list = []
            for i in range(rung_cnt):
                rung_dict = {}
                start = (16 + rung_hash_len) * i
                #print(f"Left index: {input_bytes[start:start+8]}")
                rung_dict["left_index"] = input_bytes[start:start+8]
                rung_dict["left_index_int"] = int(rung_dict["left_index"].hex(), 16)
                #print(f"Right index: {input_bytes[start+8:start+16]}")
                rung_dict["right_index"] = input_bytes[start+8:start+16]
                rung_dict["right_index_int"] = int(rung_dict["right_index"].hex(), 16)
                rung_dict["hash"] = input_bytes[(start+16):(start+16+rung_hash_len)]
                rung_list.append(rung_dict)
            return rung_list
    
        # Each ladder index is 8-byte long, each ladder rung hash is n-byte long
        end_rung = (2 * n + 4) + rung_cnt * (8 + 8 + n)
        rungs = get_rungs(rung_cnt, ladder[(2*n+4):end_rung], n)
        return rungs, end_rung

    def ladder_get_rightindex(self) -> bytes:
        return self.rungs[-1]["right_index"]
        
    def ladder_print(self, preset="blue"):
        # Ladder data on top 
        ladder_data = {
            "Flag": self.flag,
            "SID": self.sid,
            "Rung Count": self.rung_cnt.to_bytes(2, "big"),
        }
        df_ladder = pd.DataFrame(list(ladder_data.items()), columns=["Ladder Field", "Value"])
        df_ladder["Field Length (bytes)"] = df_ladder["Value"].apply(lambda x: len(x) if isinstance(x, bytes) else "")
        df_ladder["Field Data"] = df_ladder["Value"].apply(lambda x: x.hex(" ", 4).upper() if isinstance(x, bytes) else x)
        df_ladder = df_ladder[["Ladder Field", "Field Length (bytes)", "Field Data"]]

        # Rungs
        rows = []
        for i, row in enumerate(self.rungs, start=1):
            rows.append({
                "Ladder Field": f"Rung {i} Left Index",
                "Field Length (bytes)": len(row["left_index"]),
                "Field Data": row["left_index"].hex(" ", -4).upper()
            })
            rows.append({
                "Ladder Field": f"Rung {i} Right Index",
                "Field Length (bytes)": len(row["right_index"]),
                "Field Data": row["right_index"].hex(" ", -4).upper()
            }) 
            rows.append({
                "Ladder Field": f"Rung {i} Hash Value",
                "Field Length (bytes)": len(row["hash"]),
                "Field Data": row["hash"].hex(" ", -4).upper()
            })  
        df_rung = pd.DataFrame(rows)

        
        # Combine two DataFrame
        df_combined = pd.concat([df_ladder, df_rung], ignore_index=True).fillna("")

        # Colors for different rungs
        if preset == "blue":
            RUNG_BLOCK_COLORS = [
                "#f0f7ff",
                "#e1efff",
                "#d2e6ff",
                "#c2dcff",
            ]
        # Account for Scenario B in SigTag demo
        else:
            RUNG_BLOCK_COLORS = [
                "#fcfbf6",
                "#fcf8e3",
                "#fcf7d9",
                "#edeada",
            ]
        
        # Set each rung a color for clarity
        NUM_LADDER_ROWS = len(df_ladder)
        def color_by_blocks(data: pd.DataFrame):
            style_df = pd.DataFrame("", index=data.index, columns=data.columns)
        
            for idx in range(len(data)):
                if idx < NUM_LADDER_ROWS:
                    # Shared ladder rows
                    if preset == "blue":
                        style_df.iloc[idx] = "background-color: #b0d2ff;"
                    else:
                        style_df.iloc[idx] = "background-color: #f5e9ab;"
                else:
                    # Get to the rung index
                    rung_row_idx = idx - NUM_LADDER_ROWS
        
                    # Group each rung for a color
                    rung_group_number = rung_row_idx // 3
                    color = RUNG_BLOCK_COLORS[
                        rung_group_number % len(RUNG_BLOCK_COLORS)
                    ]
                    style_df.iloc[idx] = f"background-color: {color};"
            return style_df
        
        # Set style
        if preset == "blue":
            df_styled = (
                df_combined.style
                    .set_uuid("ladder_printout")
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
                    subset=["Ladder Field"],
                    **{"font-weight": "bold", "color": "#111111", "text-align": "left"},
                )
                .set_table_styles(
                    [
                        {
                            "selector": "th",
                            "props": [
                                ("background-color", "#2a94cc"),
                                ("color", "white"),
                                ("font-weight", "bold"),
                            ],
                        },
                        {
                            "selector": "",  # The outer wrapper
                            "props": [
                                ("border", "2.5px solid #2a94cc"),
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
            return make_html(df_styled, header_color="#2a94cc", align={"Ladder Field": "left", 
                                                                   "Field Length (bytes)": "center",
                                                                   "Field Data": "left"})
        else:
            df_styled = (
                df_combined.style
                    .set_uuid("ladder_printout")
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
                    subset=["Ladder Field"],
                    **{"font-weight": "bold", "color": "#111111", "text-align": "left"},
                )
                .set_table_styles(
                    [
                        {
                            "selector": "th",
                            "props": [
                                ("background-color", "#947849"),
                                ("color", "white"),
                                ("font-weight", "bold"),
                            ],
                        },
                        {
                            "selector": "",  # The outer wrapper
                            "props": [
                                ("border", "2.5px solid #947849"),
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
            return make_html(df_styled, header_color="#947849", align={"Ladder Field": "left", 
                                                                       "Field Length (bytes)": "center",
                                                                       "Field Data": "left"})


    def get_ladder_siglen(self, fullsig: bytes) -> bytes:
        siglen_start_index = self._end
        ladder_sig_len = fullsig[siglen_start_index:(siglen_start_index+4)]
        return ladder_sig_len
    
    def get_ladder_sig(self, fullsig: bytes) -> bytes: 
        sig_start_index = self._end + 4
        ladder_sig = fullsig[sig_start_index:]
        return ladder_sig
