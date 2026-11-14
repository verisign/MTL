from datetime import datetime
from IPython.display import display, HTML
from IPython.core.display_functions import display
from IPython import get_ipython
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.style import Style
from rich import box
import xml.etree.ElementTree as ET
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import io
import re
import struct
import base64

## --------------------------- DNSSEC Signed Data Generation ---------------------------- ##
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


def create_dnssec_signed_data(rrsig_meta: dict[str, int | str], rrset: list[dict[str, int | str]]) -> bytes:
    """
    To construct the byte object that will be signed for DNSSEC.
    Parameters:
    -----------
    rrsig_meta: RRSIG RDATA portion
    rrset     : RRset
    """

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



## --------------------------- NSEC3 Decoder ---------------------------- ##
def decode_b32_nsec3(nsec3_b32_str: str) -> bytes:
    # NSEC3 extended hex uses: 0123456789abcdefghijklmnopqrstuv
    # Standard base32 uses:    ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
    nsec3_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    std_alphabet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    
    # Uppercase for consistency
    nsec3_b32_str = nsec3_b32_str.upper()
    
    # Translate characters from NSEC3 hex to standard base32
    trans_table = str.maketrans(nsec3_alphabet, std_alphabet)
    std_b32_str = nsec3_b32_str.translate(trans_table)
    
    # Add "=" padding if needed
    padding_needed = (8 - len(std_b32_str) % 8) % 8
    std_b32_str += "=" * padding_needed
    
    return base64.b32decode(std_b32_str)


## ------------------------------ MTL Visualization (ACSII style) -------------------------------- ##
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



## --------------------------------------------------------------------------------- ##
def generate_merkle_ladder(total_nodes: int, rungs: list[tuple[int, int]]) -> list[list[str]]:
    """
    To get all layers of nodes in a MTL.
    Parameters:
    -----------
    total_nodes: number of nodes in a MTL
    rungs      : list of rungs in the corresponding ladder
    """
    rung_set = set(rungs)
    
    # Leaf tracking ranges
    current_level = [(i, i) for i in range(total_nodes)]
    layers_nodes = [current_level]
    
    # Build the tree upward
    while True:
        next_level = []
        i = 0
        while i < len(current_level):
            left_node = current_level[i]
            
            # If this node is a rung, keep it here
            if left_node in rung_set:
                i += 1
                continue
                
            # Try to combine with the right sibling
            if i + 1 < len(current_level):
                right_node = current_level[i+1]
                if right_node in rung_set:
                    next_level.append(left_node)
                    i += 1
                else:
                    internal_node = (left_node[0], right_node[1])
                    next_level.append(internal_node)
                    i += 2
            else:
                # No right sibling exists
                next_level.append(left_node)
                i += 1
                
        if not next_level or next_level == current_level:
            break
        layers_nodes.append(next_level)
        current_level = next_level

    # Format for later visualization and add '*' to rungs
    formatted_layers = []
    for h, level in enumerate(layers_nodes):
        level_strs = []
        next_level_nodes = layers_nodes[h+1] if h + 1 < len(layers_nodes) else []
        
        for node in level:
            # A node has a parent if its interval falls within a parent node range
            has_parent = any(parent[0] <= node[0] and node[1] <= parent[1] for parent in next_level_nodes)
            
            node_str = str(node[0]) if node[0] == node[1] else f"({node[0]}, {node[1]})"
            
            # Rungs
            if not has_parent:
                node_str += "*"
                
            level_strs.append(node_str)
        formatted_layers.append(level_strs)
        
    return formatted_layers[::-1]


def format_tree_ascii(layers):
    """
    To render a level-by-level node list into an aligned ASCII tree map.
    """
    bottom_row = layers[-1]
    bottom_row_strs = []
    leaf_positions = []
    current_pos = 0

    # Get the base layout from leaf nodes
    for idx, item in enumerate(bottom_row):
        val = str(item)
        pad_left = " " * 3
        pad_right = " " * 2
        full_str = f"{pad_left}{val}{pad_right}"
        
        if idx % 2 == 0:
            center = current_pos + len(pad_left) + (len(val) // 2) + 1
        else:
            center = current_pos + len(pad_left) + (len(val) // 2) - 1
            
        leaf_positions.append(center)
        bottom_row_strs.append(full_str)
        current_pos += len(full_str)

    diagram_width = current_pos + 40
    output_lines = ["".join(bottom_row_strs).rstrip()]
    current_positions = list(leaf_positions)

    # Traverse up
    for r_idx in range(len(layers) - 2, -1, -1):
        row = layers[r_idx]
        next_positions = []
        
        branch_line = [" "] * diagram_width
        h_line = [" "] * diagram_width
        pipe_line = [" "] * diagram_width
        node_line = [" "] * diagram_width

        child_ptr = 0
        for i, node in enumerate(row):
            left_c = current_positions[child_ptr] if child_ptr < len(current_positions) else None
            right_c = current_positions[child_ptr + 1] if (child_ptr + 1) < len(current_positions) else None
            child_ptr += 2 

            if left_c is not None and right_c is not None:
                center = (left_c + right_c) // 2
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
                continue

            next_positions.append(center)
            h_line[center] = "H"
            pipe_line[center] = "|"

            node_str = str(node)
            start_x = center - (len(node_str) // 2)
            for char_idx, char in enumerate(node_str):
                if 0 <= start_x + char_idx < len(node_line):
                    node_line[start_x + char_idx] = char

        if any(c != " " for c in branch_line):
            output_lines.append("".join(branch_line).rstrip())
        output_lines.append("".join(h_line).rstrip())
        output_lines.append("".join(pipe_line).rstrip())
        output_lines.append("".join(node_line).rstrip())
        
        current_positions = next_positions

    return "\n".join(reversed(output_lines))


## ------------------------------ MTL Visualization (COLOR style) -------------------------------- ##
def parse_layer(node_str):
    """
    To extract the leaf boundaries from a node representation.
    """
    cleaned = str(node_str).strip().replace('*', '')
    if cleaned.isdigit():
        val = int(cleaned)
        return val, val
    match = re.search(r'\((\d+),\s*(\d+)\)', cleaned)
    if match:
        return int(match.group(1)), int(match.group(2))
    return None


def get_style(node):
    base_style = {"boxstyle": "round,pad=0.7", "lw": 2, "alpha": 1}
    if str(node).endswith("*"):
        # Rung
        return {**base_style, "facecolor": "#fce4ec", "edgecolor": "#e91e63"}
    elif str(node).startswith("H_"):
        # Hash representation
        return {**base_style, "facecolor": "#e0e0e0", "edgecolor": "#757575"}
    elif "(" in str(node):
        # Internal node
        return {**base_style, "facecolor": "#ffffff", "edgecolor": "#25a0f7"}
    else:
        # Leaf
        return {**base_style, "facecolor": "#bcd6ca", "edgecolor": "#259662"}



def mtl_print(total_leaves: int, rungs: list[dict], target_width=6):
    # Build the drawing dataset
    all_rungs = get_rung_index(rungs)
    ladder_layers = generate_merkle_ladder(total_leaves, all_rungs)
    
    G = nx.DiGraph()
    pos = {}
    edges = []
    
    num_layers = len(ladder_layers)
    num_leaves = len(ladder_layers[-1])
    
    # Width scales with the number of layers
    # Height scales with the number of leaves
    auto_width = max(6, num_layers * 1.6)
    auto_height = max(5, num_leaves * 0.45)
    aspect_ratio = auto_height / auto_width

    # Edges and coordinates 
    for layer_idx, current_layer in enumerate(ladder_layers):
        x_base = float(layer_idx) * 1.0
        
        for node_name in current_layer:
            bounds = parse_layer(node_name)
            if not bounds:
                continue
            start, end = bounds
            
            # Y coordinate is the center of its leaves
            y_coord = (float(start) + float(end)) / 2.0

            # Put all rung nodes at the same x position
            if node_name.endswith("*"):
                if "(" in node_name or ")" in node_name: 
                    pos[node_name] = [0, y_coord]
                # Create an extra rung node for single leaf rung; remove the rung mark from the leaf rung in the graph
                else:
                    pos[node_name.rstrip("*")] = [x_base, y_coord]
                    node_name_leafrung = "(" + node_name.rstrip("*") + ", " + node_name.rstrip("*") + ")*"
                    pos[node_name_leafrung] = [0, y_coord]
            else:
                pos[node_name] = [x_base, y_coord]

            # Leaf node is a rung: add edge to the extra rung node in the graph
            if start == end:
                if node_name.endswith("*"):
                    h_node_name = f"H_{node_name}"
                    pos[h_node_name] = [x_base - 0.5, y_coord]
                    edges.append((h_node_name, node_name.rstrip("*")))
                    edges.append((h_node_name, node_name_leafrung))
            
            # Find children in the next layer
            if layer_idx < num_layers - 1 and start != end:
                next_layer = ladder_layers[layer_idx + 1]
                children = []
                
                for potential_child in next_layer:                    
                    c_bounds = parse_layer(potential_child)
                    if c_bounds:
                        c_start, c_end = c_bounds
                        # If the interval falls inside the parent interval
                        if c_start >= start and c_end <= end:
                            children.append(potential_child)
                
                # If children found, link through a hash node
                if children:
                    h_node_name = f"H_{node_name}"
                    # Put the hash node halfway between layer columns
                    pos[h_node_name] = [x_base + 0.5, y_coord]
                    edges.append((node_name, h_node_name))
                    for child in children:
                        edges.append((h_node_name, child))   

    G.add_edges_from(edges)

    fig = plt.figure(figsize=(target_width, target_width * aspect_ratio), dpi=150, facecolor='#ffffff')
    ax = plt.gca()
    ax.set_facecolor('#ffffff')

    scale_factor = target_width / auto_width if auto_width > target_width else 1.0
    
    nx.draw_networkx_edges(
        G, pos, 
        edgelist=edges, 
        edge_color="#bdbdbd", 
        width=1, 
        arrows=True, 
        arrowstyle="-|>", 
        arrowsize=10 * scale_factor,
        ax=ax,
        node_size=0
    )
    
    for node, coords in pos.items():
        box_props = get_style(node)
        display_label = "H" if str(node).startswith("H_") else node
        ax.text(
            coords[0], coords[1], 
            s=display_label, 
            size=max(6, int(11 * scale_factor)), 
            family="monospace", 
            weight="bold",
            ha="center", 
            va="center", 
            bbox=box_props,
            zorder=3  
        )
        
    x_coords = [c[0] for c in pos.values()]
    y_coords = [c[1] for c in pos.values()]
    plt.xlim(min(x_coords) - 0.5, max(x_coords) + 0.5)
    plt.ylim(min(y_coords) - 0.8, max(y_coords) + 0.8)
    
    plt.axis("off")
    plt.tight_layout()
    plt.close(fig) 

    return fig



## ---------------------------------- Make HTML Object ---------------------------------------- ##
def make_html(style_obj, border_color="#dee2e6", header_color="#2a94cc", align=None):
    """
    To convert Pandas styled DataFrame into HTML.    
    Parameters:
    -----------
    styler_obj   : the configured pandas .style object
    border_color : Hex color for cell boundaries; default "#dee2e6"
    header_color : Hex color for the table header background and outer frame. Default "#2a94cc"
    align        : list or dict, optional: a dict mapping column names
    """
    raw_html = style_obj.to_html()
    
    # Extract CSS rules
    css_rules = {}
    style_match = re.search(r'<style[^>]*>(.*?)</style>', raw_html, re.DOTALL)
    if style_match:
        style_content = style_match.group(1)
        # Parse rules matching format: #T_uuid_rowX_colY { prop: val; ... } or class selectors like .colX, .rowX, etc.
        blocks = re.findall(r'([^{]+)\s*\{\s*([^}]+)\s*\}', style_content)
        for selectors, props_str in blocks:
            props = [p.strip() for p in props_str.split(';') if p.strip()]
            for selector in selectors.split(','):
                selector = selector.strip()
                # Clean up ID/class prefix
                clean_sel = re.sub(r'^#[A-Za-z0-9_]+\s+', '', selector)
                clean_sel = clean_sel.replace('.', '').replace('#', '').strip()
                if clean_sel:
                    if clean_sel not in css_rules:
                        css_rules[clean_sel] = []
                    css_rules[clean_sel].extend(props)

    # Parse table layout
    clean_html_body = re.sub(r'<style[^>]*>.*?</style>', '', raw_html, flags=re.DOTALL).strip()
    try:
        root = ET.fromstring(clean_html_body)
    except Exception:
        root = ET.fromstring(f"<div>{clean_html_body}</div>").find("table")

    global_font = "font-family: 'Segoe UI', Arial, sans-serif;"
    global_padding = "padding: 8px;"
    global_border = f"border: 1.5px solid {border_color};"
    
    df = style_obj.data
    col_align = {}
    if align:
        for k, v in align.items():
            col_align[k] = v

    # Helper function to map CSS classes
    def style_element(element, is_header=False, col_index=0):
        element_id = element.get("id", "")
        element_classes = element.get("class", "").split()
        
        applied_props = []
        
        # Get matching styles
        keys_to_check = [element_id] + element_classes
        for key in keys_to_check:
            if key in css_rules:
                applied_props.extend(css_rules[key])
                
        # Remove duplicates if any
        style_dict = {}
        for prop in applied_props:
            if ":" in prop:
                k, v = prop.split(":", 1)
                style_dict[k.strip().lower()] = v.strip()

        if is_header:
            style_dict.setdefault("background-color", header_color)
            style_dict.setdefault("color", "white")
            style_dict.setdefault("font-weight", "bold")
        else:
            style_dict.setdefault("color", "#000000")
            if col_index == 0:
                style_dict.setdefault("font-weight", "bold")
                style_dict.setdefault("color", "#111111")

        style_dict.setdefault("font-family", "'Segoe UI', Arial, sans-serif")
        style_dict.setdefault("padding", "8px")
        style_dict.setdefault("border", f"1.5px solid {border_color}")
        
        # Baseline parameters
        if "text-align" not in style_dict:
            current_col = df.columns[col_index] if col_index < len(df.columns) else col_index
            align_default = col_align.get(current_col, col_align.get(col_index, "left"))
            style_dict["text-align"] = f"{align_default} !important"
            
        inline_style = "; ".join([f"{k}: {v}" for k, v in style_dict.items()]) + ";"
        element.set("style", inline_style)

    # Map headers (<th>)
    headers = root.findall(".//th")
    for i, th in enumerate(headers):
        style_element(th, is_header=True, col_index=i)

    # Map cells (<td>)
    rows = root.findall(".//tbody/tr")
    for row in rows:
        cells = row.findall("td")
        for i, td in enumerate(cells):
            style_element(td, is_header=False, col_index=i)

    # Framework mapping
    root.set("style", f"border: 2.5px solid {header_color}; border-collapse: collapse; table-layout: auto; width: auto%; max-width: 66%")

    return HTML(ET.tostring(root, encoding="utf-8").decode("utf-8"))



## -------------------------------- Print Data and Data Length -------------------------------- ##
def print_data(title: str, hex_string: str, length_bytes: int, n: int = 16, print_type: str = "default"):
    console = Console()
    hex_string = hex_string.upper()
    type_lower = print_type.lower()
    
    # Define default style
    DEFAULT_COLOR = "bold cadet_blue"
    
    formatted_text = Text()
    legend_text = Text()

    # Helper: for condensed signature
    # Lengths are in bytes
    def process_condsig(n: int):
        slices = [
            {"tag": "MTL-Type", "length": 1, "style": "bold #d13642"},
            {"tag": "Flags", "length": 2, "style": "bold #787877"},
            {"tag": "SID", "length": 2*n, "style": "bold cadet_blue"},
            {"tag": "Randomizer", "length": n, "style": "bold #e6782d"},
            {"tag": "Leaf Index", "length": 8, "style": "bold #25b4fa"},
            {"tag": "Target Rung Index", "length": 16, "style": "bold magenta"},
            {"tag": "Sibling Hash Count", "length": 2, "style": "bold bright_blue"},
        ]
        sibling_count_start = 1 + 2 + 2*n + n + 8 + 16
        sibling_start_hex_idx = sibling_count_start * 2
        sibling_end_hex_idx = sibling_start_hex_idx + (2 * 2) # 2 bytes for Sibling Hash Count
        
        sibling_count_hex = hex_string[sibling_start_hex_idx:sibling_end_hex_idx]
        sibling_count_val = int(sibling_count_hex, 16)     
        sibling_hash_len = sibling_count_val * n
        
        slices.append({
            "tag": "Sibling Hash", 
            "length": sibling_hash_len, 
            "style": "bold #34bf5d"
        })
        slices_end = sibling_count_start + 2 + sibling_hash_len     
        return slices, slices_end

    # Helper: for ladder
    def process_ladder(n: int, last_slice_end: int = 0):
        slices = [
            {"tag": "Flags", "length": 2, "style": "bold #787877"},
            {"tag": "SID", "length": 2*n, "style": "bold cadet_blue"},
            {"tag": "Rung Count", "length": 2, "style": "bold #bd72a4"},
        ]
        rung_count_start = 2 + 2*n + last_slice_end
        rung_start_hex_idx = rung_count_start * 2
        rung_end_hex_idx = rung_start_hex_idx + (2 * 2) # 2 bytes for Rung Count
        
        rung_count_hex = hex_string[rung_start_hex_idx:rung_end_hex_idx]
        rung_count_val = int(rung_count_hex, 16)     
        rung_hash_len = rung_count_val * n
        
        for idx in range(rung_count_val):
            slices.append({
                "tag": f"Rung [{idx+1}] Index", 
                "length": 16, 
                "style": "bold #c9a650"
            })
            slices.append({
                "tag": f"Rung [{idx+1}] Hash", 
                "length": 16, 
                "style": "bold #4e60c9"
            })
        return slices

    # Helper: for signed ladder
    def process_signedladder(n: int, last_slice_end: int = 0):
        slices = process_ladder(n=n, last_slice_end=last_slice_end)
        slices.append({
            "tag": "Signature Length", 
            "length": 4, 
            "style": "bold #9e5e59"
        })
        slices.append({
            "tag": "Signature", 
            "length": 2420, 
            "style": "bold #b4b5b5"
        })
        return slices
        
    
    # CASE Default
    if type_lower == "default":
        chunks = [hex_string[i:i+8] for i in range(0, len(hex_string), 8)]
        
        char_counter = 0
        for chunk in chunks:
            formatted_text.append(chunk, style=DEFAULT_COLOR)
            char_counter += len(chunk)
            
            if char_counter % 64 == 0:
                formatted_text.append("\n")
            else:
                formatted_text.append(" ")  
        formatted_text.rstrip()


    # CASE Others
    else:
        if type_lower == "condsig":
            slices, _ = process_condsig(n=n)
        elif type_lower == "ladder":
            slices = process_ladder(n=n)    
        elif type_lower == "signed_ladder":
            slices = process_signedladder(n=n)   
        elif type_lower == "fullsig":
            slices_condsig, condsig_end = process_condsig(n=n)
            slices_signedladder = process_signedladder(n=n, last_slice_end=condsig_end)
            slices = slices_condsig + slices_signedladder
        elif type_lower == "sigtag":
            slices = [
                {"tag": "SID", "length": 2*n, "style": "bold cadet_blue"},
                {"tag": "Ladder Right Index", "length": 8, "style": "bold #9e615e"},
            ]

        styled_stream = Text()
        current_idx = 0
        styled_segments = []
        legend_items = []
        
        for sl in slices:
            char_length = sl["length"] * 2
            chunk_hex = hex_string[current_idx:current_idx + char_length]
            if chunk_hex:
                styled_segments.append((chunk_hex, sl["style"]))
                legend_items.append((sl["tag"], sl["style"]))
                current_idx += char_length
                
        if current_idx < len(hex_string):
            remaining_hex = hex_string[current_idx:]
            styled_segments.append((remaining_hex, "bold bright_black"))
            legend_items.append(("Payload Data", "bold bright_black"))

        # Combine
        for hex_chunk, style in styled_segments:
            styled_stream.append(hex_chunk, style=style)

        # Format into 8 characters per group
        formatted_text = Text()
        total_chars = len(styled_stream)
        chunk_count = 0
        
        for i in range(0, total_chars, 8):
            # Regardless of slice color
            sub_chunk = styled_stream[i:i+8]
            formatted_text.append(sub_chunk)
            chunk_count += 1
            
             # 8 * 8 = 64
            if chunk_count % 8 == 0:
                formatted_text.append("\n")
            else:
                formatted_text.append(" ")
                
        formatted_text.rstrip()

    
    # Inline display
    table = Table(show_header=False, box=None, padding=(1, 1, 1, 1))

    # Row 1: printout
    table.add_row(formatted_text)

    # Row 2: Length
    meta_text = Text()
    meta_text.append(f"Length of {title}: ", style="default")
    meta_text.append(f"{length_bytes} bytes", style="bold green")
    table.add_row(meta_text)
    
    panel = Panel(
        table, 
        title=f"[bold bright_blue]{title}[/bold bright_blue]", 
        title_align="center",
        border_style="bright_blue",
        style=Style(bgcolor="#ffffff"),
        expand=False
    )

    # Add legend if sliced
    if type_lower != "default":
        legend_table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
        
        for _ in range(4):
            legend_table.add_column()
        
        current_row = []
        for tag, style in legend_items:
            item_text = Text()
            item_text.append(" ■ ", style=style)
            item_text.append(f"{tag}", style="default")
            current_row.append(item_text)
    
            # Next line if reaches 4
            if len(current_row) == 4:
                legend_table.add_row(*current_row)
                current_row = []
                
        if current_row:
            # Pad the remaining with empty text
            while len(current_row) < 4:
                current_row.append(Text(""))
            legend_table.add_row(*current_row)

        background_legend = Panel(
        legend_table, 
        box=box.SQUARE,
        style="on #ffffff",
        border_style="#ffffff",
        expand=False
        )
    
        console.print(background_legend)   
    console.print(panel)