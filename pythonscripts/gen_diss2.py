#!/usr/bin/env python3
"""
This script reads a DPI JSON file that describes the protocol fields for each IP
and generates:
  1. A Wireshark Lua dissector file per IP that decodes each field and runs DPI tests.
     - If no errors, the Info column shows the parsed field values.
     - If errors, the Info column only shows "[DPI Error: ...]".
  2. A general static dissector (saved as <protocol>.lua) that decodes fields according 
     to fixed sizes (no DPI tests), showing a summary of fields in the Info column.

Now, each field in the DPI JSON has an additional property "bitfields_count" (an integer or null).
When a field’s type is "bitfield", the generated code will:
  - Check that the number of bits set (turned on) in the field equals bitfields_count.
  - Display the entire field as a binary string rather than decomposing it.

Additional types supported: int, float, double, char, long, bool, bitfield, and more.

Note on float/double extraction:
Wireshark's TvbRange object does not have le_double()/le_float() methods.
Instead, we extract the raw bytes and use string.unpack.
In this example the big‑endian format is used (">f" for float, ">d" for double).
"""

import json
import os

# Path to the DPI JSON file (change as needed)
JSON_FILENAME = "/mnt/c/Users/aviv/Desktop/newProject/server/dpi_output.json"

# Directory to save the Lua files
OUTPUT_DIR = "/mnt/c/Users/aviv/Desktop/newProject/data"

# UDP port to register the dissectors (change if needed)
UDP_PORT = 10000

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Load the DPI specification
with open(JSON_FILENAME, "r") as f:
    dpi_spec = json.load(f)

protocol = dpi_spec.get("protocol", "CustomProtocol")
dpi_data = dpi_spec.get("dpi", {})

##########################################################################
# Helper function to generate the list of all fields (including bitfields)
##########################################################################
def generate_field_list(fields):
    all_fields = []
    for field_name, info in fields.items():
        all_fields.append(f"f_{field_name}")
        # Only add decomposed bitfield entries if the field type is not "bitfield"
        if info.get("field_type") != "bitfield":
            bitfields_count = info.get("bitfields_count")
            if bitfields_count is not None and bitfields_count:
                for i in range(bitfields_count):
                    all_fields.append(f"f_{field_name}_bf{i}")
    return all_fields

##########################################################################
# 1. Generate per-IP Lua dissectors (with DPI tests)
##########################################################################
for ip, fields in dpi_data.items():
    ip_clean = ip.replace('.', '_')
    proto_name = f"{protocol}_{ip_clean}"
    filename = f"{protocol}_for_{ip_clean}.lua"
    filepath = os.path.join(OUTPUT_DIR, filename)
    
    with open(filepath, "w") as outfile:
        # Header
        outfile.write(f"-- Wireshark Lua dissector for {protocol} on IP {ip}\n")
        outfile.write("-- Generated automatically from DPI JSON.\n\n")
        
        # Proto definition
        outfile.write(f"local {proto_name} = Proto(\"{proto_name}\", \"{protocol} for IP {ip}\")\n\n")
        
        # Declare ProtoFields for each field
        for field_name, info in fields.items():
            ftype = info["field_type"]
            if ftype == "bool":
                proto_field_type = "ProtoField.uint8"
                base = ", base.DEC"
                outfile.write(f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
            elif ftype == "int":
                size = info["min_size"]
                if size == 1:
                    proto_field_type = "ProtoField.uint8"
                elif size == 2:
                    proto_field_type = "ProtoField.uint16"
                elif size == 4:
                    proto_field_type = "ProtoField.uint32"
                elif size == 8:
                    proto_field_type = "ProtoField.uint64"
                else:
                    proto_field_type = "ProtoField.uint32"
                base = ", base.DEC"
                outfile.write(f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
            elif ftype == "float":
                outfile.write(f"local f_{field_name} = ProtoField.float(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\")\n")
            elif ftype == "double":
                outfile.write(f"local f_{field_name} = ProtoField.double(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\")\n")
            elif ftype == "long":
                if info["min_size"] == 8:
                    outfile.write(f"local f_{field_name} = ProtoField.uint64(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\", base.DEC)\n")
                else:
                    outfile.write(f"local f_{field_name} = ProtoField.int32(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\", base.DEC)\n")
            elif ftype == "char":
                proto_field_type = "ProtoField.string"
                base = ""
                outfile.write(f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
            elif ftype == "bitfield":
                size = info["min_size"]
                if size == 1:
                    proto_field_type = "ProtoField.uint8"
                elif size == 2:
                    proto_field_type = "ProtoField.uint16"
                elif size == 4:
                    proto_field_type = "ProtoField.uint32"
                elif size == 8:
                    proto_field_type = "ProtoField.uint64"
                else:
                    proto_field_type = "ProtoField.uint32"
                base = ""
                outfile.write(f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", \"{field_name.capitalize()} (Bitfield)\"){base}\n")
            else:
                outfile.write(f"local f_{field_name} = ProtoField.string(\"{proto_name}.{field_name}\", \"{field_name.capitalize()}\")\n")
            
            # For non-bitfield types with bitfields_count defined, declare additional ProtoFields.
            if info.get("field_type") != "bitfield":
                bitfields_count = info.get("bitfields_count")
                if bitfields_count is not None and bitfields_count:
                    for i in range(bitfields_count):
                        lua_bf_field = f"f_{field_name}_bf{i}"
                        bf_label = f"{field_name.capitalize()} Bitfield {i+1}"
                        outfile.write(f"local {lua_bf_field} = ProtoField.uint8(\"{proto_name}.{field_name}_bf{i}\", \"{bf_label}\", base.DEC)\n")
                    bf_fields_list = ", ".join([f"f_{field_name}_bf{i}" for i in range(bitfields_count)])
                    outfile.write(f"local bf_fields_{field_name} = {{ {bf_fields_list} }}\n")
        
        outfile.write("\n")
        # Register all fields (including bitfields)
        all_fields = generate_field_list(fields)
        outfile.write(f"{proto_name}.fields = {{ {', '.join(all_fields)} }}\n\n")
        
        # Begin dissector function and add helper functions for bitfield processing
        outfile.write(f"function {proto_name}.dissector(buffer, pinfo, tree)\n")
        outfile.write("    if buffer:len() == 0 then return end\n")
        outfile.write(f"    pinfo.cols.protocol = \"{protocol}\"\n")
        outfile.write(f"    local subtree = tree:add({proto_name}, buffer(), \"{protocol} for IP {ip}\")\n")
        outfile.write("    local offset = 0\n")
        outfile.write("    local dpi_error = false\n")
        outfile.write("    local error_messages = {}\n")
        outfile.write("    local parsed_values = {}\n\n")
        
        # Helper functions for bitfield type
        outfile.write("    -- Helper function to count the number of bits set in a value\n")
        outfile.write("    local function popcount(x)\n")
        outfile.write("        local count = 0\n")
        outfile.write("        while x > 0 do\n")
        outfile.write("            count = count + (x % 2)\n")
        outfile.write("            x = math.floor(x / 2)\n")
        outfile.write("        end\n")
        outfile.write("        return count\n")
        outfile.write("    end\n\n")
        
        outfile.write("    -- Helper function to convert a number to a binary string of a given bit length\n")
        outfile.write("    local function to_binary_str(num, bits)\n")
        outfile.write("        local s = \"\"\n")
        outfile.write("        for i = bits - 1, 0, -1 do\n")
        outfile.write("            local bit_val = bit.rshift(num, i)\n")
        outfile.write("            s = s .. (bit.band(bit_val, 1) == 1 and \"1\" or \"0\")\n")
        outfile.write("        end\n")
        outfile.write("        return s\n")
        outfile.write("    end\n\n")
        
        # Parse each field
        for field_name, info in fields.items():
            ftype = info["field_type"]
            outfile.write(f"    -- Field: {field_name}\n")
            if ftype == "bitfield":
                outfile.write(f"    if buffer:len() < offset + {info['min_size']} then\n")
                outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        dpi_error = true\n")
                outfile.write(f"        table.insert(error_messages, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        return\n")
                outfile.write("    end\n")
                if info["min_size"] == 8:
                    outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint64()\n")
                else:
                    outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint()\n")
                outfile.write(f"    local {field_name}_item = subtree:add(f_{field_name}, buffer(offset, {info['min_size']}))\n")
                outfile.write(f"    local num_bits = {info['min_size']} * 8\n")
                outfile.write(f"    local actual_bit_count = popcount({field_name})\n")
                outfile.write(f"    if actual_bit_count ~= {info['bitfields_count']} then\n")
                outfile.write(f"        {field_name}_item:add_expert_info(PI_MALFORMED, PI_ERROR, \"Bitfield {field_name} expected {info['bitfields_count']} bits set, got \" .. actual_bit_count)\n")
                outfile.write("        dpi_error = true\n")
                outfile.write(f"        table.insert(error_messages, \"Bitfield {field_name} expected {info['bitfields_count']} bits set, got \" .. actual_bit_count)\n")
                outfile.write("    end\n")
                outfile.write("    local binary_str = to_binary_str(" + field_name + ", num_bits)\n")
                outfile.write(f"    {field_name}_item:append_text(\" (\" .. binary_str .. \")\")\n")
                outfile.write(f"    parsed_values['{field_name}'] = binary_str\n")
                outfile.write(f"    offset = offset + {info['min_size']}\n\n")
            elif not info.get("is_dynamic_array", False):
                outfile.write(f"    if buffer:len() < offset + {info['min_size']} then\n")
                outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        return\n")
                outfile.write("    end\n")
                if ftype in ["int", "bool", "long"]:
                    if info["min_size"] == 8:
                        outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint64()\n")
                    else:
                        outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint()\n")
                elif ftype == "float":
                    outfile.write(f"    local {field_name}_bytes = buffer(offset, {info['min_size']}):bytes():raw()\n")
                    outfile.write(f"    local {field_name} = string.unpack(\">f\", {field_name}_bytes)\n")
                elif ftype == "double":
                    outfile.write(f"    local {field_name}_bytes = buffer(offset, {info['min_size']}):bytes():raw()\n")
                    outfile.write(f"    local {field_name} = string.unpack(\">d\", {field_name}_bytes)\n")
                else:
                    outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):string()\n")
                outfile.write(f"    local {field_name}_item = subtree:add(f_{field_name}, buffer(offset, {info['min_size']}))\n")
                outfile.write(f"    parsed_values['{field_name}'] = {field_name}\n")
                
                if ftype in ["int", "bool", "long", "float", "double"] and info.get("min_value") is not None and info.get("max_value") is not None:
                    outfile.write("    do\n")
                    outfile.write(f"        local min_val = {info['min_value']}\n")
                    outfile.write(f"        local max_val = {info['max_value']}\n")
                    outfile.write(f"        if {field_name} < min_val or {field_name} > max_val then\n")
                    outfile.write(f"            {field_name}_item:add_expert_info(PI_MALFORMED, PI_ERROR, \"Value out of range for {field_name}\")\n")
                    outfile.write("            dpi_error = true\n")
                    outfile.write(f"            table.insert(error_messages, \"{field_name} out of range\")\n")
                    outfile.write("        end\n")
                    outfile.write("    end\n")
                
                outfile.write(f"    offset = offset + {info['min_size']}\n\n")
                
                bitfields_count = info.get("bitfields_count")
                if bitfields_count is not None and bitfields_count:
                    outfile.write("    do\n")
                    outfile.write(f"        local bits_per_field = ({info['min_size']} * 8) / {bitfields_count}\n")
                    outfile.write(f"        for i = 0, {bitfields_count} - 1 do\n")
                    outfile.write("            local shift = (({0} - 1 - i) * bits_per_field)\n".format(bitfields_count))
                    outfile.write("            local mask = (1 << bits_per_field) - 1\n")
                    outfile.write(f"            local bf_value = bit.band(bit.rshift({field_name}, shift), mask)\n")
                    outfile.write(f"            subtree:add(bf_fields_{field_name}[i+1], bf_value)\n")
                    outfile.write(f"            parsed_values['{field_name}_bf' .. i] = bf_value\n")
                    outfile.write("        end\n")
                    outfile.write("    end\n\n")
            else:
                size_field = info["size_defining_field"]
                outfile.write(f"    local dynamic_length = {size_field}\n")
                outfile.write(f"    if dynamic_length < {info['min_size']} or dynamic_length > {info['max_size']} then\n")
                outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"{field_name} length out of range\")\n")
                outfile.write("        dpi_error = true\n")
                outfile.write(f"        table.insert(error_messages, \"{field_name} length out of range\")\n")
                outfile.write("    end\n")
                outfile.write(f"    if buffer:len() < offset + dynamic_length then\n")
                outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        dpi_error = true\n")
                outfile.write(f"        table.insert(error_messages, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        return\n")
                outfile.write("    end\n")
                if ftype in ["int", "bool", "long"]:
                    if info["min_size"] == 8:
                        outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):uint64()\n")
                    else:
                        outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):uint()\n")
                elif ftype == "float":
                    outfile.write(f"    local {field_name}_bytes = buffer(offset, dynamic_length):bytes():raw()\n")
                    outfile.write(f"    local {field_name} = string.unpack(\">f\", {field_name}_bytes)\n")
                elif ftype == "double":
                    outfile.write(f"    local {field_name}_bytes = buffer(offset, dynamic_length):bytes():raw()\n")
                    outfile.write(f"    local {field_name} = string.unpack(\">d\", {field_name}_bytes)\n")
                else:
                    outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):string()\n")
                outfile.write(f"    local {field_name}_item = subtree:add(f_{field_name}, buffer(offset, dynamic_length))\n")
                outfile.write(f"    parsed_values['{field_name}'] = {field_name}\n")
                outfile.write("    offset = offset + dynamic_length\n\n")
                
                bitfields_count = info.get("bitfields_count")
                if bitfields_count is not None and bitfields_count:
                    outfile.write("    do\n")
                    outfile.write(f"        local bits_per_field = (dynamic_length * 8) / {bitfields_count}\n")
                    outfile.write(f"        for i = 0, {bitfields_count} - 1 do\n")
                    outfile.write("            local shift = (({0} - 1 - i) * bits_per_field)\n".format(bitfields_count))
                    outfile.write("            local mask = (1 << bits_per_field) - 1\n")
                    outfile.write(f"            local bf_value = bit.band(bit.rshift({field_name}, shift), mask)\n")
                    outfile.write(f"            subtree:add(bf_fields_{field_name}[i+1], bf_value)\n")
                    outfile.write(f"            parsed_values['{field_name}_bf' .. i] = bf_value\n")
                    outfile.write("        end\n")
                    outfile.write("    end\n\n")
        
        # --- Added printing of packet details for each field ---
        outfile.write("    -- Print packet details for each field (for debugging purposes)\n")
        outfile.write("    print(\"Packet details for IP \" .. tostring(\"" + ip + "\") .. \":\")\n")
        outfile.write("    for k, v in pairs(parsed_values) do\n")
        outfile.write("        print(\"  \" .. k .. \" = \" .. tostring(v))\n")
        outfile.write("    end\n\n")
        # --- End printing packet details ---
        
        outfile.write("    if dpi_error then\n")
        outfile.write("        local msg = table.concat(error_messages, \"; \")\n")
        outfile.write("        pinfo.cols.info = \"[DPI Error: \" .. msg .. \"]\"\n")
        outfile.write("        subtree:add_expert_info(PI_PROTOCOL, PI_ERROR, \"DPI Error in this packet\")\n")
        outfile.write("    else\n")
        outfile.write("        local parts = {}\n")
        outfile.write("        for k, v in pairs(parsed_values) do\n")
        outfile.write("            table.insert(parts, k .. \"=\" .. tostring(v))\n")
        outfile.write("        end\n")
        outfile.write("        table.sort(parts)\n")
        outfile.write("        pinfo.cols.info = table.concat(parts, \", \")\n")
        outfile.write("    end\n")
        
        outfile.write("end\n\n")
        
        outfile.write("-- Register this dissector for UDP port\n")
        outfile.write("local udp_port = DissectorTable.get(\"udp.port\")\n")
        outfile.write(f"udp_port:add({UDP_PORT}, {proto_name})\n")
    
    print(f"Generated per-IP dissector: {filepath}")

##########################################################################
# 2. Generate a static general dissector for ALL IPs (no DPI tests)
##########################################################################
if dpi_data:
    first_ip = next(iter(dpi_data))
    fields = dpi_data[first_ip]
    static_filename = f"{protocol}.lua"
    static_filepath = os.path.join(OUTPUT_DIR, static_filename)
    
    with open(static_filepath, "w") as outfile:
        outfile.write(f"-- Wireshark Lua static dissector for {protocol}\n")
        outfile.write("-- Decodes fields by fixed sizes (no DPI tests), showing field summary in Info.\n\n")
        
        outfile.write(f"local {protocol} = Proto(\"{protocol}\", \"{protocol}\")\n\n")
        
        # Declare ProtoFields for the static dissector
        for field_name, info in fields.items():
            ftype = info["field_type"]
            if ftype == "bool":
                proto_field_type = "ProtoField.uint8"
                base = ", base.DEC"
                outfile.write(f"local f_{field_name} = {proto_field_type}(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
            elif ftype == "int":
                size = info["min_size"]
                if size == 1:
                    proto_field_type = "ProtoField.uint8"
                elif size == 2:
                    proto_field_type = "ProtoField.uint16"
                elif size == 4:
                    proto_field_type = "ProtoField.uint32"
                elif size == 8:
                    proto_field_type = "ProtoField.uint64"
                else:
                    proto_field_type = "ProtoField.uint32"
                base = ", base.DEC"
                outfile.write(f"local f_{field_name} = {proto_field_type}(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
            elif ftype == "float":
                outfile.write(f"local f_{field_name} = ProtoField.float(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\")\n")
            elif ftype == "double":
                outfile.write(f"local f_{field_name} = ProtoField.double(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\")\n")
            elif ftype == "long":
                if info["min_size"] == 8:
                    outfile.write(f"local f_{field_name} = ProtoField.uint64(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\", base.DEC)\n")
                else:
                    outfile.write(f"local f_{field_name} = ProtoField.int32(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\", base.DEC)\n")
            elif ftype == "char":
                proto_field_type = "ProtoField.string"
                base = ""
                outfile.write(f"local f_{field_name} = {proto_field_type}(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\"){base}\n")
            elif ftype == "bitfield":
                size = info["min_size"]
                if size == 1:
                    proto_field_type = "ProtoField.uint8"
                elif size == 2:
                    proto_field_type = "ProtoField.uint16"
                elif size == 4:
                    proto_field_type = "ProtoField.uint32"
                elif size == 8:
                    proto_field_type = "ProtoField.uint64"
                else:
                    proto_field_type = "ProtoField.uint32"
                base = ""
                outfile.write(f"local f_{field_name} = {proto_field_type}(\"{protocol}.{field_name}\", \"{field_name.capitalize()} (Bitfield)\"){base}\n")
            else:
                outfile.write(f"local f_{field_name} = ProtoField.string(\"{protocol}.{field_name}\", \"{field_name.capitalize()}\")\n")
            
            if ftype != "bitfield":
                bitfields_count = info.get("bitfields_count")
                if bitfields_count is not None and bitfields_count:
                    for i in range(bitfields_count):
                        lua_bf_field = f"f_{field_name}_bf{i}"
                        bf_label = f"{field_name.capitalize()} Bitfield {i+1}"
                        outfile.write(f"local {lua_bf_field} = ProtoField.uint8(\"{protocol}.{field_name}_bf{i}\", \"{bf_label}\", base.DEC)\n")
                    bf_fields_list = ", ".join([f"f_{field_name}_bf{i}" for i in range(bitfields_count)])
                    outfile.write(f"local bf_fields_{field_name} = {{ {bf_fields_list} }}\n")
        
        outfile.write("\n")
        all_fields = generate_field_list(fields)
        outfile.write(f"{protocol}.fields = {{ {', '.join(all_fields)} }}\n\n")
        
        outfile.write(f"function {protocol}.dissector(buffer, pinfo, tree)\n")
        outfile.write("    if buffer:len() == 0 then return end\n")
        outfile.write(f"    pinfo.cols.protocol = \"{protocol}\"\n")
        outfile.write(f"    local subtree = tree:add({protocol}, buffer(), \"{protocol}\")\n")
        outfile.write("    local offset = 0\n")
        outfile.write("    local field_values = {}\n\n")
        
        outfile.write("    -- Add helper functions for bitfield processing\n")
        outfile.write("    local function popcount(x)\n")
        outfile.write("        local count = 0\n")
        outfile.write("        while x > 0 do\n")
        outfile.write("            count = count + (x % 2)\n")
        outfile.write("            x = math.floor(x / 2)\n")
        outfile.write("        end\n")
        outfile.write("        return count\n")
        outfile.write("    end\n\n")
        
        outfile.write("    local function to_binary_str(num, bits)\n")
        outfile.write("        local s = \"\"\n")
        outfile.write("        for i = bits - 1, 0, -1 do\n")
        outfile.write("            local bit_val = bit.rshift(num, i)\n")
        outfile.write("            s = s .. (bit.band(bit_val, 1) == 1 and \"1\" or \"0\")\n")
        outfile.write("        end\n")
        outfile.write("        return s\n")
        outfile.write("    end\n\n")
        
        for field_name, info in fields.items():
            ftype = info["field_type"]
            outfile.write(f"    -- Field: {field_name}\n")
            if ftype == "bitfield":
                outfile.write(f"    if buffer:len() < offset + {info['min_size']} then\n")
                outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        return\n")
                outfile.write("    end\n")
                if info["min_size"] == 8:
                    outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint64()\n")
                else:
                    outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint()\n")
                outfile.write(f"    local {field_name}_item = subtree:add(f_{field_name}, buffer(offset, {info['min_size']}))\n")
                outfile.write(f"    local num_bits = {info['min_size']} * 8\n")
                outfile.write(f"    local actual_bit_count = popcount({field_name})\n")
                outfile.write(f"    if actual_bit_count ~= {info['bitfields_count']} then\n")
                outfile.write(f"        {field_name}_item:add_expert_info(PI_MALFORMED, PI_ERROR, \"Bitfield {field_name} expected {info['bitfields_count']} bits set, got \" .. actual_bit_count)\n")
                outfile.write("    end\n")
                outfile.write("    local binary_str = to_binary_str(" + field_name + ", num_bits)\n")
                outfile.write(f"    {field_name}_item:append_text(\" (\" .. binary_str .. \")\")\n")
                outfile.write(f"    field_values['{field_name}'] = binary_str\n")
                outfile.write(f"    offset = offset + {info['min_size']}\n\n")
            elif not info.get("is_dynamic_array", False):
                outfile.write(f"    if buffer:len() < offset + {info['min_size']} then\n")
                outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        return\n")
                outfile.write("    end\n")
                if ftype in ["int", "bool", "long"]:
                    if info["min_size"] == 8:
                        outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint64()\n")
                    else:
                        outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):uint()\n")
                elif ftype == "float":
                    outfile.write(f"    local {field_name}_bytes = buffer(offset, {info['min_size']}):bytes():raw()\n")
                    outfile.write(f"    local {field_name} = string.unpack(\">f\", {field_name}_bytes)\n")
                elif ftype == "double":
                    outfile.write(f"    local {field_name}_bytes = buffer(offset, {info['min_size']}):bytes():raw()\n")
                    outfile.write(f"    local {field_name} = string.unpack(\">d\", {field_name}_bytes)\n")
                else:
                    outfile.write(f"    local {field_name} = buffer(offset, {info['min_size']}):string()\n")
                outfile.write(f"    subtree:add(f_{field_name}, buffer(offset, {info['min_size']}))\n")
                outfile.write(f"    field_values['{field_name}'] = {field_name}\n")
                outfile.write(f"    offset = offset + {info['min_size']}\n\n")
                
                bitfields_count = info.get("bitfields_count")
                if bitfields_count is not None and bitfields_count:
                    outfile.write("    do\n")
                    outfile.write(f"        local bits_per_field = ({info['min_size']} * 8) / {bitfields_count}\n")
                    outfile.write(f"        for i = 0, {bitfields_count} - 1 do\n")
                    outfile.write("            local shift = (({0} - 1 - i) * bits_per_field)\n".format(bitfields_count))
                    outfile.write("            local mask = (1 << bits_per_field) - 1\n")
                    outfile.write(f"            local bf_value = bit.band(bit.rshift({field_name}, shift), mask)\n")
                    outfile.write(f"            subtree:add(bf_fields_{field_name}[i+1], bf_value)\n")
                    outfile.write(f"            field_values['{field_name}_bf' .. i] = bf_value\n")
                    outfile.write("        end\n")
                    outfile.write("    end\n\n")
            else:
                size_field = info["size_defining_field"]
                outfile.write(f"    local dynamic_length = {size_field}\n")
                outfile.write(f"    if dynamic_length < {info['min_size']} or dynamic_length > {info['max_size']} then\n")
                outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"{field_name} length out of range\")\n")
                outfile.write("        dpi_error = true\n")
                outfile.write(f"        table.insert(error_messages, \"{field_name} length out of range\")\n")
                outfile.write("    end\n")
                outfile.write(f"    if buffer:len() < offset + dynamic_length then\n")
                outfile.write(f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        dpi_error = true\n")
                outfile.write(f"        table.insert(error_messages, \"Not enough bytes for {field_name}\")\n")
                outfile.write("        return\n")
                outfile.write("    end\n")
                if ftype in ["int", "bool", "long"]:
                    if info["min_size"] == 8:
                        outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):uint64()\n")
                    else:
                        outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):uint()\n")
                elif ftype == "float":
                    outfile.write(f"    local {field_name}_bytes = buffer(offset, dynamic_length):bytes():raw()\n")
                    outfile.write(f"    local {field_name} = string.unpack(\">f\", {field_name}_bytes)\n")
                elif ftype == "double":
                    outfile.write(f"    local {field_name}_bytes = buffer(offset, dynamic_length):bytes():raw()\n")
                    outfile.write(f"    local {field_name} = string.unpack(\">d\", {field_name}_bytes)\n")
                else:
                    outfile.write(f"    local {field_name} = buffer(offset, dynamic_length):string()\n")
                outfile.write(f"    subtree:add(f_{field_name}, buffer(offset, dynamic_length))\n")
                outfile.write(f"    field_values['{field_name}'] = {field_name}\n")
                outfile.write("    offset = offset + dynamic_length\n\n")
                
                bitfields_count = info.get("bitfields_count")
                if bitfields_count is not None and bitfields_count:
                    outfile.write("    do\n")
                    outfile.write(f"        local bits_per_field = (dynamic_length * 8) / {bitfields_count}\n")
                    outfile.write(f"        for i = 0, {bitfields_count} - 1 do\n")
                    outfile.write("            local shift = (({0} - 1 - i) * bits_per_field)\n".format(bitfields_count))
                    outfile.write("            local mask = (1 << bits_per_field) - 1\n")
                    outfile.write(f"            local bf_value = bit.band(bit.rshift({field_name}, shift), mask)\n")
                    outfile.write(f"            subtree:add(bf_fields_{field_name}[i+1], bf_value)\n")
                    outfile.write(f"            field_values['{field_name}_bf' .. i] = bf_value\n")
                    outfile.write("        end\n")
                    outfile.write("    end\n\n")
        
        # --- Added printing of packet details for each field ---
        outfile.write("    -- Print packet details for each field (for debugging purposes)\n")
        outfile.write("    print(\"Static Packet details:\")\n")
        outfile.write("    for k, v in pairs(field_values) do\n")
        outfile.write("        print(\"  \" .. k .. \" = \" .. tostring(v))\n")
        outfile.write("    end\n\n")
        # --- End printing packet details ---
        
        outfile.write("    local parts = {}\n")
        outfile.write("    for k, v in pairs(field_values) do\n")
        outfile.write("        table.insert(parts, k .. \"=\" .. tostring(v))\n")
        outfile.write("    end\n")
        outfile.write("    table.sort(parts)\n")
        outfile.write("    pinfo.cols.info = \"Static: \" .. table.concat(parts, \", \")\n")
        
        outfile.write("end\n\n")
        outfile.write("-- Register this dissector for the UDP port\n")
        outfile.write("local udp_port = DissectorTable.get(\"udp.port\")\n")
        outfile.write(f"udp_port:add({UDP_PORT}, {protocol})\n")
    
    print(f"Generated global static dissector: {static_filepath}")
