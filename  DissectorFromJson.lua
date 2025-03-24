local json = require("dkjson") -- Ensure you have a JSON Lua library installed.

-- File path to the JSON file
local file_path = "C:\\Users\\aviv\\Desktop\\newProject\\dpi_output.json"

-- Function to read the JSON file
local function read_json_file(path)
    local file = io.open(path, "r")
    if not file then error("Could not open file: " .. path) end
    local content = file:read("*a")
    file:close()
    return content
end

-- Read the JSON content from the file
local jsonString = read_json_file(file_path)

-- Parse the JSON string
decoded_json = json.decode(jsonString, { strict = true })

-- Function to create a Wireshark dissector for each IP
function create_dissector_for_ip(ip, fields)
    local protocol_name = "CustomProtocol_" .. ip:gsub("%.", "_")
    local p = Proto(protocol_name, "Custom Protocol for " .. ip)

    -- Define the protocol fields
    local proto_fields = {}

    for field_name, details in pairs(fields) do
        local field_type
        if details.field_type == "bool" then
            field_type = ftypes.BOOLEAN
        elseif details.field_type == "int" then
            field_type = ftypes.UINT32
        elseif details.field_type == "char" then
            field_type = ftypes.STRING
        else
            field_type = ftypes.NONE
        end

        proto_fields[field_name] = ProtoField.new(
            field_name,
            protocol_name .. "." .. field_name,
            field_type
        )
    end

    p.fields = proto_fields

    -- Dissector function
    function p.dissector(buffer, pinfo, tree)
        pinfo.cols.protocol = p.name
        local subtree = tree:add(p, buffer())

        local offset = 0
        for field_name, details in pairs(fields) do
            local size = details.min_size
            if details.is_dynamic_array then
                local size_defining_field = details.size_defining_field
                if size_defining_field and fields[size_defining_field] then
                    size = buffer(offset, fields[size_defining_field].min_size):uint()
                end
            end

            subtree:add(proto_fields[field_name], buffer(offset, size))
            offset = offset + size
        end
    end

    -- Register the dissector
    DissectorTable.get("udp.port"):add(10000, p)
end

-- Generate dissectors for all IPs
for ip, fields in pairs(decoded_json.dpi) do
    create_dissector_for_ip(ip, fields)
end
