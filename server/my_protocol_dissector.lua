-- Wireshark Lua dissector for my_protocol protocol running over UDP (Layer 5)
local my_protocol_proto = Proto("my_protocol", "my_protocol Layer 5 Protocol")

-- Protocol fields
local f_f = ProtoField.string("my_protocol.f", "f")
local f_t = ProtoField.string("my_protocol.t", "t")
local f_tttt = ProtoField.uint32("my_protocol.tttt", "tttt", base.DEC)

my_protocol_proto.fields = {f_f, f_t, f_tttt}

-- Dissector function
function my_protocol_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "my_protocol"
    local subtree = tree:add(my_protocol_proto, buffer(), "my_protocol Layer 5 Protocol Data")

    subtree:add(f_f, buffer(0, 0))
    subtree:add(f_t, buffer(0, 0))
    subtree:add(f_tttt, buffer(0, 4))
end

-- Register the dissector to the specified UDP port
local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(10000, my_protocol_proto)
