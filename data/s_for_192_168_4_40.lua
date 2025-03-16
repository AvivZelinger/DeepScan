-- Wireshark Lua dissector for s on IP 192.168.4.40
-- This file was generated automatically from the DPI JSON description.

local s_192_168_4_40 = Proto("s_192_168_4_40", "s for IP 192.168.4.40")

local f_sync = ProtoField.uint8("s_192_168_4_40.sync", "Sync"), base.DEC
local f_id = ProtoField.uint32("s_192_168_4_40.id", "Id"), base.DEC
local f_type = ProtoField.uint32("s_192_168_4_40.type", "Type"), base.DEC
local f_length = ProtoField.uint32("s_192_168_4_40.length", "Length"), base.DEC
local f_payload = ProtoField.string("s_192_168_4_40.payload", "Payload")
local f_crc = ProtoField.uint32("s_192_168_4_40.crc", "Crc"), base.DEC
local f_flag = ProtoField.uint8("s_192_168_4_40.flag", "Flag"), base.DEC

s_192_168_4_40.fields = { f_sync, f_id, f_type, f_length, f_payload, f_crc, f_flag }

function s_192_168_4_40.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "s (192.168.4.40)"
    local subtree = tree:add(s_192_168_4_40, buffer(), "s for IP 192.168.4.40")
    local offset = 0
    local dpi_error = false  -- flag to indicate any DPI test failure

    -- Field: sync
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field sync")
        dpi_error = true
        return
    end
    local sync = buffer(offset, 1):uint()
    local sync_tree = subtree:add(f_sync, buffer(offset, 1))
    if sync < 0 or sync > 1 then
        sync_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field sync")
        dpi_error = true
    end
    offset = offset + 1

    -- Field: id
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field id")
        dpi_error = true
        return
    end
    local id = buffer(offset, 4):uint()
    local id_tree = subtree:add(f_id, buffer(offset, 4))
    if id < 2242 or id > 8400 then
        id_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field id")
        dpi_error = true
    end
    offset = offset + 4

    -- Field: type
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field type")
        dpi_error = true
        return
    end
    local type = buffer(offset, 4):uint()
    local type_tree = subtree:add(f_type, buffer(offset, 4))
    offset = offset + 4

    -- Field: length
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field length")
        dpi_error = true
        return
    end
    local length = buffer(offset, 4):uint()
    local length_tree = subtree:add(f_length, buffer(offset, 4))
    if length < 7 or length > 14 then
        length_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field length")
        dpi_error = true
    end
    offset = offset + 4

    -- Field: payload
    -- Dynamic array field: payload (length defined by field 'length')
    local dynamic_length = length
    if dynamic_length < 7 or dynamic_length > 14 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Dynamic field payload length (" .. dynamic_length .. ") out of allowed range")
        dpi_error = true
    end
    if buffer:len() < offset + dynamic_length then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for dynamic field payload")
        dpi_error = true
        return
    end
    local payload = buffer(offset, dynamic_length):string()
    local payload_tree = subtree:add(f_payload, buffer(offset, dynamic_length))
    offset = offset + dynamic_length

    -- Field: crc
    if buffer:len() < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field crc")
        dpi_error = true
        return
    end
    local crc = buffer(offset, 4):uint()
    local crc_tree = subtree:add(f_crc, buffer(offset, 4))
    if crc < 232297096 or crc > 4100283207 then
        crc_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field crc")
        dpi_error = true
    end
    offset = offset + 4

    -- Field: flag
    if buffer:len() < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough bytes for field flag")
        dpi_error = true
        return
    end
    local flag = buffer(offset, 1):uint()
    local flag_tree = subtree:add(f_flag, buffer(offset, 1))
    if flag < 0 or flag > 1 then
        flag_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Value out of range for field flag")
        dpi_error = true
    end
    offset = offset + 1

    if dpi_error then
        pinfo.cols.info:append(" [DPI Error]")
        subtree:add_expert_info(PI_PROTOCOL, PI_ERROR, "DPI Error in this packet")
    end
end

-- Register this dissector to a UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(10000, s_192_168_4_40)
