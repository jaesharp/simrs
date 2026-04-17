-- simrs-apdu.lua -- Wireshark Lua dissector for simrs DLT_USER0 APDU frames.
--
-- Decodes the 1-byte flags header used by simrs-pcap's User0 link type,
-- then parses the APDU payload as either a command or response.
--
-- Installation:
--   Copy to your Wireshark plugins directory, or load with:
--     wireshark -X lua_script:tools/simrs-apdu.lua capture.pcap
--
-- The DLT_USER0 (147) encapsulation must be configured:
--   Edit -> Preferences -> Protocols -> DLT_USER -> DLT_USER0 = simrs_apdu
--
-- For GSMTAP captures (LINKTYPE 2342), Wireshark's built-in gsmtap
-- dissector handles SIM APDUs natively -- no Lua dissector needed.
--
-- Frame format (simrs-pcap User0):
--   Byte 0: flags
--     bit 0: direction (0 = command terminal->card, 1 = response card->terminal)
--     bit 1: ATR frame  (0 = APDU, 1 = ATR)
--     bit 2: shadow mismatch (0 = match/no shadow, 1 = divergence detected)
--   Bytes 1+: APDU or ATR payload

local proto = Proto("simrs_apdu", "simrs APDU")

-- Protocol fields.
local f_direction = ProtoField.uint8(
    "simrs_apdu.direction", "Direction", base.DEC,
    { [0] = "Command (Terminal -> Card)", [1] = "Response (Card -> Terminal)" },
    0x01)
local f_is_atr = ProtoField.bool(
    "simrs_apdu.is_atr", "ATR Frame", 8, nil, 0x02)
local f_mismatch = ProtoField.bool(
    "simrs_apdu.mismatch", "Shadow Mismatch", 8, nil, 0x04)

-- INS name lookup (ISO 7816-4 + ETSI TS 102 221 + 3GPP TS 31.102).
local ins_names = {
    [0x04] = "DEACTIVATE FILE",
    [0x10] = "TERMINAL PROFILE",
    [0x12] = "FETCH",
    [0x14] = "TERMINAL RESPONSE",
    [0x20] = "VERIFY",
    [0x24] = "CHANGE REFERENCE DATA",
    [0x26] = "DISABLE VERIFICATION",
    [0x28] = "ENABLE VERIFICATION",
    [0x2C] = "UNBLOCK PIN",
    [0x32] = "INCREASE",
    [0x44] = "ACTIVATE FILE",
    [0x70] = "MANAGE CHANNEL",
    [0x88] = "AUTHENTICATE",
    [0xA2] = "SEARCH RECORD",
    [0xA4] = "SELECT",
    [0xAA] = "TERMINAL CAPABILITY",
    [0xB0] = "READ BINARY",
    [0xB2] = "READ RECORD",
    [0xC0] = "GET RESPONSE",
    [0xC2] = "ENVELOPE",
    [0xD6] = "UPDATE BINARY",
    [0xDC] = "UPDATE RECORD",
    [0xF2] = "STATUS",
}

-- SW1 interpretations.
local sw1_names = {
    [0x90] = "Normal",
    [0x91] = "Normal + proactive",
    [0x61] = "Data available",
    [0x62] = "Warning (NV unchanged)",
    [0x63] = "Warning (NV changed)",
    [0x64] = "Exec error (NV unchanged)",
    [0x65] = "Exec error (NV changed)",
    [0x67] = "Wrong length",
    [0x68] = "Function not supported",
    [0x69] = "Command not allowed",
    [0x6A] = "Wrong parameters",
    [0x6B] = "Wrong P1-P2",
    [0x6C] = "Wrong Le",
    [0x6D] = "INS not supported",
    [0x6E] = "CLA not supported",
    [0x6F] = "Internal error",
    [0x98] = "SIM app error",
}

-- Command APDU fields.
local f_cla  = ProtoField.uint8("simrs_apdu.cla",  "CLA",  base.HEX)
local f_ins  = ProtoField.uint8("simrs_apdu.ins",  "INS",  base.HEX)
local f_p1   = ProtoField.uint8("simrs_apdu.p1",   "P1",   base.HEX)
local f_p2   = ProtoField.uint8("simrs_apdu.p2",   "P2",   base.HEX)
local f_lc   = ProtoField.uint8("simrs_apdu.lc",   "Lc",   base.DEC)
local f_data = ProtoField.bytes("simrs_apdu.data",  "Data")
local f_le   = ProtoField.uint8("simrs_apdu.le",   "Le",   base.DEC)

-- Response APDU fields.
local f_rdata = ProtoField.bytes("simrs_apdu.rdata", "Response Data")
local f_sw1   = ProtoField.uint8("simrs_apdu.sw1",  "SW1",  base.HEX)
local f_sw2   = ProtoField.uint8("simrs_apdu.sw2",  "SW2",  base.HEX)

-- ATR field.
local f_atr = ProtoField.bytes("simrs_apdu.atr", "ATR")

proto.fields = {
    f_direction, f_is_atr, f_mismatch,
    f_cla, f_ins, f_p1, f_p2, f_lc, f_data, f_le,
    f_rdata, f_sw1, f_sw2,
    f_atr,
}

-- Expert info for mismatch packets.
local ef_mismatch = ProtoExpert.new(
    "simrs_apdu.mismatch_expert", "Shadow SIM divergence detected",
    expert.group.PROTOCOL, expert.severity.WARN)
proto.experts = { ef_mismatch }

function proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("simrs")

    local buf_len = buffer:len()
    if buf_len < 1 then return end

    local subtree = tree:add(proto, buffer(), "simrs APDU")

    -- Parse flags byte.
    local flags = buffer(0, 1):uint()
    local dir = bit.band(flags, 0x01)
    local is_atr = bit.band(flags, 0x02) ~= 0
    local is_mismatch = bit.band(flags, 0x04) ~= 0

    subtree:add(f_direction, buffer(0, 1))
    subtree:add(f_is_atr, buffer(0, 1))
    subtree:add(f_mismatch, buffer(0, 1))

    if is_mismatch then
        subtree:add_proto_expert_info(ef_mismatch)
    end

    local payload = buffer(1)
    local plen = buf_len - 1

    if is_atr then
        -- ATR frame.
        pinfo.cols.info:set("ATR (" .. plen .. " bytes)")
        if plen > 0 then
            subtree:add(f_atr, payload)
        end
        return
    end

    if dir == 0 then
        -- Command APDU: CLA INS P1 P2 [Lc Data] [Le]
        if plen < 4 then
            pinfo.cols.info:set("Command (truncated)")
            return
        end

        local cla = payload(0, 1):uint()
        local ins = payload(1, 1):uint()
        local p1  = payload(2, 1):uint()
        local p2  = payload(3, 1):uint()

        subtree:add(f_cla, payload(0, 1))
        subtree:add(f_ins, payload(1, 1))
        subtree:add(f_p1,  payload(2, 1))
        subtree:add(f_p2,  payload(3, 1))

        local ins_name = ins_names[ins] or string.format("INS 0x%02X", ins)
        local info = ins_name

        if plen == 4 then
            -- Case 1: no Lc, no Le.
            info = info .. " (case 1)"
        elseif plen == 5 then
            -- Case 2: Le only.
            subtree:add(f_le, payload(4, 1))
            info = info .. string.format(" Le=%d", payload(4, 1):uint())
        elseif plen >= 6 then
            local lc = payload(4, 1):uint()
            subtree:add(f_lc, payload(4, 1))

            if lc > 0 and plen >= 5 + lc then
                subtree:add(f_data, payload(5, lc))
            end

            if plen > 5 + lc then
                -- Case 4: Lc + Data + Le.
                subtree:add(f_le, payload(5 + lc, 1))
                info = info .. string.format(" Lc=%d Le=%d", lc, payload(5 + lc, 1):uint())
            else
                -- Case 3: Lc + Data only.
                info = info .. string.format(" Lc=%d", lc)
            end
        end

        if is_mismatch then
            info = info .. " [MISMATCH]"
        end

        pinfo.cols.info:set(info)

    else
        -- Response APDU: [Data] SW1 SW2
        if plen < 2 then
            pinfo.cols.info:set("Response (truncated)")
            return
        end

        local sw1 = payload(plen - 2, 1):uint()
        local sw2 = payload(plen - 1, 1):uint()

        if plen > 2 then
            subtree:add(f_rdata, payload(0, plen - 2))
        end

        subtree:add(f_sw1, payload(plen - 2, 1))
        subtree:add(f_sw2, payload(plen - 1, 1))

        local sw1_name = sw1_names[sw1] or ""
        local info = string.format("SW %02X %02X", sw1, sw2)
        if sw1_name ~= "" then
            info = info .. " (" .. sw1_name .. ")"
        end
        if plen > 2 then
            info = info .. string.format(" [%d bytes]", plen - 2)
        end
        if is_mismatch then
            info = info .. " [MISMATCH]"
        end

        pinfo.cols.info:set(info)
    end
end

-- Register for DLT_USER0 (encapsulation type 147).
local wtap = DissectorTable.get("wtap_encap")
wtap:add(147, proto)
