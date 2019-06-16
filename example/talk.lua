-- This is a simple Wireshark/`tshark` plugin written in Lua. It is
-- a protocol dissector for the equally simple protocol used by the
-- original `talk(1)` program and its server counterpart, `talkd(8)`.
--
-- I have attempted to comment my code as thoroughly as I understand
-- it, including using LDoc conventions. See
--
--     https://stevedonovan.github.io/ldoc/
--
-- for details on LDoc and usage.
--
-- @script talk
-- @license GPL-3.0-or-later

if disable_lua == nil and not _WIREBAIT_ON_ then  --disable_lua == nil checks if this script is being run from wireshark.
  local wirebait = require("wirebaitlib");
  local dissector_tester = wirebait.new({dissector_filepath="example/talk.lua", only_show_dissected_packets=true});

  --[[Two options here:
        - call dissector_tester:dissectHexData() to dissect hex data from a string (no pcap needed) 
        - call dissector_tester:dissectPcap() to dissect packets from a pcap file]]
  --dissector_tester:dissectPcap("example/captures/talk_conv.pcap")  --dissetion from packet data contained in a pcap file
  --dissector_tester:dissectPcap("/Users/markus/Downloads/ntalk-dissector-master/talk-callee-not-accepting-mesg.pcap")
  dissector_tester:dissectPcap("/Users/markus/Downloads/ntalk-dissector-master/talk-callee-not-logged-in.pcap")

  return
end

-- Choose some sensible defaults.
local default_settings = {
    port = 518
}

-- Create a Proto object, but don't register it yet.
local talk = Proto('talk', 'Talk Protocol')

-- Define protocol message and reply opcodes. These are used in the
-- `ProtoField`s for `talk.request_type` and `talk.reply_type`.
local talk_request_types = {
    [0] = 'LEAVE_INVITE',
    [1] = 'LOOK_UP',
    [2] = 'DELETE',
    [3] = 'ANNOUNCE'
}
local talk_reply_types = {
    [0] = 'SUCCESS',           -- Operation completed properly.
    [1] = 'NOT_HERE',          -- Callee not logged in.
    [2] = 'FAILED',            -- Operation failed for unexplained reason.
    [3] = 'MACHINE_UNKNOWN',   -- Caller's machine name unknown.
    [4] = 'PERMISSION_DENIED', -- Callee's TTY doesn't permit announce.
    [5] = 'UNKNOWN_REQUEST',   -- Request has invalid type value.
    [6] = 'BADVERSION',        -- Request has invalid protocol version.
    [7] = 'BADADDR',           -- Request has invalid addr value.
    [8] = 'BADCTLADDR'         -- Request has invalid ctl_addr value.
}

-- Create protocol fields, which map to structs defined in `talkd.h`.
local pfields = {
    protocol_version = ProtoField.uint8('talk.version', 'Protocol version'),
    request_type     = ProtoField.uint8('talk.request_type', 'Request type', base.DEC, talk_request_types),
    reply_type       = ProtoField.uint8('talk.reply_type', 'Reply type', base.DEC, talk_reply_types),
    pad              = ProtoField.uint8('talk.pad', 'Pad'),
    message_id_num   = ProtoField.uint32('talk.msg_id', 'Message ID number'),
    -- TODO:
    -- The addresses here are actually `struct osockaddr`, which `talkd.h` defines as follows:
    -- /*
    --  * 4.3 compat sockaddr
    --  */
    -- #include <_types.h>
    -- struct osockaddr {
    --     __uint16_t      sa_family;      /* address family */
    --     char            sa_data[14];    /* up to 14 bytes of direct address */
    -- };
    --
    -- I think that this "address family" is either always 0x0002, which
    -- means that what follows is a 2-byte port number, then a 4-byte IPv4
    -- address. Otherwise, the entire address space is an IPv6 address.
    -- I'm not sure where the port number would be, then, though.
    address_port     = ProtoField.uint16('talk.addr_port', 'Port'),
    address          = ProtoField.ipv4('talk.addr', 'Address'),
    ctl_address_port = ProtoField.uint16('talk.ctl_addr_port', 'Control port'),
    ctl_address      = ProtoField.ipv4('talk.ctl_addr', 'Control address'),
    caller_pid       = ProtoField.int32('talk.pid', 'Process ID'),
    caller_name      = ProtoField.string('talk.caller_name', "Caller's name", base.ASCII, 'Account name of the calling user'),
    callee_name      = ProtoField.string('talk.callee_name', "Callee's name", base.ASCII, 'Account name of the called user'),
    callee_tty_name  = ProtoField.string('talk.callee_tty_name', "Callee's TTY name")
}

-- Register the above fields as part of the Talk protocol.
talk.fields = pfields

-- The Talk protocol has a client-server architecture. Messages sent
-- from the client to server are called `CTL_MSG`s, while messages
-- sent from the server to the client are called `CTL_RESPONSE`s.
local ctl_msg = {
    ['vers']          = pfields.protocol_version,
    ['type']          = pfields.request_type,
    ['answer']        = pfields.reply_type,
    ['pad']           = pfields.pad,
    ['id_num']        = pfields.message_id_num,
    ['addr_port']     = pfields.address_port,
    ['addr']          = pfields.address,
    ['ctl_addr_port'] = pfields.ctl_address_port,
    ['ctl_addr']      = pfields.ctl_address,
    ['pid']           = pfields.caller_pid,
    ['l_name']        = pfields.caller_name,
    ['r_name']        = pfields.callee_name,
    ['r_tty']         = pfields.callee_tty_name
}
local ctl_response = {
    ['vers']      = pfields.protocol_version,
    ['type']      = pfields.request_type,
    ['answer']    = pfields.reply_type,
    ['pad']       = pfields.pad,
    ['id_num']    = pfields.message_id_num,
    ['addr_port'] = pfields.address_port,
    ['addr']      = pfields.address
}

-- Now that we've registered some fields for the `talk` Proto object,
-- create some analysis fields to view data that has been dissected.
local f_protocol_version = Field.new('talk.version')
local f_request_type     = Field.new('talk.request_type')
local f_reply_type       = Field.new('talk.reply_type')
local f_pad              = Field.new('talk.pad')
local f_message_id_num   = Field.new('talk.msg_id')
local f_address_port     = Field.new('talk.addr_port')
local f_address          = Field.new('talk.addr')
local f_ctl_address_port = Field.new('talk.ctl_addr_port')
local f_ctl_address      = Field.new('talk.ctl_addr')
local f_caller_pid       = Field.new('talk.pid')
local f_caller_name      = Field.new('talk.caller_name')
local f_callee_name      = Field.new('talk.callee_name')
local f_callee_tty_name  = Field.new('talk.callee_tty_name')

--- Helper to determine whether the packet is a request.
--
-- There is no field in the protocol indicating the directionality of
-- the message, so a naive test is simply to check whether or not the
-- packet is destined to the `talkd` server's listening port.
--
-- @param pktinfo A Pinfo object representing the given packet.
--
-- @return boolean True if the packet is a message from the client.
local function isRequest(pktinfo)
    return pktinfo.dst_port == default_settings['port']
end

--- Helper to determine whether the packet is a reply.
--
-- @param pktinfo A Pinfo object representing the given packet.
--
-- @return boolean True if the packet is a message from the server.
local function isReply(pktinfo)
    return not isRequest(pktinfo)
end

--- Helper to print the request message type's name.
--
-- The request type is a byte whose value indicates that the client
-- is asking the server to take a particular action.
--
-- See the `talk_request_types` table for these values.
--
-- @return string
local function getRequestType()
    --warn("f_request_type()() " .. f_request_type()())
    --warn("f_request_type() " .. tostring(f_request_type()))
    return talk_request_types[f_request_type()()]
end

--- Helper to print the reply message type's name.
--
-- In a Talk request (message from client to server), this will always
-- be 0x00 (`SUCCESS`), and is ignored.
--
-- @return string
local function getReplyType()
    return talk_reply_types[f_reply_type()()]
end

--- The actual dissector for the Talk protocol.
--
-- The callback function that Wireshark calls when disssecting a
-- given packet matching the Talk protocol's UDP port.
--
-- @param tvbuf The `Tvb` object for the packet.
-- @param pktinfo The `Pinfo` object representing the packet info.
-- @param root The `TreeItem` object representing the root of the tree view.
talk.dissector = function (tvbuf, pktinfo, root)

    -- Display protocol name in Packet List pane's Protocol column.
    pktinfo.cols.protocol:set('Talk')

    -- Get this packet's length.
    local pktlen = tvbuf:reported_length_remaining()

    -- Since Talk does not encapsulate any other protocol, the entire
    -- packet is part of the Talk protocol, so its whole range should
    -- be added to the Packet Details pane as the Talk protocol.
    local tree = root:add(talk, tvbuf:range(0, pktlen))

    -- TODO: Make sure the packet seems sensible. I.e., not malformed
    --       in some way. Should also add some hints for the analyst,
    --       probably in the form of Wireshark "expert info" fields.

    -- Parse the bytes in the packet buffer and add its information
    -- to the Packet Details pane as an expandable tree view.
    local protocol_version = tvbuf:range(0, 1)
    tree:add(pfields.protocol_version, protocol_version)

    local request_type = tvbuf:range(protocol_version:offset() + protocol_version:len(), 1)
    tree:add(pfields.request_type, request_type)

    local reply_type = tvbuf:range(request_type:offset() + request_type:len(), 1)
    tree:add(pfields.reply_type, reply_type)

    local pad = tvbuf:range(reply_type:offset() + reply_type:len(), 1) -- TODO: What is this used for???
    tree:add(pfields.pad, pad)

    local message_id_num = tvbuf:range(pad:offset() + pad:len(), 4)
    tree:add(pfields.message_id_num, message_id_num)

    -- TODO: What are the two bytes in between the message_id_num and
    --       the next field? Part of the `struct osockaddr`?

    -- Always starts at 10 bytes offset from beginning of packet, not
    -- immediately following the `message_id_num`'s last byte.
    local address_port = tvbuf:range(10, 2)
    tree:add(pfields.address_port, address_port)

    local address = tvbuf:range(address_port:offset() + address_port:len(), 4)
    tree:add(pfields.address, address)

    local str_info = ''
    if isRequest(pktinfo) then
        str_info = 'CTL_MSG: '
        -- TODO: What are the two bytes in between the address and the
        --       the next field? Part of the `struct osockaddr`?

        -- Always start at 26 bytes offset from the beginning of packet.
        local ctl_address_port = tvbuf:range(26, 2)
        tree:add(pfields.ctl_address_port, ctl_address_port)

        local ctl_address = tvbuf:range(ctl_address_port:offset() + ctl_address_port:len(), 4)
        tree:add(pfields.ctl_address, ctl_address)

        -- Always start at 40 bytes offset from the beginning of packet.
        local caller_pid = tvbuf:range(40, 4)
        tree:add(pfields.caller_pid, caller_pid)

        -- 12 bytes is the default size of the name string buffers
        -- in `talkd.h`, used for both the caller and callee's names.
        local caller_name = tvbuf:range(caller_pid:offset() + caller_pid:len(), 12)
        tree:add(pfields.caller_name, caller_name)

        local callee_name = tvbuf:range(caller_name:offset() + caller_name:len(), 12)
        tree:add(pfields.callee_name, callee_name)

        -- The TTY name is given a buffer 16 bytes long in `talkd.h`.
        local offset = callee_name:offset() + callee_name:len()
        local last   = pktlen - offset
        local callee_tty_name = tvbuf:range(offset, last)
        tree:add(pfields.callee_tty_name, callee_tty_name)

        -- Set text for the tree items in the Packet Details pane, and
        -- set text for the Info column in the Packet List pane.
        if 'LOOK_UP' == getRequestType() then
            str_info = str_info .. '"' .. f_caller_name()() .. '" looking for invitation from "' .. f_callee_name()() .. '"'
        elseif 'ANNOUNCE' == getRequestType() then
            str_info = str_info .. 'Ringing "'
                .. f_callee_name()() .. '", "' ..  f_caller_name()() .. '" calling'
            tree:append_text(', ' .. f_caller_name()() .. ' ringing ' .. f_callee_name()())
        elseif 'LEAVE_INVITE' == getRequestType() then
            str_info = str_info .. 'Leave invitation for "' .. f_callee_name()() .. '"'
                .. ' from ' .. f_caller_name()() .. '@'
                .. tostring(f_address()()) .. ':' .. tostring(f_address_port()())
        elseif 'DELETE' == getRequestType() then
            str_info = str_info .. 'Delete message ID ' .. f_message_id_num()()
        end
        pktinfo.cols.info:set(str_info)
    else
        -- Set text for the tree items in the Packet Details pane, and
        -- set text for the Info column in the Packet List pane.
        str_info = 'CTL_RESPONSE: '
        if 'LOOK_UP' == getRequestType() and 'SUCCESS' == getReplyType() then
            str_info = str_info .. 'Found invitation: call ' .. tostring(f_address()()) .. ':' .. tostring(f_address_port()())
                .. ' to connect'
        elseif 'LOOK_UP' == getRequestType() and 'NOT_HERE' == getReplyType() then
            str_info = str_info .. 'No existing invitation; message ID ' .. f_message_id_num()()
        elseif 'ANNOUNCE' == getRequestType() and 'SUCCESS' == getReplyType() then
            str_info = str_info .. 'Successful announce; message ID ' .. f_message_id_num()()
        elseif 'ANNOUNCE' == getRequestType() and 'NOT_HERE' == getReplyType() then
            str_info = str_info .. 'Callee is not here; message ID ' .. f_message_id_num()()
        elseif 'ANNOUNCE' == getRequestType() and 'PERMISSION_DENIED' == getReplyType() then
            str_info = str_info .. 'Callee is not accepting messages; message ID ' .. f_message_id_num()()
        elseif 'LEAVE_INVITE' == getRequestType() and 'SUCCESS' == getReplyType() then
            str_info = str_info .. 'Successfully left invitation; message ID ' .. f_message_id_num()()
        elseif 'DELETE' == getRequestType() then
            str_info = str_info .. 'Deleted message'
        end
        pktinfo.cols.info:set(str_info)

        -- TODO: Figure out what these last 8 bytes for a reply packet
        --       mean. Meanwhile fallback to generic "Data" dissector.
        --[[Dissector.get('data'):call(
            tvbuf:range(
                address:offset() + address:len()
            ):tvb(), pktinfo, root
        )]]
    end

end

-- Invoke our dissector for a specific UDP port.
DissectorTable.get('udp.port'):add(default_settings.port, talk)
