local arguments = {...}
local synx_env = _G.env or error('run getrenv()._G.env = getgenv() on synapse or another exploit that has rconsoleprint')
local Ignored = arguments[1] or {
	DATA_REPLIC_PING = true,
	DATA_REPLIC_PING_BACK = true,
	TIMESTAMP = true,
	DATA_REPLIC_HASH = true
}

local packetids = arguments[2] or {
	[0x00] = "CONNECTED_PING",
	[0x01] = "UNCONNECTED_PING",
	[0x03] = "CONNECTED_PONG",
	[0x04] = "DETECT_LOST_CONNECTIONS",
	[0x05] = "OPEN_CONNECTION_REQUEST_1",
	[0x06] = "OPEN_CONNECTION_REPLY_1",
	[0x07] = "OPEN_CONNECTION_REQUEST_2",
	[0x08] = "OPEN_CONNECTION_REPLY_2",
	[0x09] = "CONNECTION_REQUEST",
	[0x10] = "CONNECTION_REQUEST_ACCEPTED",
	[0x11] = "CONNECTION_REQUEST_FAILED",
	[0x13] = "NEW_INCOMING_CONNECTION",
	[0x15] = "DISCONNECT_NOTIFICATION",
	[0x18] = "INVALPASSWORD",
	[0x1B] = "TIMESTAMP",
	[0x1C] = "UNCONNECTED_PONG",
	[0x81] = "SET_GLOBALS",
	[0x82] = "TEACH_DESCRIPTOR_DICTIONARIES",
	[0x83] = {
		Name = "DATA",
		SubData = {
			[1] = { -- 1 is the position of the byte after bytes[1] so 1 is bytes[2]
				[0x00] = "REPLIC_END",
				[0x01] = "REPLIC_DELETE_INSTANCE",
				[0x02] = "REPLIC_NEW_INSTANCE",
				[0x03] = "REPLIC_PROP",
				[0x04] = "REPLIC_MARKER",
				[0x05] = "REPLIC_PING",
				[0x06] = "REPLIC_PING_BACK",
				[0x07] = "REPLIC_EVENT",
				[0x08] = "REPLIC_REQUEST_CHAR",
				[0x09] = "REPLIC_ROCKY",
				[0x0A] = "REPLIC_CFRAME_ACK",
				[0x0B] = "REPLIC_JOIN_DATA",
				[0x0C] = "REPLIC_UPDATE_CLIENT_QUOTA",
				[0x0D] = "REPLIC_STREAM_DATA",
				[0x0E] = "REPLIC_REGION_REMOVAL",
				[0x0F] = "REPLIC_INSTANCE_REMOVAL",
				[0x10] = "REPLIC_TAG",
				[0x11] = "REPLIC_STATS",
				[0x12] = "REPLIC_HASH",
				[0x13] = "REPLIC_ATOMIC",
				[0x14] = "REPLIC_STREAM_DATA_INFO"
			}
		}
	},
	[0x84] = "MARKER",
	[0x85] = "PHYSICS",
	[0x86] = "TOUCHES",
	[0x87] = "CHAT_ALL",
	[0x88] = "CHAT_TEAM",
	[0x89] = "REPORT_ABUSE",
	[0x8A] = "SUBMIT_TICKET",
	[0x8B] = "CHAT_GAME",
	[0x8C] = "CHAT_PLAYER",
	[0x8D] = "CLUSTER",
	[0x8E] = "PROTOCOL_MISMATCH",
	[0x8F] = "PREFERRED_SPAWN_NAME",
	[0x90] = "PROTOCOL_SYNC",
	[0x91] = "PLACEVERIFICATION",
	[0x92] = "DICTIONARY_FORMAT",
	[0x93] = "HASH_MISMATCH",
	[0x94] = "SECURITY_KEY_MISMATCH",
	[0x95] = "REQUEST_STATS",
	[0x96] = "NEW_SCHEMA"
}

while true do
	local t = "{ "
	local bytes = rnet.nextPacket().bytes

	for k,v in next, bytes do
		t = t .. " " .. string.format("0x%02X ", v);
	end

	local prefix = "UNKOWN_PACKET"

	if packetids[bytes[1]] then
		if packetids[bytes[1]].Name then
			prefix = packetids[bytes[1]].Name
			for k,v in next, packetids[bytes[1]].SubData do
				if v[bytes[1 + k]] then
					prefix = prefix .. "_" .. v[bytes[1 + k]]
				end
			end
		else
			prefix = packetids[bytes[1]]
		end
	end

	if not Ignored[prefix] then
		synx_env.rconsoleprint(prefix .. ": " .. t .. "}\n")
	end
end
