--[[
     to copy and paste run getrenv()._G.env = getgenv() on synapse or another exploit that has rconsoleprint
     if you're just using celery by itself then open roblox's dev console for packets

     there will probably be updates
     it sometimes misses packets
--]]

_G.env = _G.env or {
    rconsoleprint = print -- for the people who don't have access to rconsoleprint
}

local Ignored = { -- these won't show in the console
    DATA_REPLIC_PING = true,
    DATA_REPLIC_PING_BACK = true,
    TIMESTAMP = true,
    DATA_REPLIC_HASH = true
}

loadstring(game:HttpGet("https://raw.githubusercontent.com/68656c702e/celery-packet-logger/main/logger.lua"))(Ignored)
