-- http://openmymind.net/An-Introduction-To-OpenResty-Nginx-Lua/

local function process()
    ngx.header.content_type = "text/html";
    ngx.say(ngx.var.uri .. " allowed")
end

return process