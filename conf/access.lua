local function process()
    local uri = ngx.var.uri
    if uri ~= "/ok" then
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
end

return process