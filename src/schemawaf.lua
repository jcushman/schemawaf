local _M = {}

local cjson  = require "cjson"

-- loaded by init
_schema = {}

----------- helpers -------------

-- safely load json file into table
-- based on https://github.com/p0pr0ck5/lua-resty-waf/blob/428242a97f78eb6b373be07f32df6729a0616bb6/lib/resty/waf/util.lua#L167
local function load_json_file(path)
    local f = io.open(path)
    if f ~= nil then
        local data = f:read("*all")
        f:close()
        local jdata
        if pcall(function() jdata = cjson.decode(data) end) then
            return jdata, nil
        else
            return nil, "could not decode " .. data
        end
    else
        return nil, "could not open " .. path
    end
end

-- check if value completely matches regex
local function valid(value, regex)
    local m, err = ngx.re.match(value, regex .. "$", "ajo")
    return m
end

-- print debug message to stderr
local function debug(message)
    ngx.log(ngx.STDERR, message)
end

-- log a configuration error and exit
local function fatal_fail(message)
	ngx.log(ngx.ERR, message)
	ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

-- convert table of values to table of {value=true} for quick membership tests
local function Set (list)
    local set = {}
    for _, l in ipairs(list) do set[l] = true end
    return set
end

-- Given request_params, return only the params that are in route_params.
-- If a param is in route params but doesn't match the regex, return an error.
local function whitelist_params(route_params, request_params)
    local whitelist_params = {}
    for param, pattern in pairs(route_params) do
        if request_params[param] ~= nil then
            if valid(request_params[param], pattern) then
                whitelist_params[param] = request_params[param]
            else
                -- if param doesn't match regex, throw an error
                debug("invalid "..request_params[param].." "..pattern)
                return nil, param
            end
        end
    end
    return whitelist_params, nil
end

local function raise_error(status, message)
 ngx.status = status
 ngx.say(message)
 ngx.exit(ngx.HTTP_OK)  -- kills processing of nginx request -- status is overridden by above
end

-- look up patterns like "$alphanum" in the lookup table.
-- if pattern doesn't start with "$", just return pattern itself.
local function resolve_pattern(lookup_table, pattern)
    if string.sub(pattern, 1, 1) == "$" then
        local result = lookup_table[pattern]
        if result == nil then
            fatal_fail("Pattern not found: " .. pattern)
        end
        return result
    else
        return pattern
    end
end

-- call resolve_pattern on all patterns in a table
local function resolve_patterns(lookup_table, patterns)
    for k, v in pairs(patterns) do
        patterns[k] = resolve_pattern(lookup_table, v)
    end
end

local function dump_table(t)
    local out = ""
    for k, v in pairs(t) do
        out = out .. k .. ": " .. v .. "\n"
    end
    return out
end

----------- entry points (nginx phases) -------------

function _M.init_phase(schema_path)
    -- load rules json
    _schema, error = load_json_file(schema_path)
    if error then
        fatal_fail(error)
    end

    for _, route in ipairs(_schema.routes) do
        -- for performance, process the routes table to turn route.methods into Set()
        route.methods = Set(route.methods)

        -- resolve pattern references for POST
        if route.post_params then
            resolve_patterns(_schema.patterns, route.post_params)
        end

        -- resolve pattern references for GET
        if route.get_params then
            resolve_patterns(_schema.patterns, route.get_params)
        end
    end

    -- resolve pattern references for headers
    resolve_patterns(_schema.patterns, _schema.headers)
end

function _M.access_phase()

    local request_path = ngx.var.uri
    local request_method = ngx.req.get_method()
    local request_headers = ngx.req.get_headers()

    -- whitelist headers
    for header, header_value in pairs(request_headers) do
        if _schema.headers[header] ~= nil then
            if valid(header_value, _schema.headers[header]) then
                ngx.req.set_header(header, header_value)
            else
                debug("Clearing invalid header value "..header_value.." for "..header)
                ngx.req.clear_header(header)
            end
        else
            debug("Clearing unknown header "..header)
            ngx.req.clear_header(header)
        end
    end

    -- whitelist requested path
    for _, route in ipairs(_schema.routes) do

        -- find matching route and request method
        if route["methods"][request_method] and valid(request_path, route["pattern"]) then

            -- limit GET params to whitelist
            if route["get_params"] then
                local whitelisted_params, error_param = whitelist_params(route["get_params"], ngx.req.get_uri_args())
                if error_param then
                    return raise_error(ngx.HTTP_UNAUTHORIZED, "Invalid GET param value for key " .. error_param)
                end
                ngx.req.set_uri_args(whitelisted_params)
            else
                ngx.req.set_uri_args({})
            end

            -- limit POST params to whitelist
            if route["post_params"] then
                ngx.req.read_body()
                post_args = ngx.req.get_post_args()
                local whitelisted_params, error_param = whitelist_params(route["post_params"], post_args)
                if error_param then
                    return raise_error(ngx.HTTP_UNAUTHORIZED, "Invalid POST param value for key " .. error_param)
                end
                ngx.req.set_body_data(ngx.encode_args(whitelisted_params))
            else
                ngx.req.discard_body()
            end

            -- successfully passed all tests!
            return
        end
    end

    -- if we fall through to here, no whitelisted route was found
    ngx.exit(ngx.HTTP_NOT_FOUND)
end


function _M.content_phase()
    -- for debug -- simply return that request was allowed
    ngx.header.content_type = "text/html";
    ngx.say(ngx.var.uri .. " allowed")
end

return _M

