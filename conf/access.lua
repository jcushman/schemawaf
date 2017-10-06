-- site configuration

patterns = {
    alphanum="[a-zA-Z0-9]+",
}

routes = {
    {
        methods={"GET"},
        pattern="/cases",
        get={
            api_key=patterns["alphanum"],
            citation="[a-zA-Z0-9 \\.]+",
        },
    },
    {
        methods={"GET", "POST"},
        pattern="/login",
        post={
            username=patterns["alphanum"],
            password=patterns["alphanum"],
        },
    },
}

headers = {
    ["user-agent"]=".*",
    ["host"]=".*",
    ["content-type"]=".*",
    ["accept"]=".*",
    ["content-length"]="\\d+",
}

-- helpers --

local function valid(value, regex)
    -- check if value completely matches regex
    local m, err = ngx.re.match(value, regex .. "$", "ajo")
    return m
end

local function debug(message)
    -- print debug message to stderr
    ngx.log(ngx.STDERR, message)
end

local function Set (list)
    -- convert table of values to table of {value=true} for quick membership tests
    local set = {}
    for _, l in ipairs(list) do set[l] = true end
    return set
end

local function prep_routes()
    -- process the routes table to turn route.methods into Set()
    for _, route in ipairs(routes) do
        route["methods"] = Set(route["methods"])
    end
end

local function whitelist_params(route_params, request_params)
    -- Given request_params, return only the params that are in route_params.
    -- If a param is in route params but doesn't match the regex, return an error.
    local whitelist_params = {}
    for param, pattern in pairs(route_params) do
        if request_params[param] ~= nil then
            if valid(request_params[param], pattern) then
                whitelist_params[param] = request_params[param]
            else
                -- if param doesn't match regex, throw an error
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

-- handler --

local function process()

    local request_path = ngx.var.uri
    local request_method = ngx.req.get_method()
    local request_headers = ngx.req.get_headers()

    -- whitelist headers
    for header, header_value in pairs(request_headers) do
        if headers[header] ~= nil then
            if valid(header_value, headers[header]) then
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
    for _, route in ipairs(routes) do

        -- find matching route and request method
        if route["methods"][request_method] and valid(request_path, route["pattern"]) then

            -- limit GET params to whitelist
            if route["get"] then
                local whitelisted_params, error_param = whitelist_params(route["get"], ngx.req.get_uri_args())
                if error_param then
                    return raise_error(ngx.HTTP_UNAUTHORIZED, "Invalid GET param value for key " .. error_param)
                end
                ngx.req.set_uri_args(whitelisted_params)
            else
                ngx.req.set_uri_args({})
            end

            -- limit POST params to whitelist
            if route["post"] then
                ngx.req.read_body()
                local whitelisted_params, error_param = whitelist_params(route["post"], ngx.req.get_post_args())
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

prep_routes()

return process