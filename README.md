# SchemaWAF

SchemaWAF is a simple 
[positive-security-based](https://www.owasp.org/index.php/Positive_security_model)
[web application firewall](https://www.owasp.org/index.php/Web_Application_Firewall) based on 
[OpenResty](https://openresty.org/).

Requests to an upstream webserver are validated against a schema defining all valid requests.
The schema defines regular-expression whitelists of request method, path, GET paramaters, 
POST parameters, and header values. Any unexpected values are filtered out.

## To try the example echo server:

This runs SchemaWAF on localhost port 80 with the schema in
 `example/schema.json`. Any request to `http://localhost/path` will either be blocked
 by SchemaWAF, or reach the upstream echo server and print the details of the filtered request.

Run the example server:

    $ cd example/
    $ docker-compose 

Unexpected routes return 404 without reaching the upstream server:

    $ curl 'http://localhost/unknown'
    <html>
    <head><title>404 Not Found</title></head>
    <body bgcolor="white">
    <center><h1>404 Not Found</h1></center>
    <hr><center>openresty/1.11.2.5</center>
    </body>
    </html>

Unexpected GET, POST, or header keys for known routes are filtered out and passed upstream:

    $ curl -H "Ignore: this" -d "username=joe&ignore=this" 'http://localhost/login?ignore=this'
    Request: POST /login
    
    Headers:
    host: echo-app
    content-length: 12
    user-agent: curl/7.52.1
    connection: close
    content-type: application/x-www-form-urlencoded
    accept: */*
    
    GET:
    
    POST:
    username: joe

Unexpected values for known parameters return 401 without reaching the upstream server:

    $ curl -i -d "username=?" 'http://localhost/login'
    HTTP/1.1 401 Unauthorized
    Server: openresty/1.11.2.5
    Date: Fri, 06 Oct 2017 15:51:32 GMT
    Content-Type: application/octet-stream
    Transfer-Encoding: chunked
    Connection: keep-alive
    
    Invalid POST param value for key username

## Schema format

In theory the right format to use would be OpenAPI, but for now the schema.json file follows this pattern:

    {
      "version": 1,
      "patterns": {
        "$pattern_name": "<regex>",
        ...
      },
      "headers": {
        "user-agent": "$pattern_name",
        ...
      },
      "routes": [
        {
          "pattern": "/api",
          "methods": [
            "GET",
            "POST"
          ],
          "get_params": {
            "key": "$pattern_name",
            ...
          },
          "post_params": {
            "key": "$pattern_name",
            ...
          }
        },
        ...
      ]
    }

## Q

### Is this a good idea?

Maybe? Cloudflare 
[did something similar](https://blog.cloudflare.com/cloudflares-new-waf-compiling-to-lua/) 
to implement their blacklisting WAF.

### How do you keep the schema up to date?

Manually for now. But there are a bunch of ways for 
[APIs to publish schemas](http://www.django-rest-framework.org/api-guide/schemas/)
that might allow auto publishing of routes from upstream servers.
