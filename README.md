lzmq-auth
=========
[![Build Status](https://travis-ci.org/moteus/lzmq-auth.png?branch=master)](https://travis-ci.org/moteus/lzmq-auth)

Implementaion of [czmq zauth](http://czmq.zeromq.org/manual:zauth) class.<br/>
For now lzmq-auth does not support automatic reload password and certificates files.

###Install

Using LuaRocks:

You need install `lzmq` or `lzmq-ffi` (>3.1).
To support unit test and CURVE certificate directory you need [lua-path](https://github.com/moteus/lua-path) module.

```
luarocks install lzmq
luarocks install lzmq-auth
luarocks install lua-path
luarocks install luafilesystem
```

###Usage
```lua
local zmq   = require "lzmq"
local zauth = require "lzmq.auth"
local ctx   = zmq.context()
local auth  = zauth.new(ctx)

auth:start()            -- start ZAP service thread
auth:allow('127.0.0.1') -- add IP address to whitelist

-- regular ZMQ code

auth:stop()             -- stop ZAP service thread

```

[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/moteus/lzmq-auth/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

