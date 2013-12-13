lzmq-auth
=========
[![Build Status](https://travis-ci.org/moteus/lzmq-auth.png?branch=master)](https://travis-ci.org/moteus/lzmq-auth)

Implementaion of [czmq zauth](http://czmq.zeromq.org/manual:zauth) class.<br/>
For now lzmq-auth does not support automatic reload password and certificates files.

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

