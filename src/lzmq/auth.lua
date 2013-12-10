local zmq      = require "lzmq"
local zthreads = require "lzmq.threads"

local zauth = {} do
zauth.__index = zauth

function zauth:new(ctx)
  local o = setmetatable({
    private_ = {
      ctx = assert(ctx);
    }
  }, self)

  return o
end

function zauth:started()
  return not not self.private_.thread
end

function zauth:context()
  return self.private_.ctx
end

function zauth:start()
  if not self:started() then
    local thread, pipe = zthreads.fork(self.private_.ctx, 'require "lzmq.impl.auth_zap"(...)')
    if not thread then return nil, pipe end
    thread:start()
    self.private_.thread, self.private_.pipe = thread, pipe
  end
  return true
end

function zauth:stop()
  local thread, pipe = self.private_.thread, self.private_.pipe
  if thread then
    pipe:send('TERMINATE')
    thread:join()
    pipe:close()
    self.private_.thread, self.private_.pipe = nil
  end
end

function zauth:allow(address)
  local pipe = self.private_.pipe
  pipe:sendx('ALLOW', address)
  return pipe:recv()
end

function zauth:deny(address)
  local pipe = self.private_.pipe
  pipe:sendx('DENY', address)
  return pipe:recv()
end

function zauth:verbose(...)
  local pipe = self.private_.pipe
  local enable = ...
  if select("#", ...) == 0 then enable = true end
  pipe:sendx('VERBOSE', enable and '1' or '0')
  return pipe:recv()
end

function zauth:configure_plain(domain, passwords)
  local pipe = self.private_.pipe
  domain = domain or '*'
  pipe:sendx('PLAIN', domain, passwords)
  return pipe:recv()
end

function zauth:configure_curve(domain, location)
  local pipe = self.private_.pipe
  pipe:sendx('CURVE', domain or '*', location)
  return pipe:recv()
end

end

local selftest do

local ZSOCKET_DYNFROM = 0xc000
local ZSOCKET_DYNTO   = 0xffff

local function dyn_bind (sok, address)
  local ok, err
  for port = ZSOCKET_DYNFROM, ZSOCKET_DYNTO do
    ok, err = sok:bind(address .. ":" .. tostring(port))
    if ok then return port end
  end
  return nil, err
end

local function s_can_connect(ctx, server, client)
  local port_nbr = zmq.assert(dyn_bind(server, "tcp://127.0.0.1"))
  assert(client:connect("tcp://127.0.0.1:" .. tostring(port_nbr)))
  server:send("Hello, World")
  client:set_rcvtimeo(200)
  local success = (client:recv() == "Hello, World")

  client:close()
  server:close()

  return success, ctx:socket(zmq.PUSH),ctx:socket(zmq.PULL)
end

local TESTDIR = ".test_zauth"

local function test_impl(auth, verbose)
  local path  = require "path"
  local zcert = require "cert"

  local ctx = assert(auth:context())

  auth:start()
  auth:verbose(verbose)

  local server  = ctx:socket(zmq.PUSH)
  local client  = ctx:socket(zmq.PULL)
  local success 

  -- A default NULL connection should always success, and not
  -- go through our authentication infrastructure at all.
  success, server, client = s_can_connect(ctx, server, client)
  assert(success)

  -- When we set a domain on the server, we switch on authentication
  -- for NULL sockets, but with no policies, the client connection
  -- will be allowed.
  server:set_zap_domain("global")
  success, server, client = s_can_connect(ctx, server, client)
  assert(success)

  -- Blacklist 127.0.0.1, connection should fail
  server:set_zap_domain("global")
  auth:deny("127.0.0.1")
  success, server, client = s_can_connect(ctx, server, client)
  assert(not success)

  -- Whitelist our address, which overrides the blacklist
  server:set_zap_domain("global")
  auth:deny("127.0.0.1")
  auth:allow("127.0.0.1")
  success, server, client = s_can_connect(ctx, server, client)
  assert(success)

  -- Try PLAIN authentication
  server:set_plain_server(1)
  client:set_plain_username("admin")
  client:set_plain_password("Password")
  success, server, client = s_can_connect(ctx, server, client)
  assert(not success)

  local pass_path = path.join(TESTDIR, "/password-file")
  local password  = assert(io.open(pass_path, "w+"))
  password:write("admin=Password\n")
  password:close()

  server:set_plain_server(1)
  client:set_plain_username("admin")
  client:set_plain_password("Password")
  auth:configure_plain("*", pass_path);
  success, server, client = s_can_connect(ctx, server, client)
  assert(success)

  server:set_plain_server(1)
  client:set_plain_username("admin")
  client:set_plain_password("Bogus")
  auth:configure_plain("*", pass_path);
  success, server, client = s_can_connect(ctx, server, client)
  assert(not success)

  -- Try CURVE authentication
  -- We'll create two new certificates and save the client public
  -- certificate on disk; in a real case we'd transfer this securely
  -- from the client machine to the server machine.
  local server_cert = zcert.new()
  local client_cert = zcert.new()
  local server_key = server_cert:public_key(true)

  -- Test without setting-up any authentication
  server_cert:apply(server)
  client_cert:apply(client)
  server:set_curve_server(1)
  client:set_curve_serverkey(server_key)
  success, server, client = s_can_connect(ctx, server, client)
  assert(not success)

  -- Test full client authentication using certificates
  server_cert:apply(server)
  client_cert:apply(client)
  server:set_curve_server(1)
  client:set_curve_serverkey(server_key)
  client_cert:save_public(path.join(TESTDIR, "mycert.key"))
  auth:configure_curve("*", TESTDIR)
  success, server, client = s_can_connect(ctx, server, client)
  assert(success)

end

selftest = function(verbose)
  io.write (" * zauth: ")

  local path = require "path"
  path.mkdir(TESTDIR)
  assert(path.isdir(TESTDIR))

  local auth = zauth:new(zmq.context())
  assert(pcall(test_impl, auth, verbose))
  auth:stop()
  auth:context():destroy()

  path.each(path.join(TESTDIR, "*.*"), path.remove)
  -- path.each with lfs <1.6 close dir iterator only on gc.
  collectgarbage("collect") collectgarbage("collect")
  path.rmdir(TESTDIR)
  
  io.write(" OK\n")
end

end

return {
  new      = function(...) return zauth:new(...) end;
}
