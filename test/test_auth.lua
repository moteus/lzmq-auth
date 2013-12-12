local HAS_RUNNER = not not lunit
local lunit      = require "lunit"
local TEST_CASE  = assert(lunit.TEST_CASE)
local skip       = lunit.skip or function() end

local zmq        = require "lzmq"
local zauth      = require "lzmq.auth"
local zcert      = require "lzmq.cert"
local path       = require "path"

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

local _ENV = TEST_CASE "lzmq.auth" do

local TESTDIR   = ".test_auth"
local pass_path = path.join(TESTDIR, "password-file")
local auth, ctx, server, client, auth2

local function test_connect()
  local port_nbr = assert_number(dyn_bind(server, "tcp://127.0.0.1"))
  assert(client:connect("tcp://127.0.0.1:" .. tostring(port_nbr)))

  server:send("Hello, World")
  local success = (client:recv() == "Hello, World")

  return success
end

function setup()
  ctx  = assert(zmq.context())
  auth = assert(zauth.new(ctx))
  assert(auth:start())
  auth:verbose(false) -- to wait

  path.mkdir(TESTDIR)
  assert(path.isdir(TESTDIR))

  server = assert(ctx:socket{zmq.PUSH})
  client = assert(ctx:socket{zmq.PULL, rcvtimeo = 200})

end

function teardown()
  if client then client:close() end
  if server then server:close() end
  if auth   then auth:stop()    end
  if auth2  then auth2:stop()   end
  if ctx    then ctx:destroy()  end

  path.each(path.join(TESTDIR, "*.*"), path.remove)
  -- path.each with lfs <1.6 close dir iterator only on gc.
  collectgarbage("collect") collectgarbage("collect")
  path.rmdir(TESTDIR)
end

function test_null()
  -- A default NULL connection should always success, and not
  -- go through our authentication infrastructure at all.
  assert_true(test_connect())
end

function test_null_domain()
  -- When we set a domain on the server, we switch on authentication
  -- for NULL sockets, but with no policies, the client connection
  -- will be allowed.
  server:set_zap_domain("global")
  assert_true(test_connect())
end

function test_blacklist()
  -- Blacklist 127.0.0.1, connection should fail
  server:set_zap_domain("global")
  auth:deny("127.0.0.1")
  assert_false(test_connect())
end

function test_whitelist()
  -- Whitelist our address, which overrides the blacklist
  server:set_zap_domain("global")
  auth:deny("127.0.0.1")
  auth:allow("127.0.0.1")
  assert_true(test_connect())
end

function test_plain_no_auth()
  -- Try PLAIN authentication
  server:set_plain_server(1)
  client:set_plain_username("admin")
  client:set_plain_password("Password")
  assert_false(test_connect())
end

function test_plain()
  local password  = assert(io.open(pass_path, "w+"))
  password:write("admin=Password\n")
  password:close()

  server:set_plain_server(1)
  client:set_plain_username("admin")
  client:set_plain_password("Password")
  auth:configure_plain("*", pass_path)

  assert_true(test_connect())
end

function test_plain_default_domain()
  local password  = assert(io.open(pass_path, "w+"))
  password:write("admin=Password\n")
  password:close()

  server:set_plain_server(1)
  client:set_plain_username("admin")
  client:set_plain_password("Password")
  assert_error(function() auth:configure_plain(pass_path, nil) end)
  auth:configure_plain(pass_path)

  assert_true(test_connect())
end

function test_plain_wrong_pass()
  local password  = assert(io.open(pass_path, "w+"))
  password:write("admin=Password\n")
  password:close()

  server:set_plain_server(1)
  client:set_plain_username("admin")
  client:set_plain_password("Bogus")
  auth:configure_plain("*", pass_path);

  assert_false(test_connect())
end

function test_curve_fail()
  -- Try CURVE authentication
  -- We'll create two new certificates and save the client public
  -- certificate on disk; in a real case we'd transfer this securely
  -- from the client machine to the server machine.
  local server_cert = zcert.new()
  local client_cert = zcert.new()
  local server_key  = server_cert:public_key(true)

  -- Test without setting-up any authentication
  server_cert:apply(server)
  client_cert:apply(client)
  server:set_curve_server(1)
  client:set_curve_serverkey(server_key)

  assert_false(test_connect())
end

function test_curve()
  -- Try CURVE authentication
  -- We'll create two new certificates and save the client public
  -- certificate on disk; in a real case we'd transfer this securely
  -- from the client machine to the server machine.
  local server_cert = zcert.new()
  local client_cert = zcert.new()
  local server_key  = server_cert:public_key(true)

  -- Test full client authentication using certificates
  server_cert:apply(server)
  client_cert:apply(client)
  server:set_curve_server(1)
  client:set_curve_serverkey(server_key)
  client_cert:save_public(path.join(TESTDIR, "mycert.key"))
  auth:configure_curve("*", TESTDIR)

  assert_true(test_connect())
end

function test_curve_default_domain()
  -- Try CURVE authentication
  -- We'll create two new certificates and save the client public
  -- certificate on disk; in a real case we'd transfer this securely
  -- from the client machine to the server machine.
  local server_cert = zcert.new()
  local client_cert = zcert.new()
  local server_key  = server_cert:public_key(true)

  -- Test full client authentication using certificates
  server_cert:apply(server)
  client_cert:apply(client)
  server:set_curve_server(1)
  client:set_curve_serverkey(server_key)
  client_cert:save_public(path.join(TESTDIR, "mycert.key"))
  assert_error(function() auth:configure_curve(TESTDIR, nil) end)
  auth:configure_curve(TESTDIR)

  assert_true(test_connect())
end

function test_start_error()
  local auth2 = zauth.new(ctx)
  local ok, err = auth2:start()
  assert( not ok )
end

end

if not HAS_RUNNER then lunit.run() end
