return function (...)

local function prequire(...)
  local ok, mod = pcall(require, ...)
  if ok then return mod end
  return nil, mod
end

local zmq      = require "lzmq"
local zloop    = require "lzmq.loop"
local zcert    = require "lzmq.cert"
local ctx      = require "lzmq.threads".get_parent_ctx()
local path     = prequire "path"
local pipe     = ...

local CURVE_ALLOW_ANY = "*"

local loop
local whitelist = {}
local blacklist = {}
local passwords = {}
local certs     = {}
local allow_any = false
local verbose   = false

local function log(...)
  if verbose then
    print(string.format(...))
  end
end

local function load_certificates(location)
  local res = {}

  if not (path and path.each) then
    log("E: module `path` not found")
    return res
  end

  path.each(path.join(location, "*.key"), function(f)
    if f:sub(-11) ~= ".key_secret" then
      local cert = zcert.load(f)
      if cert then
        res[cert:public_key(true)] = 'OK'
      else
        log("E: can not load cert: %s", f)
      end
    end
  end, {
    skipdirs = true;
    recurse  = true;
  })
  return res
end

local function load_passwords(location)
  local f, err = io.open(location, 'r+')
  if not f then return nil, err end
  local res = {}
  for str in f:lines() do
    local user, pass = string.match(str, "%s*([^=]-)%s*=%s*([^=]-)%s*$")
    if user then res[user] = pass end
  end
  f:close()
  return res
end

local function recv_zap(sok)
  local msg, err = sok:recv_all()
  if not msg then return err end
  local req = {
    version    = msg[1]; -- Version number, must be "1.0"
    sequence   = msg[2]; -- Sequence number of request
    domain     = msg[3]; -- Server socket domain
    address    = msg[4]; -- Client IP address
    identity   = msg[5]; -- Server socket idenntity
    mechanism  = msg[6]; -- Security mechansim
  }
  if req.mechanism == "PLAIN" then
    req.username = msg[7];   -- PLAIN user name
    req.password = msg[8];   -- PLAIN password, in clear text
  elseif req.mechanism == "CURVE" then
    req.client_key = msg[7]; -- CURVE client public key
  end
  return req
end

local function send_zap(sok, req, status, text)
  return sok:send_all{"1.0", req.sequence, status, text, "", ""}
end

local on_auth do -- auth

local function auth_plain(domain, username, password)
  if (not domain) or (domain == '') then domain = '*' end
  password = password or ""

  local allow = false
  local reason = ""
  local status

  if passwords then
    local pass_t = passwords[domain]
    if pass_t then
      if pass_t[username] then
        if password == pass_t[username] then
          allow = true
        else
          reason = "Invalid password"
        end
      else
        reason = "Invalid username"
      end
    else
      reason = "Invalid domain"
    end
  
    log("I: %s (PLAIN) domain=%s username=%s password=%s (%s)",
      allow and "ALLOWED" or "DENIED", domain, username, password, reason
    )

  else
    reason = "No passwords defined"
    log("I: DENIED (PLAIN) no passwords defined")
  end

  return allow, reason
end

local function auth_curve(domain, client_key)
  if allow_any then
    log("I: ALLOWED (CURVE allow any client)")
    return true, "OK"
  end

  if (not domain) or (domain == '') then domain = '*' end

  local allow = false
  local reason = ""

  if certs[domain] then
    -- convert binary key to z85 text
    z85_client_key = zmq.z85_encode(client_key)
    if certs[domain][z85_client_key] then
      allow, reason = true, "OK"
    else
      reason = "Unknown key"
    end
    log("I: %s (CURVE) domain=%s client_key=%s",
      allow and "ALLOWED" or "DENIED", domain, z85_client_key
    )
  else
    reason = "Unknown domain"
  end

  return allow, reason
end

-- Setup auth handler
-- http://rfc.zeromq.org/spec:27
on_auth = function(sok)
  local msg = recv_zap(sok)
  if not msg then return end

  if msg.version ~= "1.0" then
    return send_zap(sok, msg, "400", "Invalid version")
  end

  -- Check if address is explicitly whitelisted or blacklisted
  local allowed = false
  local denied  = false
  local reason  = "NO ACCESS"
 
  if next(whitelist) then
    if whitelist[msg.address] then
      allowed = true
      log("I: PASSED (whitelist) address=%s", msg.address)
    else
      denied = true
      reason = "Address not in whitelist"
      log("I: DENIED (not in whitelist) address=%s", msg.address)
    end
  elseif next(blacklist) then
    if blacklist[msg.address] then
      denied = true
      reason = "Address is blacklisted"
      log("I: DENIED (blacklist) address=%s", msg.address)
    else
      allowed = true
      log("I: PASSED (not in blacklist) address=%s", msg.address)
    end
  end

  --Mechanism-specific checks
  if not denied then
    if msg.mechanism == 'NULL' and not allowed then
      --For NULL, we allow if the address wasn't blacklisted
      log("I: ALLOWED (NULL)")
      allowed = true
    elseif msg.mechanism == 'PLAIN' then
      -- For PLAIN, even a whitelisted address must authenticate
      allowed, reason = auth_plain(msg.domain, msg.username, msg.password)
    elseif msg.mechanism == 'CURVE' then
      -- For CURVE, even a whitelisted address must authenticate
      allowed, reason = auth_curve(msg.domain, msg.client_key)
    end
  end

  if allowed then
    send_zap(sok, msg, "200", "OK")
  else
    send_zap(sok, msg, "400", reason)
  end
end

end

local on_pipe do -- front end API

local API = {} do

function API.ALLOW(msg)
  local addr = msg[2]
  whitelist[addr] = true
  return 'OK'
end

function API.DENY(msg)
  local addr = msg[2]
  blacklist[addr] = true
  return 'OK'
end

function API.PLAIN(msg)
  local domain      = msg[2]
  passwords[domain] = load_passwords(msg[3])
  return 'OK'
end

function API.CURVE(msg)
  local domain    = msg[2]
  local location  = msg[3]

  allow_any = (location == CURVE_ALLOW_ANY)
  if not allow_any then
    certs[domain] = load_certificates(location)
  end

  return 'OK'
end

function API.VERBOSE(msg)
  local enabled = msg[2]
  verbose = (enabled == '1')
  return 'OK'
end

function API.TERMINATE(msg)
  loop:interrupt()
  return 'OK'
end

end

on_pipe = function(sok)
  local msg = sok:recv_all()
  if not msg then return loop:interrupt() end
  local cmd = msg[1]
  log("I: auth received API command: %s", table.concat(msg, '::'))
  local fn = API[cmd]
  if not fn then
    return log("E: invalid auth command from API: %s", cmd)
  end
  local res = fn(msg)
  if res then sok:send(res) end
end

end

do -- main loop

local ok, err

repeat

loop, err = zloop.new(2, ctx)
if not loop then
  err = "can not create zmq.loop: " .. tostring(err)
  break
end

ok, err = loop:add_new_bind(zmq.REP, "inproc://zeromq.zap.01", on_auth)
if not ok then
  err = "can not bind to ZAP interface: " .. tostring(err)
  break
end

ok, err = loop:add_socket(pipe, on_pipe)
if not ok then
  err = "can not start poll pipe socket: " .. tostring(err)
  break
end

until true

if ok then
  pipe:send("OK")

  log("I: start auth ZAP loop")
  loop:start()
  log("I: auth ZAP loop interrupted")

else
  log("E: " .. tostring(err))
  pipe:sendx("ERROR", tostring(err))
end

end

ctx:destroy(100)

log("I: ZAP thread done!")
end
