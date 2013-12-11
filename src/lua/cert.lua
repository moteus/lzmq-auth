local zmq   = require "lzmq"
local io    = require "io"
local table = require "table"

local zcert = {} do
zcert.__index = zcert

function zcert:new_empty()
  local o = setmetatable({
    private_ = {}
  },self)

  return o
end

function zcert:new()
  return self:new_empty():init(
    zmq.curve_keypair(true)
  )
end

function zcert:destroy()
  self.private_ = nil
end

function zcert:init(pk, sk, meta)
  self.private_.public_key = pk
  self.private_.secret_key = sk
  self.private_.metadata = meta or self.private_.metadata or {}

  return self
end

function zcert:public_key(txt)
  if txt then
    return zmq.z85_encode(self.private_.public_key)
  end
  return self.private_.public_key
end

function zcert:secret_key(txt)
  if txt then
    return zmq.z85_encode(self.private_.secret_key)
  end
  return self.private_.secret_key
end

function zcert:set_meta(name, ...)
  local value = string.format(...)
  self.private_.metadata[name] = value
end

function zcert:meta(name)
  return self.private_.metadata[name]
end

function zcert:meta_keys()
  local keys = {}
  for k in pairs(self.private_.metadata) do
    table.insert(keys, k)
  end
  return keys
end

function zcert:apply(zsocket)
  zsocket:set_curve_secretkey(self:secret_key())
  zsocket:set_curve_publickey(self:public_key());
end

function zcert:dup()
  local meta = {}
  for k, v in pairs(self.private_.metadata) do meta[k] = v end

  return zcert:new_empty():init(
    self:public_key(), self:secret_key(), meta
  )
end

function zcert:eq(rhs)
  return self:public_key() == rhs:public_key()
    and self:secret_key() == rhs:secret_key()
end

zcert.__eq = zcert.eq

function zcert:hash()
  return self:public_key(true) .. "\0" .. self:secret_key(true)
end

end

local zcert_load do -- load / save

local function read_all(fname)
  local f, err = io.open(fname, "r+b")
  if not f then return nil, err end
  local data = f:read("*all")
  f:close()
  return data
end

local function ltrim(s) return (string.gsub (s, "^%s+","")) end

local function rtrim(s) return (string.gsub (s, "%s+$","")) end

local function trim(s)  return rtrim(ltrim (s)) end

local function start_with(str, pat)
  return (#str >= #pat) and (str:sub(1,#pat) == pat)
end

local function split(str, sep, plain)
  local b, res = 1, {}
  while b <= #str do
    local e, e2 = string.find(str, sep, b, plain)
    if e then
      table.insert(res, (string.sub(str, b, e-1)))
      b = e2 + 1
    else
      table.insert(res, (string.sub(str, b)))
      break
    end
  end
  return res
end

local function read_lines(fname)
  local data, err = read_all(fname)
  if not data then return nil, err end
  return split(data, "\r\n?")
end

local function is_blank(line)
  return start_with(line, '#') or (trim(line) == '')
end

local function unquote(P)
  if P:sub(1,1) == '"' and P:sub(-1,-1) == '"' then
    return (P:sub(2,-2))
  end
  return P
end

local function quote(P)
  return '"' .. P .. '"'
end

local function read_cert(fname)
  local data, err = read_lines(fname)
  if not data then return nil, err end
  local cert = {}
  local section = cert
  for i, line in ipairs(data) do if not is_blank(line) then
    local e, e2 = string.find(line, '=', nil, true)
    if not e then
      section = {}
      cert[ trim(line) ] = section
    else
      local key = string.sub(line, 1, e-1)
      local val = string.sub(line, e2+1)
      section[trim(key)] = unquote(trim(val))
    end
  end end
  return cert
end

local function writeln(f, ...)
  f:write(...)
  f:write("\r\n")
end

local function write_kv(f, k, v)
  writeln(f, "    ", k, " = ", quote(v))
end

local function write_comment(f, ...)
  writeln(f, "# ", ...)
end

function zcert_load(...)
  local filename = string.format(...)

  -- Try first to load secret certificate, which has both keys
  -- Then fallback to loading public certificate
  local filename_secret = filename .. "_secret"

  local root, err = read_cert(filename_secret)
  if not root then root, err = read_cert(filename) end
  if not root then return nil, err end
  root.curve = root.curve or {}
  local public_text = root.curve["public-key"]
  local secret_text = root.curve["secret-key"]

  if not secret_text then secret_text = ("0"):rep(40) end

  local public_key, secret_key

  if public_text and (#public_text == 40) then
    public_key = zmq.z85_decode(public_text)
  end

  if secret_text and (#secret_text == 40) then
    secret_key = zmq.z85_decode(secret_text)
  end

  if public_text and not public_key then
    return nil, "invalid public key"
  end

  if secret_text and not secret_key then
    return nil, "invalid secret key"
  end

  local metadata = root.metadata or {}

  return zcert:new_empty():init(
    public_key, secret_key, metadata
  )
end

function zcert_save_public(self, f)
  write_comment (f, "**** Generated on ", tostring(os.date()), " by LZMQ ****")
  write_comment (f, "ZeroMQ CURVE Public Certificate")
  write_comment (f, "Exchange securely, or use a secure mechanism to verify the contents")
  write_comment (f, "of this file after exchange. Store public certificates in your home")
  write_comment (f, "directory, in the .curve subdirectory.")
  writeln(f, " ")
  writeln(f, "metadata")
  for k, v in pairs(self.private_.metadata) do write_kv(f, k, v) end
  writeln(f, "curve")
  write_kv(f, "public-key", self:public_key(true))

  return true
end

function zcert_save_secret(self, f)
  write_comment (f, "**** Generated on ", tostring(os.date()), " by LZMQ ****")
  write_comment (f, "ZeroMQ CURVE **Secret** Certificate");
  write_comment (f, "DO NOT PROVIDE THIS FILE TO OTHER USERS nor change its permissions.");
  writeln(f, " ")
  writeln(f, "metadata")
  for k, v in pairs(self.private_.metadata) do write_kv(f, k, v) end
  writeln(f, "curve")
  write_kv(f, "public-key", self:public_key(true))
  write_kv(f, "secret-key", self:secret_key(true))

  return true
end

function zcert:save(...)
  local filename = string.format(...)

  --Save public certificate using specified filename
  local f, err = io.open(filename, "w+b")
  if not f then return nil, f end
  zcert_save_public(self, f, filename)
  f:close()

  --- @todo change file mode to secret file
  filename = filename .. "_secret"
  f, err = io.open(filename, "w+b")
  if not f then return nil, f end
  zcert_save_secret(self, f)
  f:close()

  return true
end

function zcert:save_public(...)
  local filename = string.format(...)
  --Save public certificate using specified filename
  local f, err = io.open(filename, "w+b")
  if not f then return nil, f end
  zcert_save_public(self, f, filename)
  f:close()
  return true
end

end

local function selftest(verbose)
  local path = require "path"

  io.write (" * zcert: ")
  local TESTDIR = ".test_zcert"
  path.mkdir(TESTDIR)

  -- Create a simple certificate with metadata
  local cert = zcert:new()
  cert:set_meta ("email", "ph@imatix.com");
  cert:set_meta ("name", "Pieter Hintjens");
  cert:set_meta ("organization", "iMatix Corporation");
  cert:set_meta ("version", "%d", 1);

  assert(cert:meta("email") == "ph@imatix.com")

  local keys = cert:meta_keys()
  assert(#keys == 4)

  -- Check the dup and eq methods
  local shadow = assert(cert:dup())
  assert(cert:eq(shadow))
  assert(cert == shadow)

  -- Check we can save and load certificate
  local p = path.join(TESTDIR, "mycert.txt")
  assert(cert:save(p))

  assert(path.isfile(p))
  assert(path.isfile(p .. "_secret"))

  -- Load certificate, will in fact load secret one
  shadow = assert(zcert_load(p))
  assert(cert:eq(shadow))

  -- Delete secret certificate, load public one
  assert(path.remove(p .. "_secret"))
  shadow = assert(zcert_load(p))

  -- 32-byte null key encodes as 40 '0' characters
  assert(shadow:secret_key(true) == "0000000000000000000000000000000000000000")

  
  path.each(path.join(TESTDIR, "*.*"), path.remove)
  -- path.each with lfs <1.6 close dir iterator only on gc.
  collectgarbage("collect") collectgarbage("collect")
  path.rmdir(TESTDIR)

  io.write("OK\n")
end

return {
  new  = function(...) return zcert:new(...) end;
  load = zcert_load;
}
