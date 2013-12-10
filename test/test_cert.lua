local HAS_RUNNER = not not lunit
local lunit      = require "lunit"
local TEST_CASE  = assert(lunit.TEST_CASE)
local skip       = lunit.skip or function() end

local zcert      = require "lzmq.cert"
local path       = require "path"

local _ENV = TEST_CASE "lzmq.cert" do

local TESTDIR = ".test_zcert"
local cert, shadow

function setup()
  path.mkdir(TESTDIR)
  assert(path.isdir(TESTDIR))

  -- Create a simple certificate with metadata
  cert = assert(zcert:new())
  assert_nil(cert:set_meta ("email", "ph@imatix.com"))
  assert_nil(cert:set_meta ("name", "Pieter Hintjens"))
  assert_nil(cert:set_meta ("organization", "iMatix Corporation"))
  assert_nil(cert:set_meta ("version", "%d", 1))

end

function teardown()
  if cert then cert:destroy() end
  if shadow then shadow:destroy() end

  path.each(path.join(TESTDIR, "*.*"), path.remove)
  -- path.each with lfs <1.6 close dir iterator only on gc.
  collectgarbage("collect") collectgarbage("collect")
  path.rmdir(TESTDIR)
end

function test_meta()
  assert_equal("ph@imatix.com", cert:meta("email"))

  local keys = assert_table(cert:meta_keys())
  assert_equal(4, #keys)
end

function test_dup()
  -- Check the dup and eq methods

  shadow = assert(cert:dup())
  assert_true(cert:eq(shadow))
  assert_equal(cert, shadow)

end

function test_save()
  -- Check we can save and load certificate
  local p = path.join(TESTDIR, "mycert.txt")
  assert(cert:save(p))

  assert(path.isfile(p))
  assert(path.isfile(p .. "_secret"))

  -- Load certificate, will in fact load secret one
  shadow = assert(zcert.load(p))
  assert_equal(cert, shadow)

  -- Delete secret certificate, load public one
  assert(path.remove(p .. "_secret"))
  shadow = assert(zcert.load(p))

  -- 32-byte null key encodes as 40 '0' characters
  assert_equal("0000000000000000000000000000000000000000", shadow:secret_key(true))
end

end

if not HAS_RUNNER then lunit.run() end