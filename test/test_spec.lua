local fqclient = require("../lua/fqclient.lua")

local function mkreader(exchange, program)
  local key_auth = mtev.uuid()
  local key_bind = mtev.uuid()
  local key_read = mtev.uuid()
  local fqc_read = fqclient.new("127.0.0.1", 8765, "busted-user-1", "busted-pw")
  fqc_read.auth_cb = function()
    mtev.notify(key_auth)
  end
  fqc_read.bind_cb = function()
    mtev.notify(key_bind)
  end
  fqc_read:bind(exchange, program) -- need to bind before connect
  fqc_read:connect()
  -- We have to call fq_read:recv() in a loop in order for call backs to execute.
  mtev.coroutine_spawn(function()
      while true do
        local m = { fqc_read:recv() }
        if #m > 0 then
          mtev.log("error", "RECV: %s\n", mtev.tojson(m):tostring())
          mtev.notify(key_read, m[2]) -- just forward payload
        else
          mtev.sleep(.005)
        end
      end
  end)
  assert.truthy(mtev.waitfor(key_auth, 5))
  assert.truthy(mtev.waitfor(key_bind, 5))
  local reader = function(timeout)
    local _, m = mtev.waitfor(key_read, timeout or 5)
    return m
  end
  return reader
end

describe("fq", function()

  local fq, api

  setup(function()
      -- Setup fq process wrapper
      fq = mtev.Proc:new {
        path = "../fqd",
        argv = {
          "fqd", "-D",
          '-n', '192.168.33.10',
          '-c', './fqd.sqlite',
          '-p', '8765',
        },
        boot_match = "Listening on port",
      }
      -- write stderr output to out.log
      fq:logwrite("out.log")
      -- Optional: Forward fqd output to error log
      -- fq:loglog("error")
      api =  mtev.Api:http("127.0.0.1", '8765')
  end)

  teardown(function()
      fq:kill()
  end)

  it("should start", function()
       fq:start()
       assert.truthy(fq:ready())
  end)

  it("should allow HTTP requests", function()
       assert.truthy(api:get("/stats.json"):check())
  end)

  local fqc_send
  local exchange = "test-exchange"
  local program = "prefix:"
  local route = "test-route"
  local reader
  it("should accept connections", function()
       fqc_send = fqclient.new("127.0.0.1", 8765, "busted-user-2", "busted-pw")
       fqc_send:connect()
       reader = mkreader(exchange, "prefix:")
  end)

  it("should send/recv hello messages", function()
       local msg = "Hello!"
       local N = 10
       for i=1,N do
         fqc_send:send(msg, exchange, route)
       end
       for i=1,N do
         assert.equal(msg, reader())
       end
  end)

  it("should send messages via HTTP", function()
       -- Submit message via HTTP
       -- $ curl -X POST -H "X-Fq-User: web" -H 'X-Fq-Route: user-route' \
       --   -H 'X-Fq-Exchange: busted-exchange' 192.168.33.10:8765/submit \
       --   --data 'Hello world!'
       -- {"routed":1,"dropped":0,"no_route":0,"no_exchange":0}
       local payload = "Some HTTP payload"
       r = api:post("/submit", payload, {
                      ["X-Fq-User"] = "web",
                      ["X-Fq-Route"] = "web-route",
                      ["X-Fq-Exchange"] = exchange,
       }):check()
       print(r:text())
       assert.equals(r:json().routed, 1)
       assert.equals(payload, reader())
  end)

  it("should send messages via fqs", function()
       -- quick and dirty way to spin up fqs
       mtev.sh(string.format(
         [[printf 'hello fqs' | LD_LIBRARY_PATH=../:/opt/circonus/lib ../fqs -x "%s" -r "%s"]],
         exchange, route))
       assert.equals('hello fqs', reader())
  end)

  it("should allow multiple readers", function()
       local reader2 = mkreader(exchange, "prefix:")
       local msg = "hello reader 2!"
       fqc_send:send(msg, exchange, route)
       assert.equals(msg, reader())
       assert.equals(msg, reader2())
  end)

  it("should filter prefixes", function()
       local reader_x = mkreader(exchange, "prefix:x")
       fqc_send:send("abc", exchange, "abc")
       fqc_send:send("xxx", exchange, "xxx")
       assert.equals("abc", reader())
       assert.equals("xxx", reader())
       assert.equals("xxx", reader_x())
  end)

end)
