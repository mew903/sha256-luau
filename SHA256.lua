-- Luau (roblox) optimized adaptation of SHA-256
-- note: sha256 is great for fast hashing without collisions
--       this means: good for indexing, bad for security (read: bruteforcing, rainbow tables)
--       if you're looking for a password hashing algorithm, consider bcrypt
--       you shouldn't be hashing passwords on roblox games anyway
--       mew903, 2024

local bytec = string.byte
local charc = string.char
local clockc = os.clock
local clonec = table.clone
local concatc = table.concat
local floorc = math.floor
local formatc = string.format
local gsubc = string.gsub
local repc = string.rep

local H, K = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}, {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

function LSHIFT(a: number, disp: number): number
  return (disp < 0) and RSHIFT(a, -disp) or (a * 2 ^ disp) % 2 ^ 32
end

function RSHIFT(x: number, disp: number): number
  local x = x % 0x100000000
  return (disp > 31 or disp < -31) and 0
      or (disp < 0) and LSHIFT(x, -disp) or floorc(x % 2 ^ 32 / 2 ^ disp)
end

type narray = {
  [number]: number,
}

type cache = {
  [string]: string,
}

type bitmap = {
  [number]: narray,
  n: number?,
}

local lshift, rshift = LSHIFT, RSHIFT

local function memoize(memo: (any) -> any): bitmap
  local bitmap = { }
  setmetatable(bitmap, {
    __index = function(self, k)
      local v = memo(k)
      rawset(self, k, v)
      return v
    end,
    __metatable = true,
  })
  return bitmap :: any
end

local function uncached(t: bitmap, m: number): (number, number) -> number
  return function(a, b)
    local res, p = 0, 1
    while a ~= 0 and b ~= 0 do
      local am, bm = a % m, b % m
      res, a, b, p = res + t[am][bm] * p, (a - am) / m, (b - bm) / m, p * m
    end
    return res + (a + b) * p
  end
end

local function makebitop(t: bitmap): (number, number) -> number
  local bitop = uncached(t, 2)
  return uncached(memoize(function(a)
    return memoize(function(b)
      return bitop(a, b)
    end)
  end), 2 ^ (t.n or 1))
end

local bxor1 = makebitop({
  [0] = { [0] = 0, 1 },
  [1] = { [0] = 1, 0 },
  n = 4,
})

local function bxor(a: number?, b: number?, c: number?, ...: number): number
  if b and a then
    local a, b = a % 0x100000000, b % 0x100000000
    local z = bxor1(a, b)
    return c and bxor(z, c, ...) or z
  elseif a then
    return a % 0x100000000
  end
  return 0
end

local function band(a: number?, b: number?, c: number?, ...: number): number
  if b and a then
    local a, b = a % 0x100000000, b % 0x100000000
    local z = ((a + b) - bxor1(a, b)) / 2
    return c and band(z, c, ...) or z
  elseif a then
    return a % 0x100000000
  end
  return 0xffffffff
end

local function bnot(x: number): number
  return (-1 - x) % 0x100000000
end

local function rrotate(x: number, disp: number): number
  local x = x % 0x100000000
  local disp = disp % 32
  return rshift(x, disp) + lshift(band(x, 2 ^ disp - 1), 32 - disp)
end

local function char2hex(c: string)
  return formatc('%02x', bytec(c))
end

local function str2hex(input: string): string
  local hex = gsubc(input, '.', char2hex)
  return hex
end

local function num2s(l: number, n: number): string
  local s = ''
  for i = 1, n do
    local rem = l % 256
    s = charc(rem) .. s
    l = (l - rem) / 256
  end
  return s
end

local function s232num(s: string, i: number): number
  local n = 0
  for i = i, i + 3 do
    n = n * 256 + bytec(s, i)
  end
  return n
end

local function preproc(input: string): string
  local len = #input
  return input .. '\128' .. repc('\0', 64 - ((len + 9) % 64)) .. num2s(8 * len, 8)
end

local function digestblock(b: string, round: number, out: narray): ()
  local w = { }
  for j = 1, 16 do
    w[j] = s232num(b, round + (j - 1) * 4)
  end
  for j = 17, 64 do
    local v = w[j - 15]
    local s0 = bxor(rrotate(v, 7), rrotate(v, 18), rshift(v, 3))
    local z = w[j - 2]
    w[j] = w[j - 16] + s0 + w[j - 7] + bxor(rrotate(z, 17), rrotate(z, 19), rshift(z, 10))
  end
  local a, b, c, d, e, f, g, h = out[1], out[2], out[3], out[4], out[5], out[6], out[7], out[8]
  for i = 1, 64 do
    local bx = bxor(band(a, b), band(a, c), band(b, c))
    local t2 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
    local s1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
    local ch = bxor(band(e, f), band(bnot(e), g))
    local t1 = h + s1 + ch + K[i] + w[i]
    h, g, f, e, d, c, b, a = g, f, e, d + t1, c, b, a, t1 + t2 + bx
  end
  out[1] = band(out[1] + a)
  out[2] = band(out[2] + b)
  out[3] = band(out[3] + c)
  out[4] = band(out[4] + d)
  out[5] = band(out[5] + e)
  out[6] = band(out[6] + f)
  out[7] = band(out[7] + g)
  out[8] = band(out[8] + h)
end

local cache: cache = { }

local function sha256(input: string): (string, number)
  local timestamp = clockc()
  local cached = cache[input]
  if cached then
    return cached, clockc() - timestamp
  end
  local out, pre = clonec(H), preproc(input)
  for round = 1, #pre, 64 do
    digestblock(pre, round, out)
  end
  local hash = str2hex(concatc({
    num2s(out[1], 4), num2s(out[2], 4),
    num2s(out[3], 4), num2s(out[4], 4),
    num2s(out[5], 4), num2s(out[6], 4),
    num2s(out[7], 4), num2s(out[8], 4),
  }, ''))
  cache[input] = hash
  return hash, clockc() - timestamp
end

assert(sha256('SHA256') == 'b3abe5d8c69b38733ad57ea75e83bcae42bbbbac75e3a5445862ed2f8a2cd677')
assert(sha256('mew903') == '2e502fa17214e0c5fbae24fbad05bb2a52d78b27f6f90e08b2ba2731d5f09735')

return sha256
