-- Multi-Class Bayesian Cache Learning Script

local cache_id = KEYS[1]
local category = KEYS[2]  -- Multi-class category (finance, personal, etc.)
local conf = cmsgpack.unpack(KEYS[3])
cache_id = string.sub(cache_id, 1, conf.cache_elt_len)

-- Try each prefix in Redis
for i = 0, conf.cache_max_keys do
  local prefix = conf.cache_prefix .. string.rep("X", i)
  local have = redis.call('HGET', prefix, cache_id)

  if have then
    -- Already in cache, update category
    redis.call('HSET', prefix, cache_id, category)
    return false
  end
end

local added = false
local lim = conf.cache_max_elt
for i = 0, conf.cache_max_keys do
  if not added then
    local prefix = conf.cache_prefix .. string.rep("X", i)
    local count = redis.call('HLEN', prefix)

    if count < lim then
      -- Add to this prefix
      redis.call('HSET', prefix, cache_id, category)
      added = true
    end
  end
end

if not added then
  -- Expire old keys
  local expired = false
  for i = 0, conf.cache_max_keys do
    local prefix = conf.cache_prefix .. string.rep("X", i)
    local exists = redis.call('EXISTS', prefix)

    if exists then
      if not expired then
        redis.call('DEL', prefix)
        redis.call('HSET', prefix, cache_id, category)
        expired = true
      elseif i > 0 then
        local new_prefix = conf.cache_prefix .. string.rep("X", i - 1)
        redis.call('RENAME', prefix, new_prefix)
      end
    end
  end
end

return true
