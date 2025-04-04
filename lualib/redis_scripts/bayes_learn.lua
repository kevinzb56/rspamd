-- Multi-Class Bayesian Learning Script
-- This script supports categories: finance, personal, important, spam, promotional, social

local prefix = KEYS[1]
local category = KEYS[2]  -- Multi-class category (finance, personal, etc.)
local symbol = KEYS[3]
local is_unlearn = KEYS[4] == 'true' and true or false
local input_tokens = cmsgpack.unpack(KEYS[5])
local text_tokens

if KEYS[6] then
  text_tokens = cmsgpack.unpack(KEYS[6])
end

local learned_key = 'learns_' .. category  -- Store learning count per category

redis.call('SADD', symbol .. '_keys', prefix)
redis.call('HSET', prefix, 'version', '2') -- new schema
redis.call('HINCRBY', prefix, learned_key, is_unlearn and -1 or 1) -- Increase/decrease count

for i, token in ipairs(input_tokens) do
  redis.call('HINCRBY', token, category, is_unlearn and -1 or 1)  -- Update category count
  
  if text_tokens then
    local tok1 = text_tokens[i * 2 - 1]
    local tok2 = text_tokens[i * 2]

    if tok1 then
      if tok2 then
        redis.call('HSET', token, 'tokens', string.format('%s:%s', tok1, tok2))
      else
        redis.call('HSET', token, 'tokens', tok1)
      end

      redis.call('ZINCRBY', prefix .. '_z', is_unlearn and -1 or 1, token)
    end
  end
end
