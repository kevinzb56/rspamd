-- Lua script to perform multi-class bayes classification
-- This script accepts the following parameters:
-- key1 - prefix for bayes tokens (e.g. for per-user classification)
-- key2 - set of tokens encoded in messagepack array of strings
-- key3 - array of class names encoded in messagepack (e.g. ["social", "educational", "newsletter", "promotion"])

local prefix = KEYS[1]
local input_tokens = cmsgpack.unpack(KEYS[2])
-- local classes = cmsgpack.unpack(KEYS[3])
local classes = {'Business', 'Promotional'}

local output_classes = {}
local learned_counts = {}

-- Get learned counts for each class
for _, class_name in ipairs(classes) do
  local learn_key = 'learns_' .. class_name
  learned_counts[class_name] = tonumber(redis.call('HGET', prefix, learn_key)) or 0
  output_classes[class_name] = {}
end

-- Check if we have enough training data for all classes
local has_sufficient_data = true
for _, count in pairs(learned_counts) do
  if count <= 0 then
    has_sufficient_data = false
    break
  end
end

-- Output is a set of pairs (token_index, token_count) for each class
-- Tokens that are not found are not filled to save space for sparse tokens
if has_sufficient_data then
  for i, token in ipairs(input_tokens) do
    -- Build HMGET arguments dynamically based on classes
    local hmget_args = {}
    for _, class_name in ipairs(classes) do
      table.insert(hmget_args, string.upper(string.sub(class_name, 1, 1))) -- Use first letter uppercase as key
    end

    local token_data = redis.call('HMGET', token, unpack(hmget_args))

    if token_data then
      for j, class_name in ipairs(classes) do
        local class_count = token_data[j]
        if class_count then
          table.insert(output_classes[class_name], { i, tonumber(class_count) })
        end
      end
    end
  end
end

-- Build return array: [learned_count1, learned_count2, ..., output_class1, output_class2, ...]
local result = {}
for _, class_name in ipairs(classes) do
  table.insert(result, learned_counts[class_name])
end
for _, class_name in ipairs(classes) do
  table.insert(result, output_classes[class_name])
end

return result