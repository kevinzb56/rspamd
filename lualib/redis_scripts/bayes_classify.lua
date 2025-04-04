-- Lua script to perform multi-class Bayesian classification
-- Supports categories: finance, personal, important, spam, promotional, social
-- Instead of storing just H (ham) and S (spam), it retrieves and stores counts for each category.\

local prefix = KEYS[1]
local input_tokens = cmsgpack.unpack(KEYS[2])

-- Define categories
local categories = {"finance", "personal", "important", "spam", "promotional", "social"}
local output_classes = {}  -- Stores token counts per category
local learned_counts = {}  -- Stores total learn counts per category

-- Initialize tables
for _, category in ipairs(categories) do
    output_classes[category] = {}
    learned_counts[category] = tonumber(redis.call('HGET', prefix, 'learns_' .. category)) or 0
end

-- Check if learning data exists
local has_learning_data = false
for _, count in pairs(learned_counts) do
    if count > 0 then
        has_learning_data = true
        break
    end
end

if has_learning_data then
    for i, token in ipairs(input_tokens) do
        local token_data = redis.call('HMGET', token, unpack(categories))  -- Fetch all category counts

        for j, category in ipairs(categories) do
            local count = token_data[j]
            if count then
                table.insert(output_classes[category], {i, tonumber(count)})  -- Store category count
            end
        end
    end
end

return {learned_counts, output_classes}
