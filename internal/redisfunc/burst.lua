#!lua name=__RATELIMITER_BURST_LIBRARY__

local function require_positive_integer(value, name)
    local number = tonumber(value)
    if not number or number <= 0 or number ~= math.floor(number) then
        error(name .. " must be a positive integer")
    end
    return number
end

local function now_ms()
    local parts = redis.call("TIME")
    return (tonumber(parts[1]) * 1000) + math.floor(tonumber(parts[2]) / 1000)
end

-- Integer fixed-point token bucket. One token is 1000 units, so a rate of R
-- tokens/second refills exactly R units per millisecond without floating point
-- state. Policy bounds keep all arithmetic safely below Lua's exact integer
-- range.
local function rate_limit_burst(keys, args)
    if #keys ~= 1 then
        error("burst limiter requires exactly one state key")
    end

    local key = keys[1]
    local rate = require_positive_integer(args[1], "requests_per_second")
    local capacity = require_positive_integer(args[2], "capacity")
    local capacity_units = capacity * 1000
    local current_ms = now_ms()

    local state = redis.call("HMGET", key, "tokens", "updated_ms")
    local tokens = tonumber(state[1])
    local updated_ms = tonumber(state[2])

    if not tokens or not updated_ms then
        tokens = capacity_units
        updated_ms = current_ms
    else
        if current_ms < updated_ms then
            current_ms = updated_ms
        end
        local elapsed_ms = current_ms - updated_ms
        if elapsed_ms > 0 then
            tokens = math.min(capacity_units, tokens + (elapsed_ms * rate))
        end
    end

    local allowed = 0
    local retry_after_ms = 0
    if tokens >= 1000 then
        tokens = tokens - 1000
    else
        allowed = 1
        retry_after_ms = math.ceil((1000 - tokens) / rate)
    end

    redis.call("HSET", key, "tokens", tokens, "updated_ms", current_ms)

    -- Expire idle state after at least two full refill periods. A recreated key
    -- correctly starts full, so eviction of inactive buckets is semantically safe.
    local refill_ms = math.ceil(capacity_units / rate)
    local ttl_ms = math.max(60000, refill_ms * 2)
    redis.call("PEXPIRE", key, ttl_ms)

    return {allowed, math.floor(tokens / 1000), retry_after_ms, current_ms}
end

redis.register_function('__RATELIMITER_BURST_FUNCTION__', rate_limit_burst)
