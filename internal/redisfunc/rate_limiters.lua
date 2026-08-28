#!lua name=__RATELIMITER_LIBRARY_NAME__

local EVENT_SCHEMA = "dashxd.ratelimiter.event.v1"
local MAX_CONTEXT_BYTES = 16384
local MAX_TARGETS_PER_STAGE = 8
local MAX_CHANNEL_BYTES = 256
local MAX_METADATA_ENTRIES = 32
local MAX_METADATA_KEY_BYTES = 64
local MAX_METADATA_VALUE_BYTES = 512

local function require_positive_integer(value, name)
    local number = tonumber(value)
    if not number or number <= 0 or number ~= math.floor(number) then
        error(name .. " must be a positive integer")
    end
    return number
end

local function now()
    local parts = redis.call("TIME")
    local seconds = tonumber(parts[1])
    local microseconds = tonumber(parts[2])
    local seconds_fractional = seconds + (microseconds / 1000000)
    local milliseconds = (seconds * 1000) + math.floor(microseconds / 1000)
    return seconds, microseconds, seconds_fractional, milliseconds
end

local function validate_metadata(data)
    if data == nil then
        return
    end
    if type(data) ~= "table" then
        error("callback data must be an object")
    end

    local count = 0
    for key, value in pairs(data) do
        count = count + 1
        if count > MAX_METADATA_ENTRIES then
            error("callback data has too many entries")
        end
        if type(key) ~= "string" or #key == 0 or #key > MAX_METADATA_KEY_BYTES then
            error("callback data has an invalid key")
        end
        if type(value) ~= "string" or #value > MAX_METADATA_VALUE_BYTES then
            error("callback data values must be bounded strings")
        end
    end
end

local function validate_targets(targets)
    if targets == nil then
        return
    end
    if type(targets) ~= "table" then
        error("targets must be an object")
    end

    for _, stage in ipairs({"preflight", "allowed", "blocked"}) do
        local stage_targets = targets[stage]
        if stage_targets ~= nil then
            if type(stage_targets) ~= "table" or #stage_targets > MAX_TARGETS_PER_STAGE then
                error("invalid targets for stage " .. stage)
            end
            for _, target in ipairs(stage_targets) do
                if type(target) ~= "table" then
                    error("target must be an object")
                end
                if type(target.channel) ~= "string" or #target.channel == 0 or #target.channel > MAX_CHANNEL_BYTES then
                    error("target has invalid channel")
                end
                if type(target.purpose) ~= "string" or #target.purpose == 0 or #target.purpose > 64 then
                    error("target has invalid purpose")
                end
                validate_metadata(target.data)
            end
        end
    end
end

local function decode_context(raw)
    if type(raw) ~= "string" or #raw == 0 or #raw > MAX_CONTEXT_BYTES then
        error("invalid event context")
    end

    local ok, context = pcall(cjson.decode, raw)
    if not ok or type(context) ~= "table" then
        error("event context must be valid JSON")
    end
    if type(context.bucket) ~= "string" or #context.bucket == 0 then
        error("event context bucket is required")
    end
    if context.request ~= nil and type(context.request) ~= "table" then
        error("event context request must be an object")
    end
    validate_targets(context.targets)
    return context
end

local function publish_stage(context, stage, now_ms, rate_limit)
    local targets = context.targets and context.targets[stage]
    if not targets or #targets == 0 then
        return 0
    end

    local namespace = context.request and context.request.namespace or {}
    local failures = 0
    for _, target in ipairs(targets) do
        local event = {
            schema = EVENT_SCHEMA,
            type = "rate_limit." .. stage,
            stage = stage,
            sent_time_unix_ms = now_ms,
            request = context.request or {},
            rate_limit = rate_limit,
            callback = {
                purpose = target.purpose,
                data = target.data or {}
            }
        }

        local message = {
            type = "Event",
            sentTimeUtc = now_ms,
            message = event,
            parentNamespace = namespace.parent or "",
            childNamespace = namespace.child or "",
            channel = target.channel
        }

        local reply = redis.pcall("PUBLISH", target.channel, cjson.encode(message))
        if type(reply) == "table" and reply.err then
            failures = failures + 1
        end
    end
    return failures
end

local function decision_payload(context, max_requests, window_ms, decision, count, remaining, retry_after_ms, blocked_count)
    return {
        bucket = context.bucket,
        max_requests = max_requests,
        window_ms = window_ms,
        decision = decision,
        count = count,
        remaining = remaining,
        retry_after_ms = retry_after_ms,
        blocked_count = blocked_count
    }
end

local function preflight_payload(context, max_requests, window_ms)
    return {
        bucket = context.bucket,
        max_requests = max_requests,
        window_ms = window_ms,
        decision = "pending"
    }
end

local function execute(keys, args, mode)
    local publishes = mode ~= "minimal"
    local tracks_blocked = mode == "decisions" or mode == "lifecycle"
    local expected_keys = tracks_blocked and 2 or 1
    if #keys < expected_keys then
        error("rate limiter received too few keys")
    end

    local max_requests = require_positive_integer(args[1], "max_requests")
    local window_ms = require_positive_integer(args[2], "window_ms")
    local window_seconds = window_ms / 1000
    local context = nil

    if publishes then
        context = decode_context(args[3])
    end

    local key = keys[1]
    local blocked_key = tracks_blocked and keys[2] or nil
    local seconds, microseconds, current_time, current_time_ms = now()
    local publish_failures = 0

    if mode == "preflight" or mode == "lifecycle" then
        publish_failures = publish_failures + publish_stage(
            context,
            "preflight",
            current_time_ms,
            preflight_payload(context, max_requests, window_ms)
        )
    end

    local window_start = current_time - window_seconds
    redis.call("ZREMRANGEBYSCORE", key, "-inf", window_start)
    local count = redis.call("ZCARD", key)

    if count >= max_requests then
        local blocked_count = 0
        if blocked_key then
            blocked_count = redis.call("INCR", blocked_key)
            redis.call("PEXPIRE", blocked_key, window_ms)
        end

        local retry_after_ms = 0
        local oldest = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
        if oldest[2] then
            retry_after_ms = math.max(0, math.ceil((tonumber(oldest[2]) + window_seconds - current_time) * 1000))
        end

        if mode == "decisions" or mode == "lifecycle" then
            publish_failures = publish_failures + publish_stage(
                context,
                "blocked",
                current_time_ms,
                decision_payload(context, max_requests, window_ms, "blocked", count, 0, retry_after_ms, blocked_count)
            )
        end

        return {1, count, 0, retry_after_ms, current_time_ms, blocked_count, publish_failures}
    end

    local member = tostring(seconds) .. ":" .. tostring(microseconds) .. ":" .. tostring(count + 1)
    redis.call("ZADD", key, current_time, member)
    redis.call("PEXPIRE", key, window_ms)

    count = count + 1
    local remaining = max_requests - count
    local blocked_count = 0
    if blocked_key then
        redis.call("DEL", blocked_key)
    end

    if mode == "decisions" or mode == "lifecycle" then
        publish_failures = publish_failures + publish_stage(
            context,
            "allowed",
            current_time_ms,
            decision_payload(context, max_requests, window_ms, "allowed", count, remaining, 0, blocked_count)
        )
    end

    return {0, count, remaining, 0, current_time_ms, blocked_count, publish_failures}
end

local function rate_limit_minimal(keys, args)
    return execute(keys, args, "minimal")
end

local function rate_limit_preflight(keys, args)
    return execute(keys, args, "preflight")
end

local function rate_limit_decisions(keys, args)
    return execute(keys, args, "decisions")
end

local function rate_limit_lifecycle(keys, args)
    return execute(keys, args, "lifecycle")
end

-- __RATELIMITER_REGISTRATION__
