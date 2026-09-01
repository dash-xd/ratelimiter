#!lua name=__RATELIMITER_LIBRARY_NAME__

local EVENT_SCHEMA = "dashxd.ratelimiter.event.v1"
local LIFECYCLE_SIGNAL_SCHEMA = "dashxd.ratelimiter.lifecycle.v1"
local TIMER_MEMBER = "shutdown:timer"
local MAX_TIMER_BATCH = 16
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

local function require_nonnegative_integer(value, name)
    local number = tonumber(value)
    if not number or number < 0 or number ~= math.floor(number) then
        error(name .. " must be a non-negative integer")
    end
    return number
end

local function require_boolean_integer(value, name)
    local number = tonumber(value)
    if number ~= 0 and number ~= 1 then
        error(name .. " must be 0 or 1")
    end
    return number == 1
end

local function key_type(key)
    local reply = redis.call("TYPE", key)
    if type(reply) == "table" then
        return reply.ok
    end
    return reply
end

local function require_key_type(key, expected)
    local actual = key_type(key)
    if actual ~= "none" and actual ~= expected then
        error("key " .. key .. " must be " .. expected .. ", got " .. tostring(actual))
    end
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

    for _, stage in ipairs({"preflight", "allowed", "blocked", "shutdown"}) do
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

local function publish_shutdown(context, now_ms, deadline_ms)
    local targets = context.targets and context.targets.shutdown
    if not targets or #targets == 0 then
        return false, 0
    end

    local namespace = context.request and context.request.namespace or {}
    local all_delivered = true
    local failures = 0

    for _, target in ipairs(targets) do
        local signal = {
            schema = LIFECYCLE_SIGNAL_SCHEMA,
            type = "lifecycle.shutdown",
            signal = "shutdown",
            condition = "timer",
            sent_time_unix_ms = now_ms,
            deadline_unix_ms = deadline_ms,
            bucket = context.bucket,
            request = context.request or {},
            callback = {
                purpose = target.purpose,
                data = target.data or {}
            }
        }

        local message = {
            type = "Signal",
            sentTimeUtc = now_ms,
            message = signal,
            parentNamespace = namespace.parent or "",
            childNamespace = namespace.child or "",
            channel = target.channel
        }

        local reply = redis.pcall("PUBLISH", target.channel, cjson.encode(message))
        if type(reply) == "table" and reply.err then
            all_delivered = false
            failures = failures + 1
        elseif tonumber(reply) == nil or tonumber(reply) < 1 then
            all_delivered = false
        end
    end

    return all_delivered, failures
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

local function timer_keys(keys, mode)
    if mode == "preflight" then
        return keys[2], keys[3]
    end
    if mode == "lifecycle" then
        return keys[3], keys[4]
    end
    return nil, nil
end

local function arm_timer(context, raw_context, timer_key, payload_key, after_ms, reset, now_ms)
    if after_ms == 0 then
        return
    end

    local targets = context.targets and context.targets.shutdown
    if not targets or #targets == 0 then
        error("preflight shutdown timer requires at least one shutdown target")
    end

    require_key_type(timer_key, "zset")
    require_key_type(payload_key, "hash")

    local deadline_ms = now_ms + after_ms
    if reset then
        redis.call("ZADD", timer_key, deadline_ms, TIMER_MEMBER)
        redis.call("HSET", payload_key, TIMER_MEMBER, raw_context)
        return
    end

    local added = redis.call("ZADD", timer_key, "NX", deadline_ms, TIMER_MEMBER)
    if added == 1 or redis.call("HEXISTS", payload_key, TIMER_MEMBER) == 0 then
        redis.call("HSET", payload_key, TIMER_MEMBER, raw_context)
    end
end

local function timer_arm_absolute(keys, args)
    if #keys ~= 2 then
        error("absolute timer arm requires timer and payload keys")
    end

    local timer_key = keys[1]
    local payload_key = keys[2]
    local raw_context = args[1]
    local deadline_ms = require_positive_integer(args[2], "deadline_unix_ms")
    local reset = require_boolean_integer(args[3], "timer_reset")
    local context = decode_context(raw_context)
    local targets = context.targets and context.targets.shutdown
    if not targets or #targets == 0 then
        error("absolute shutdown timer requires at least one shutdown target")
    end

    require_key_type(timer_key, "zset")
    require_key_type(payload_key, "hash")

    if reset then
        redis.call("ZADD", timer_key, deadline_ms, TIMER_MEMBER)
        redis.call("HSET", payload_key, TIMER_MEMBER, raw_context)
        return {1}
    end

    local added = redis.call("ZADD", timer_key, "NX", deadline_ms, TIMER_MEMBER)
    if added == 1 then
        redis.call("HSET", payload_key, TIMER_MEMBER, raw_context)
        return {1}
    end

    if redis.call("HEXISTS", payload_key, TIMER_MEMBER) == 0 then
        redis.call("HSET", payload_key, TIMER_MEMBER, raw_context)
    end
    return {0}
end

local function execute(keys, args, mode)
    local publishes = mode ~= "minimal"
    local tracks_blocked = mode == "decisions" or mode == "lifecycle"
    local supports_preflight = mode == "preflight" or mode == "lifecycle"

    local expected_keys = 1
    if tracks_blocked then
        expected_keys = expected_keys + 1
    end
    if supports_preflight then
        expected_keys = expected_keys + 2
    end
    if #keys < expected_keys then
        error("rate limiter received too few keys")
    end

    local max_requests = require_positive_integer(args[1], "max_requests")
    local window_ms = require_positive_integer(args[2], "window_ms")
    local window_seconds = window_ms / 1000
    local context = nil
    local raw_context = nil
    local timer_after_ms = 0
    local timer_reset = false

    if publishes then
        raw_context = args[3]
        context = decode_context(raw_context)
    end
    if supports_preflight then
        timer_after_ms = require_nonnegative_integer(args[4], "timer_after_ms")
        timer_reset = require_boolean_integer(args[5], "timer_reset")
    end

    local key = keys[1]
    local blocked_key = tracks_blocked and keys[2] or nil
    local timer_key, payload_key = timer_keys(keys, mode)

    require_key_type(key, "zset")
    if blocked_key then
        require_key_type(blocked_key, "string")
    end
    if supports_preflight then
        require_key_type(timer_key, "zset")
        require_key_type(payload_key, "hash")
    end

    local seconds, microseconds, current_time, current_time_ms = now()
    local publish_failures = 0

    if supports_preflight then
        arm_timer(
            context,
            raw_context,
            timer_key,
            payload_key,
            timer_after_ms,
            timer_reset,
            current_time_ms
        )
    end

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

local function timer_tick(keys, args)
    if #keys ~= 2 then
        error("timer tick requires timer and payload keys")
    end

    local timer_key = keys[1]
    local payload_key = keys[2]
    require_key_type(timer_key, "zset")
    require_key_type(payload_key, "hash")

    local _, _, _, current_time_ms = now()
    local due = redis.call(
        "ZRANGEBYSCORE",
        timer_key,
        "-inf",
        current_time_ms,
        "WITHSCORES",
        "LIMIT",
        0,
        MAX_TIMER_BATCH
    )

    local dispatched = 0
    local pending = 0
    local publish_failures = 0

    for i = 1, #due, 2 do
        local member = due[i]
        local deadline_ms = tonumber(due[i + 1])
        local raw_context = redis.call("HGET", payload_key, member)

        if not raw_context then
            pending = pending + 1
            publish_failures = publish_failures + 1
        else
            local ok, context = pcall(decode_context, raw_context)
            if not ok then
                pending = pending + 1
                publish_failures = publish_failures + 1
            else
                local delivered, failures = publish_shutdown(
                    context,
                    current_time_ms,
                    deadline_ms
                )
                publish_failures = publish_failures + failures

                if delivered then
                    redis.call("ZREM", timer_key, member)
                    redis.call("HDEL", payload_key, member)
                    dispatched = dispatched + 1
                else
                    pending = pending + 1
                end
            end
        end
    end

    return {dispatched, pending, publish_failures, current_time_ms}
end

local function timer_cancel(keys, args)
    if #keys ~= 2 then
        error("timer cancel requires timer and payload keys")
    end

    local timer_key = keys[1]
    local payload_key = keys[2]
    require_key_type(timer_key, "zset")
    require_key_type(payload_key, "hash")

    local removed = redis.call("ZREM", timer_key, TIMER_MEMBER)
    redis.call("HDEL", payload_key, TIMER_MEMBER)
    return {removed}
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
