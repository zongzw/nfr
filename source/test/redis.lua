 \
redis.replicate_commands() \
local t = redis.call('time')[1] \
 \
for i = 1, #KEYS do \
    if(KEYS[i] == 'SYN') then \
        local a = redis.call('hmget', ARGV[i], 'P', 'B') \
        if(a[1] == false) then  \
            local b = redis.call('hget', 'ACK', 'N') \
            redis.call('hset', 'ACK', 'N', b + 1) \
        end \
        redis.call('hmset', ARGV[i], 'P', 0, 'B', 0, 'S', t, 'E', t) \
 \
    elseif(KEYS[i] == 'RST' or KEYS[i] == 'FIN') then  \
        local a = redis.call('hmget', ARGV[i], 'P', 'B', 'S') \
        if(a[1]) then \
            local b \
            local d = t - a[3] \
 \
            b = redis.call('hmget', KEYS[i], 'N', 'P', 'B', 'D') \
            redis.call('hmset', KEYS[i], 'N', b[1] + 1, 'P', b[2] + a[1], 'B', b[3] + a[2], 'D', b[4] + d) \
             \
            b = redis.call('hmget', 'ACK', 'N', 'P', 'B') \
            redis.call('hmset', 'ACK', 'N', b[1] - 1, 'P', b[2] - a[1], 'B', b[3] - a[2]) \
 \
            redis.call('del', ARGV[i]) \
        end \
    else \
        local a = redis.call('hmget', ARGV[i], 'P', 'B') \
        if(a[1]) then  \
            redis.call('hmset', ARGV[i], 'P', a[1] + 1, 'B', KEYS[i] + a[2], 'E', t) \
            local b = redis.call('hmget', 'ACK', 'P', 'B') \
            redis.call('hmset', 'ACK', 'P', b[1] + 1, 'B', b[2] + KEYS[i]) \
        end \
    end \
 \
end \
 \
