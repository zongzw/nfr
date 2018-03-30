

script=`cat redis.lua | grep -v '\-\-' | tr '\n' ' '`
echo $script
echo eval \"$script\" $(($# / 2)) $@ | nc 127.0.0.1 9379

# ./lua_redis_test.sh SYN 20 SYN 55 23 SYN 234 SYN 2343 232 453 542 353 3232 4345 FIN FIN RST RST A A B B B C C D C B A D D C B A C B D