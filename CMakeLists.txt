cmake_minimum_required(VERSION 3.2)
project(Pkt2Redis2Pcap)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    source/test_simple/test_time.c
    source/n2r.c
    source/r2p.c
    source/test_compile.c
    source/test_curses.c
    source/test_getopt.c
    source/test_pfring_api.c
    source/test_pfring_cluster.c
    source/test_pipe_to_tcpflow.c
    source/test_redis_perf.c
    source/test_set_cpu_affinity.c
    source/test_string_handling.c
    source/test_write2influxdb.c
    source/v1_n2r.c
    source/v1_r2p.c
    source/v2_n2r.c
    source/v2_r2p.c
    source/v3_n2r2p2s.c)

add_executable(Pkt2Redis2Pcap ${SOURCE_FILES})