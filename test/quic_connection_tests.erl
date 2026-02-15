%%% -*- erlang -*-
%%%
%%% Tests for QUIC Connection State Machine
%%%

-module(quic_connection_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Connection Lifecycle Tests
%%====================================================================

start_connection_test() ->
    %% Start a connection process
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),

    %% Get state should return idle initially
    {State, _Info} = quic_connection:get_state(Pid),
    ?assertEqual(idle, State),

    %% Clean up
    quic_connection:close(Pid, normal),
    timer:sleep(100).

connect_returns_ref_test() ->
    {ok, Ref, Pid} = quic_connection:connect("127.0.0.1", 4433, #{}, self()),
    ?assert(is_reference(Ref)),
    ?assert(is_pid(Pid)),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

state_info_contains_required_fields_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    {_State, Info} = quic_connection:get_state(Pid),

    ?assert(maps:is_key(scid, Info)),
    ?assert(maps:is_key(dcid, Info)),
    ?assert(maps:is_key(role, Info)),
    ?assert(maps:is_key(version, Info)),
    ?assert(maps:is_key(streams, Info)),

    %% Should be client role
    ?assertEqual(client, maps:get(role, Info)),

    %% Should be QUIC v1
    ?assertEqual(?QUIC_VERSION_1, maps:get(version, Info)),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%%====================================================================
%% Connection Options Tests
%%====================================================================

custom_max_data_test() ->
    Opts = #{max_data => 2000000},
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, Opts, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

custom_max_streams_test() ->
    Opts = #{max_streams_bidi => 50, max_streams_uni => 25},
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, Opts, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

custom_idle_timeout_test() ->
    Opts = #{idle_timeout => 60000},
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, Opts, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

alpn_option_test() ->
    Opts = #{alpn => <<"h3">>},
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, Opts, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

%%====================================================================
%% Close Tests
%%====================================================================

close_normal_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    quic_connection:close(Pid, normal),
    timer:sleep(200),

    %% Process should be shutting down or dead
    %% (draining state then closed)
    ok.

%%====================================================================
%% Process and Timeout Tests
%%====================================================================

process_cast_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    %% Should not crash
    ok = quic_connection:process(Pid),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

handle_timeout_cast_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    %% Should not crash
    ok = quic_connection:handle_timeout(Pid),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

%%====================================================================
%% Multiple Connections Test
%%====================================================================

multiple_connections_test() ->
    {ok, Pid1} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    {ok, Pid2} = quic_connection:start_link("127.0.0.1", 4434, #{}, self()),

    ?assertNotEqual(Pid1, Pid2),

    {_, Info1} = quic_connection:get_state(Pid1),
    {_, Info2} = quic_connection:get_state(Pid2),

    %% SCIDs should be different
    ?assertNotEqual(maps:get(scid, Info1), maps:get(scid, Info2)),

    quic_connection:close(Pid1, normal),
    quic_connection:close(Pid2, normal),
    timer:sleep(100).

%%====================================================================
%% IP Address Format Tests
%%====================================================================

ipv4_tuple_address_test() ->
    {ok, Pid} = quic_connection:start_link({127,0,0,1}, 4433, #{}, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

string_hostname_test() ->
    {ok, Pid} = quic_connection:start_link("localhost", 4433, #{}, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

binary_hostname_test() ->
    {ok, Pid} = quic_connection:start_link(<<"localhost">>, 4433, #{}, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).
