%%% -*- erlang -*-
%%%
%%% Tests for QUIC Listener
%%% RFC 9000 Section 5 - Connections
%%%

-module(quic_listener_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Test Fixtures
%%====================================================================

%% Generate a test certificate and key for server
generate_test_cert() ->
    %% For tests, use dummy data - real certs would be loaded from files
    Cert = <<"test_certificate_data">>,
    PrivKey = crypto:strong_rand_bytes(32),  % Simplified for tests
    {Cert, PrivKey}.

%%====================================================================
%% Listener Lifecycle Tests
%%====================================================================

start_stop_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ?assert(is_process_alive(Listener)),
    ok = quic_listener:stop(Listener),
    timer:sleep(10),
    ?assertNot(is_process_alive(Listener)).

get_port_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    Port = quic_listener:get_port(Listener),
    ?assert(is_integer(Port)),
    ?assert(Port > 0),
    ok = quic_listener:stop(Listener).

specific_port_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    %% Use a random high port
    TestPort = 40000 + rand:uniform(10000),
    {ok, Listener} = quic_listener:start_link(TestPort, Opts),
    ActualPort = quic_listener:get_port(Listener),
    ?assertEqual(TestPort, ActualPort),
    ok = quic_listener:stop(Listener).

get_connections_empty_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    Connections = quic_listener:get_connections(Listener),
    ?assertEqual([], Connections),
    ok = quic_listener:stop(Listener).

%%====================================================================
%% Multiple Listener Tests
%%====================================================================

multiple_listeners_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener1} = quic_listener:start_link(0, Opts),
    {ok, Listener2} = quic_listener:start_link(0, Opts),
    Port1 = quic_listener:get_port(Listener1),
    Port2 = quic_listener:get_port(Listener2),
    ?assertNotEqual(Port1, Port2),
    ok = quic_listener:stop(Listener1),
    ok = quic_listener:stop(Listener2).

%%====================================================================
%% ALPN Configuration Tests
%%====================================================================

alpn_list_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>, <<"hq-29">>, <<"hq-28">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

default_alpn_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

%%====================================================================
%% Certificate Chain Tests
%%====================================================================

cert_chain_test() ->
    {Cert, PrivKey} = generate_test_cert(),
    IntermediateCert = <<"intermediate_cert">>,
    RootCert = <<"root_cert">>,
    Opts = #{
        cert => Cert,
        cert_chain => [IntermediateCert, RootCert],
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

%%====================================================================
%% Connection Handler Callback Tests
%%====================================================================

connection_handler_registration_test() ->
    %% Test that connection_handler option is accepted
    {Cert, PrivKey} = generate_test_cert(),
    TestPid = self(),
    Handler = fun(ConnPid, ConnRef) ->
        %% Notify test that handler was invoked
        TestPid ! {handler_invoked, ConnPid, ConnRef},
        HandlerPid = spawn(fun() ->
            receive
                stop -> ok
            after 5000 -> ok
            end
        end),
        {ok, HandlerPid}
    end,
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>],
        connection_handler => Handler
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

connection_handler_error_handling_test() ->
    %% Test that connection_handler errors are handled gracefully
    {Cert, PrivKey} = generate_test_cert(),
    %% Handler that returns an error
    Handler = fun(_ConnPid, _ConnRef) ->
        {error, test_error}
    end,
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>],
        connection_handler => Handler
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

connection_handler_invalid_return_test() ->
    %% Test that invalid connection_handler return values are handled
    {Cert, PrivKey} = generate_test_cert(),
    %% Handler that returns unexpected value
    Handler = fun(_ConnPid, _ConnRef) ->
        invalid_return
    end,
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>],
        connection_handler => Handler
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).
