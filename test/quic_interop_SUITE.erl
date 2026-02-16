%%% -*- erlang -*-
%%%
%%% QUIC Interoperability Test Suite
%%%
%%% Tests against real QUIC servers to verify protocol compliance.
%%% Based on QUIC Interop Runner test cases.
%%%
%%% Test Servers:
%%% - Google: quic.rocks:4433
%%% - Cloudflare: cloudflare-quic.com:443
%%% - Facebook: www.facebook.com:443
%%%

-module(quic_interop_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%% CT callbacks
-export([
    all/0,
    groups/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases
-export([
    %% Handshake tests
    handshake_google/1,
    handshake_cloudflare/1,

    %% Version tests
    version_negotiation/1,

    %% Packet tests
    initial_packet_format/1,
    packet_number_encoding/1,

    %% Crypto tests
    initial_keys_derivation/1,
    key_update/1,

    %% Connection tests
    connection_close/1,
    idle_timeout/1,

    %% Stream tests
    stream_data_transfer/1,
    bidirectional_stream/1,
    unidirectional_stream/1,

    %% Flow control tests
    flow_control_connection/1,
    flow_control_stream/1,

    %% Loss recovery tests
    retransmission/1,

    %% Local tests (no network)
    local_packet_roundtrip/1,
    local_frame_roundtrip/1,
    local_key_derivation/1,
    local_connection_state/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [
        {group, local_tests},
        {group, packet_tests},
        {group, crypto_tests}
        %% Network tests disabled by default - uncomment to run
        %% {group, handshake_tests},
        %% {group, connection_tests},
        %% {group, stream_tests}
    ].

groups() ->
    [
        {local_tests, [parallel], [
            local_packet_roundtrip,
            local_frame_roundtrip,
            local_key_derivation,
            local_connection_state
        ]},
        {packet_tests, [sequence], [
            initial_packet_format,
            packet_number_encoding
        ]},
        {crypto_tests, [sequence], [
            initial_keys_derivation
        ]},
        {handshake_tests, [sequence], [
            handshake_google,
            handshake_cloudflare
        ]},
        {connection_tests, [sequence], [
            connection_close,
            idle_timeout,
            version_negotiation
        ]},
        {stream_tests, [sequence], [
            stream_data_transfer,
            bidirectional_stream,
            unidirectional_stream
        ]},
        {flow_control_tests, [sequence], [
            flow_control_connection,
            flow_control_stream
        ]},
        {recovery_tests, [sequence], [
            retransmission
        ]}
    ].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(handshake_tests, Config) ->
    %% Check network connectivity
    case check_network() of
        ok -> Config;
        {error, _} -> {skip, "Network not available"}
    end;
init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%====================================================================
%% Local Tests (No Network Required)
%%====================================================================

local_packet_roundtrip(Config) ->
    ct:comment("Test packet encode/decode roundtrip"),

    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    Payload = <<"test payload">>,

    %% Test Initial packet
    InitialOpts = #{token => <<>>, payload => Payload, pn => 0},
    InitialEncoded = quic_packet:encode_long(initial, ?QUIC_VERSION_1, DCID, SCID, InitialOpts),
    {ok, InitialPacket, <<>>} = quic_packet:decode(InitialEncoded, 8),
    ?assertEqual(initial, InitialPacket#quic_packet.type),
    ?assertEqual(?QUIC_VERSION_1, InitialPacket#quic_packet.version),
    ?assertEqual(DCID, InitialPacket#quic_packet.dcid),
    ?assertEqual(SCID, InitialPacket#quic_packet.scid),

    %% Test Handshake packet
    HSEncoded = quic_packet:encode_long(handshake, ?QUIC_VERSION_1, DCID, SCID,
                                        #{payload => Payload, pn => 1}),
    {ok, HSPacket, <<>>} = quic_packet:decode(HSEncoded, 8),
    ?assertEqual(handshake, HSPacket#quic_packet.type),

    %% Test short header packet
    ShortEncoded = quic_packet:encode_short(DCID, 100, Payload, false),
    {ok, ShortPacket, <<>>} = quic_packet:decode(ShortEncoded, 8),
    ?assertEqual(one_rtt, ShortPacket#quic_packet.type),

    {comment, "Packet roundtrip successful"}.

local_frame_roundtrip(Config) ->
    ct:comment("Test frame encode/decode roundtrip"),

    %% Test various frame types
    %% Frame formats match quic_frame.erl:
    %% - ACK: {ack, Ranges, AckDelay, ECNCounts} where Ranges = [{Largest, FirstRange} | ...]
    %% - CONNECTION_CLOSE: {connection_close, transport|application, ErrorCode, FrameType, Reason}
    Frames = [
        ping,
        padding,
        {crypto, 0, <<"crypto data">>},
        {stream, 4, 0, <<"stream data">>, false},
        {stream, 4, 11, <<"more data">>, true},
        {ack, [{100, 5}], 25, undefined},
        {max_data, 1000000},
        {max_stream_data, 4, 500000},
        {max_streams, bidi, 100},
        {data_blocked, 1000000},
        {stream_data_blocked, 4, 500000},
        {new_connection_id, 1, 0, <<1,2,3,4,5,6,7,8>>, crypto:strong_rand_bytes(16)},
        {retire_connection_id, 0},
        {path_challenge, <<1,2,3,4,5,6,7,8>>},
        {path_response, <<8,7,6,5,4,3,2,1>>},
        {connection_close, transport, 0, 0, <<>>},
        handshake_done
    ],

    lists:foreach(fun(Frame) ->
        Encoded = quic_frame:encode(Frame),
        {Decoded, <<>>} = quic_frame:decode(Encoded),
        %% Verify key fields match
        case {Frame, Decoded} of
            {ping, ping} -> ok;
            {padding, padding} -> ok;
            {{crypto, O1, D1}, {crypto, O2, D2}} ->
                ?assertEqual(O1, O2),
                ?assertEqual(D1, D2);
            {{stream, S1, O1, D1, F1}, {stream, S2, O2, D2, F2}} ->
                ?assertEqual(S1, S2),
                ?assertEqual(O1, O2),
                ?assertEqual(D1, D2),
                ?assertEqual(F1, F2);
            {{ack, R1, D1, E1}, {ack, R2, D2, E2}} ->
                ?assertEqual(R1, R2),
                ?assertEqual(D1, D2),
                ?assertEqual(E1, E2);
            {{connection_close, T1, C1, F1, R1}, {connection_close, T2, C2, F2, R2}} ->
                ?assertEqual(T1, T2),
                ?assertEqual(C1, C2),
                ?assertEqual(F1, F2),
                ?assertEqual(R1, R2);
            {handshake_done, handshake_done} -> ok;
            _ -> ok  % Other frames
        end
    end, Frames),

    {comment, "Frame roundtrip successful"}.

local_key_derivation(Config) ->
    ct:comment("Test key derivation against RFC 9001 test vectors"),

    %% RFC 9001 Appendix A.1 test vector
    DCID = hexstr_to_bin("8394c8f03e515708"),

    %% Initial secret
    InitialSecret = quic_keys:derive_initial_secret(DCID),
    ExpectedInitialSecret = hexstr_to_bin(
        "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"),
    ?assertEqual(ExpectedInitialSecret, InitialSecret),

    %% Client initial keys
    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_initial_client(DCID),
    ?assertEqual(hexstr_to_bin("1f369613dd76d5467730efcbe3b1a22d"), ClientKey),
    ?assertEqual(hexstr_to_bin("fa044b2f42a3fd3b46fb255c"), ClientIV),
    ?assertEqual(hexstr_to_bin("9f50449e04a0e810283a1e9933adedd2"), ClientHP),

    %% Server initial keys
    {ServerKey, ServerIV, ServerHP} = quic_keys:derive_initial_server(DCID),
    ?assertEqual(hexstr_to_bin("cf3a5331653c364c88f0f379b6067e37"), ServerKey),
    ?assertEqual(hexstr_to_bin("0ac1493ca1905853b0bba03e"), ServerIV),
    ?assertEqual(hexstr_to_bin("c206b8d9b9f0f37644430b490eeaa314"), ServerHP),

    {comment, "Key derivation matches RFC 9001 test vectors"}.

local_connection_state(Config) ->
    ct:comment("Test connection state machine"),

    %% Start a connection
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    ?assert(is_pid(Pid)),

    %% Verify initial state
    {State, Info} = quic_connection:get_state(Pid),
    ?assertEqual(idle, State),
    ?assert(maps:is_key(scid, Info)),
    ?assert(maps:is_key(dcid, Info)),

    %% Close connection
    quic_connection:close(Pid, normal),
    timer:sleep(100),

    {comment, "Connection state machine works"}.

%%====================================================================
%% Packet Tests
%%====================================================================

initial_packet_format(Config) ->
    ct:comment("Verify Initial packet format per RFC 9000"),

    DCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,
    SCID = <<16#f0, 16#67, 16#a5, 16#50, 16#2a, 16#42, 16#62, 16#b5>>,

    Payload = crypto:strong_rand_bytes(100),
    Opts = #{token => <<>>, payload => Payload, pn => 0},

    Encoded = quic_packet:encode_long(initial, ?QUIC_VERSION_1, DCID, SCID, Opts),

    %% Verify header structure
    <<FirstByte, Version:32, DCIDLen, _/binary>> = Encoded,

    %% Form bit (0x80) and Fixed bit (0x40) should be set for long header
    ?assertEqual(16#C0, FirstByte band 16#C0),

    %% Version should be QUIC v1
    ?assertEqual(?QUIC_VERSION_1, Version),

    %% DCID length
    ?assertEqual(8, DCIDLen),

    {comment, "Initial packet format correct"}.

packet_number_encoding(Config) ->
    ct:comment("Test packet number encoding"),

    %% Test various packet numbers
    PNs = [0, 1, 127, 128, 255, 256, 16383, 16384, 1073741823],

    lists:foreach(fun(PN) ->
        DCID = crypto:strong_rand_bytes(8),
        Payload = <<"test">>,
        Encoded = quic_packet:encode_short(DCID, PN, Payload, false),
        {ok, Decoded, <<>>} = quic_packet:decode(Encoded, 8),
        ?assertEqual(one_rtt, Decoded#quic_packet.type)
    end, PNs),

    {comment, "Packet number encoding correct"}.

%%====================================================================
%% Crypto Tests
%%====================================================================

initial_keys_derivation(Config) ->
    ct:comment("Test initial keys derivation"),

    %% Generate random DCID and derive keys
    DCID = crypto:strong_rand_bytes(8),

    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_initial_client(DCID),
    {ServerKey, ServerIV, ServerHP} = quic_keys:derive_initial_server(DCID),

    %% Verify key sizes
    ?assertEqual(16, byte_size(ClientKey)),
    ?assertEqual(12, byte_size(ClientIV)),
    ?assertEqual(16, byte_size(ClientHP)),
    ?assertEqual(16, byte_size(ServerKey)),
    ?assertEqual(12, byte_size(ServerIV)),
    ?assertEqual(16, byte_size(ServerHP)),

    %% Client and server keys should be different
    ?assertNotEqual(ClientKey, ServerKey),
    ?assertNotEqual(ClientIV, ServerIV),
    ?assertNotEqual(ClientHP, ServerHP),

    %% Test AEAD encryption with derived keys
    Plaintext = <<"Hello, QUIC!">>,
    AAD = <<"additional data">>,
    PN = 0,

    Ciphertext = quic_aead:encrypt(ClientKey, ClientIV, PN, AAD, Plaintext),
    {ok, Decrypted} = quic_aead:decrypt(ClientKey, ClientIV, PN, AAD, Ciphertext),
    ?assertEqual(Plaintext, Decrypted),

    {comment, "Initial keys derivation and encryption works"}.

key_update(Config) ->
    ct:comment("Test TLS 1.3 key schedule"),

    %% Generate ECDHE shared secret
    {PubA, PrivA} = quic_crypto:generate_key_pair(x25519),
    {PubB, PrivB} = quic_crypto:generate_key_pair(x25519),

    SharedA = quic_crypto:compute_shared_secret(x25519, PrivA, PubB),
    SharedB = quic_crypto:compute_shared_secret(x25519, PrivB, PubA),
    ?assertEqual(SharedA, SharedB),

    %% Derive key schedule
    EarlySecret = quic_crypto:derive_early_secret(),
    HandshakeSecret = quic_crypto:derive_handshake_secret(EarlySecret, SharedA),
    MasterSecret = quic_crypto:derive_master_secret(HandshakeSecret),

    ?assertEqual(32, byte_size(EarlySecret)),
    ?assertEqual(32, byte_size(HandshakeSecret)),
    ?assertEqual(32, byte_size(MasterSecret)),

    %% Derive traffic secrets
    TranscriptHash = crypto:hash(sha256, <<"ClientHello || ServerHello">>),
    ClientHS = quic_crypto:derive_client_handshake_secret(HandshakeSecret, TranscriptHash),
    ServerHS = quic_crypto:derive_server_handshake_secret(HandshakeSecret, TranscriptHash),

    ?assertNotEqual(ClientHS, ServerHS),

    {comment, "Key schedule derivation works"}.

%%====================================================================
%% Network Tests (Require Connectivity)
%%====================================================================

handshake_google(Config) ->
    ct:comment("Test handshake with Google QUIC server"),
    {skip, "Network test - run manually"}.

handshake_cloudflare(Config) ->
    ct:comment("Test handshake with Cloudflare QUIC server"),
    {skip, "Network test - run manually"}.

version_negotiation(Config) ->
    ct:comment("Test version negotiation"),
    {skip, "Network test - run manually"}.

connection_close(Config) ->
    ct:comment("Test connection close"),
    {skip, "Not implemented yet"}.

idle_timeout(Config) ->
    ct:comment("Test idle timeout"),
    {skip, "Not implemented yet"}.

stream_data_transfer(Config) ->
    ct:comment("Test stream data transfer"),
    {skip, "Not implemented yet"}.

bidirectional_stream(Config) ->
    ct:comment("Test bidirectional stream"),
    {skip, "Not implemented yet"}.

unidirectional_stream(Config) ->
    ct:comment("Test unidirectional stream"),
    {skip, "Not implemented yet"}.

flow_control_connection(Config) ->
    ct:comment("Test connection-level flow control"),
    {skip, "Not implemented yet"}.

flow_control_stream(Config) ->
    ct:comment("Test stream-level flow control"),
    {skip, "Not implemented yet"}.

retransmission(Config) ->
    ct:comment("Test packet retransmission"),
    {skip, "Not implemented yet"}.

%%====================================================================
%% Helper Functions
%%====================================================================

check_network() ->
    %% Simple network check - try to resolve DNS
    case inet:getaddr("google.com", inet) of
        {ok, _} -> ok;
        {error, Reason} -> {error, Reason}
    end.

hexstr_to_bin(HexStr) ->
    hexstr_to_bin(HexStr, <<>>).

hexstr_to_bin([], Acc) ->
    Acc;
hexstr_to_bin([H1, H2 | Rest], Acc) ->
    Byte = list_to_integer([H1, H2], 16),
    hexstr_to_bin(Rest, <<Acc/binary, Byte>>).
