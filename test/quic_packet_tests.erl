%%% -*- erlang -*-
%%%
%%% Tests for QUIC Packet Encoding/Decoding
%%% RFC 9000 Section 17
%%%

-module(quic_packet_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Packet Number Encoding
%%====================================================================

pn_length_test() ->
    ?assertEqual(1, quic_packet:pn_length(0)),
    ?assertEqual(1, quic_packet:pn_length(255)),
    ?assertEqual(2, quic_packet:pn_length(256)),
    ?assertEqual(2, quic_packet:pn_length(65535)),
    ?assertEqual(3, quic_packet:pn_length(65536)),
    ?assertEqual(3, quic_packet:pn_length(16777215)),
    ?assertEqual(4, quic_packet:pn_length(16777216)).

encode_pn_test() ->
    ?assertEqual(<<0>>, quic_packet:encode_pn(0, 1)),
    ?assertEqual(<<255>>, quic_packet:encode_pn(255, 1)),
    ?assertEqual(<<1, 0>>, quic_packet:encode_pn(256, 2)),
    ?assertEqual(<<255, 255>>, quic_packet:encode_pn(65535, 2)),
    ?assertEqual(<<1, 0, 0>>, quic_packet:encode_pn(65536, 3)),
    ?assertEqual(<<1, 0, 0, 0>>, quic_packet:encode_pn(16777216, 4)).

decode_pn_test() ->
    ?assertEqual({0, <<>>}, quic_packet:decode_pn(<<0>>, 1)),
    ?assertEqual({255, <<"rest">>}, quic_packet:decode_pn(<<255, "rest">>, 1)),
    ?assertEqual({256, <<>>}, quic_packet:decode_pn(<<1, 0>>, 2)),
    ?assertEqual({65536, <<>>}, quic_packet:decode_pn(<<1, 0, 0>>, 3)),
    ?assertEqual({16777216, <<>>}, quic_packet:decode_pn(<<1, 0, 0, 0>>, 4)).

%%====================================================================
%% Initial Packet
%%====================================================================

initial_packet_roundtrip_test() ->
    DCID = <<1,2,3,4,5,6,7,8>>,
    SCID = <<10,20,30,40>>,
    Token = <<"initial_token">>,
    Payload = <<"encrypted_payload">>,
    PN = 0,

    Encoded = quic_packet:encode_long(initial, ?QUIC_VERSION_1, DCID, SCID,
                                       #{token => Token, pn => PN, payload => Payload}),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(initial, Packet#quic_packet.type),
    ?assertEqual(?QUIC_VERSION_1, Packet#quic_packet.version),
    ?assertEqual(DCID, Packet#quic_packet.dcid),
    ?assertEqual(SCID, Packet#quic_packet.scid),
    ?assertEqual(Token, Packet#quic_packet.token),
    ?assertEqual(PN, Packet#quic_packet.pn),
    ?assertEqual(Payload, Packet#quic_packet.payload).

initial_packet_no_token_roundtrip_test() ->
    DCID = <<1,2,3,4,5,6,7,8>>,
    SCID = <<10,20,30,40>>,
    Payload = <<"encrypted_payload">>,
    PN = 1,

    Encoded = quic_packet:encode_long(initial, ?QUIC_VERSION_1, DCID, SCID,
                                       #{pn => PN, payload => Payload}),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(initial, Packet#quic_packet.type),
    ?assertEqual(<<>>, Packet#quic_packet.token),
    ?assertEqual(PN, Packet#quic_packet.pn),
    ?assertEqual(Payload, Packet#quic_packet.payload).

initial_packet_large_pn_test() ->
    DCID = <<1,2,3,4,5,6,7,8>>,
    SCID = <<>>,
    Payload = <<"data">>,
    PN = 300,  % Requires 2 bytes

    Encoded = quic_packet:encode_long(initial, ?QUIC_VERSION_1, DCID, SCID,
                                       #{pn => PN, payload => Payload}),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(PN, Packet#quic_packet.pn).

%%====================================================================
%% Handshake Packet
%%====================================================================

handshake_packet_roundtrip_test() ->
    DCID = <<1,2,3,4,5,6,7,8>>,
    SCID = <<10,20,30,40>>,
    Payload = <<"handshake_data">>,
    PN = 2,

    Encoded = quic_packet:encode_long(handshake, ?QUIC_VERSION_1, DCID, SCID,
                                       #{pn => PN, payload => Payload}),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(handshake, Packet#quic_packet.type),
    ?assertEqual(?QUIC_VERSION_1, Packet#quic_packet.version),
    ?assertEqual(DCID, Packet#quic_packet.dcid),
    ?assertEqual(SCID, Packet#quic_packet.scid),
    ?assertEqual(PN, Packet#quic_packet.pn),
    ?assertEqual(Payload, Packet#quic_packet.payload).

%%====================================================================
%% 0-RTT Packet
%%====================================================================

zero_rtt_packet_roundtrip_test() ->
    DCID = <<1,2,3,4,5,6,7,8>>,
    SCID = <<10,20,30,40>>,
    Payload = <<"0rtt_data">>,
    PN = 0,

    Encoded = quic_packet:encode_long(zero_rtt, ?QUIC_VERSION_1, DCID, SCID,
                                       #{pn => PN, payload => Payload}),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(zero_rtt, Packet#quic_packet.type),
    ?assertEqual(Payload, Packet#quic_packet.payload).

%%====================================================================
%% Retry Packet
%%====================================================================

retry_packet_roundtrip_test() ->
    DCID = <<1,2,3,4,5,6,7,8>>,
    SCID = <<10,20,30,40>>,
    %% Retry payload = Retry Token + 16-byte Integrity Tag
    RetryToken = <<"retry_token_data">>,
    IntegrityTag = crypto:strong_rand_bytes(16),
    Payload = <<RetryToken/binary, IntegrityTag/binary>>,

    Encoded = quic_packet:encode_long(retry, ?QUIC_VERSION_1, DCID, SCID,
                                       #{payload => Payload}),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(retry, Packet#quic_packet.type),
    ?assertEqual(Payload, Packet#quic_packet.payload).

%%====================================================================
%% Short Header (1-RTT) Packet
%%====================================================================

short_packet_roundtrip_test() ->
    DCID = <<1,2,3,4,5,6,7,8>>,
    Payload = <<"encrypted_app_data">>,
    PN = 100,

    Encoded = quic_packet:encode_short(DCID, PN, Payload, false),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(one_rtt, Packet#quic_packet.type),
    ?assertEqual(DCID, Packet#quic_packet.dcid),
    ?assertEqual(PN, Packet#quic_packet.pn).

short_packet_with_spin_bit_test() ->
    DCID = <<1,2,3,4>>,
    Payload = <<"data">>,
    PN = 0,

    Encoded = quic_packet:encode_short(DCID, PN, Payload, true),

    %% Verify first byte has spin bit set (bit 5)
    <<FirstByte, _/binary>> = Encoded,
    SpinBit = (FirstByte bsr 5) band 1,
    ?assertEqual(1, SpinBit).

short_packet_large_pn_test() ->
    DCID = <<1,2,3,4,5,6,7,8>>,
    Payload = <<"data">>,
    PN = 1000000,  % Requires 3 bytes

    Encoded = quic_packet:encode_short(DCID, PN, Payload, false),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(PN, Packet#quic_packet.pn).

%%====================================================================
%% Header Form Detection
%%====================================================================

long_header_detection_test() ->
    %% Long header starts with 1 in bit 7
    LongPacket = quic_packet:encode_long(initial, ?QUIC_VERSION_1,
                                          <<1,2,3,4>>, <<5,6,7,8>>,
                                          #{pn => 0, payload => <<"data">>}),
    <<FirstByte, _/binary>> = LongPacket,
    ?assertEqual(1, (FirstByte bsr 7) band 1).

short_header_detection_test() ->
    %% Short header starts with 0 in bit 7, 1 in bit 6
    ShortPacket = quic_packet:encode_short(<<1,2,3,4>>, 0, <<"data">>, false),
    <<FirstByte, _/binary>> = ShortPacket,
    ?assertEqual(0, (FirstByte bsr 7) band 1),
    ?assertEqual(1, (FirstByte bsr 6) band 1).

%%====================================================================
%% Empty Connection IDs
%%====================================================================

empty_dcid_test() ->
    DCID = <<>>,
    SCID = <<1,2,3,4>>,
    Payload = <<"data">>,

    Encoded = quic_packet:encode_long(initial, ?QUIC_VERSION_1, DCID, SCID,
                                       #{pn => 0, payload => Payload}),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 0),
    ?assertEqual(<<>>, Packet#quic_packet.dcid).

empty_scid_test() ->
    DCID = <<1,2,3,4,5,6,7,8>>,
    SCID = <<>>,
    Payload = <<"data">>,

    Encoded = quic_packet:encode_long(initial, ?QUIC_VERSION_1, DCID, SCID,
                                       #{pn => 0, payload => Payload}),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(<<>>, Packet#quic_packet.scid).

%%====================================================================
%% Error Cases
%%====================================================================

decode_empty_test() ->
    ?assertEqual({error, empty}, quic_packet:decode(<<>>, 8)).
