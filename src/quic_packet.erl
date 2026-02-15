%%% -*- erlang -*-
%%%
%%% QUIC Packet Encoding/Decoding
%%% RFC 9000 Section 17
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC packet encoding and decoding.
%%%
%%% This module handles encoding and decoding of QUIC packets including:
%%% - Long header packets (Initial, Handshake, 0-RTT, Retry)
%%% - Short header packets (1-RTT)
%%%
%%% == Packet Header Format ==
%%%
%%% Long Header:
%%% ```
%%% +-+-+-+-+-+-+-+-+
%%% |1|1|T T|X X X X|
%%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%% |                         Version (32)                          |
%%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%% | DCID Len (8)  |
%%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%% |               Destination Connection ID (0..160)            ...
%%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%% | SCID Len (8)  |
%%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%% |                 Source Connection ID (0..160)               ...
%%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%% '''
%%%
%%% Short Header:
%%% ```
%%% +-+-+-+-+-+-+-+-+
%%% |0|1|S|R|R|K|P P|
%%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%% |                Destination Connection ID (0..160)           ...
%%% +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%% '''
%%%

-module(quic_packet).

-include("quic.hrl").

-export([
    encode_long/5,
    encode_short/4,
    decode/2,
    encode_pn/2,
    decode_pn/2,
    pn_length/1
]).

-export_type([packet_type/0, packet/0]).

-type packet_type() :: initial | handshake | zero_rtt | one_rtt | retry.
-type packet() :: #quic_packet{}.

%%====================================================================
%% API
%%====================================================================

%% @doc Encode a long header packet.
%% Type is one of: initial, handshake, zero_rtt, retry
%% Returns the encoded packet header + payload.
%% Note: For Initial packets, Token is required.
%% Note: Packet number and payload should already be encrypted.
-spec encode_long(packet_type(), non_neg_integer(), binary(), binary(),
                  #{token => binary(), pn => non_neg_integer(), payload => binary()}) ->
    binary().
encode_long(Type, Version, DCID, SCID, Opts) ->
    TypeBits = type_to_bits(Type),
    Token = maps:get(token, Opts, <<>>),
    PN = maps:get(pn, Opts, 0),
    Payload = maps:get(payload, Opts, <<>>),

    %% Reserved bits (R R) are 0, packet number length encoded in low 2 bits
    PNLen = pn_length(PN),
    PNLenBits = PNLen - 1,  % 0 = 1 byte, 1 = 2 bytes, etc.

    %% First byte: 1 | 1 | Type (2) | Reserved (2) | PN Len (2)
    FirstByte = 2#11000000 bor (TypeBits bsl 4) bor PNLenBits,

    DCIDLen = byte_size(DCID),
    SCIDLen = byte_size(SCID),

    case Type of
        initial ->
            TokenLen = byte_size(Token),
            PNBin = encode_pn(PN, PNLen),
            PayloadLen = byte_size(Payload) + PNLen,
            <<FirstByte, Version:32, DCIDLen, DCID/binary,
              SCIDLen, SCID/binary,
              (quic_varint:encode(TokenLen))/binary, Token/binary,
              (quic_varint:encode(PayloadLen))/binary,
              PNBin/binary, Payload/binary>>;
        handshake ->
            PNBin = encode_pn(PN, PNLen),
            PayloadLen = byte_size(Payload) + PNLen,
            <<FirstByte, Version:32, DCIDLen, DCID/binary,
              SCIDLen, SCID/binary,
              (quic_varint:encode(PayloadLen))/binary,
              PNBin/binary, Payload/binary>>;
        zero_rtt ->
            PNBin = encode_pn(PN, PNLen),
            PayloadLen = byte_size(Payload) + PNLen,
            <<FirstByte, Version:32, DCIDLen, DCID/binary,
              SCIDLen, SCID/binary,
              (quic_varint:encode(PayloadLen))/binary,
              PNBin/binary, Payload/binary>>;
        retry ->
            %% Retry packets have no packet number
            %% Payload contains Retry Token + Retry Integrity Tag
            <<FirstByte, Version:32, DCIDLen, DCID/binary,
              SCIDLen, SCID/binary, Payload/binary>>
    end.

%% @doc Encode a short header (1-RTT) packet.
%% DCIDLen is the expected DCID length (from connection state).
%% Returns the encoded packet.
-spec encode_short(binary(), non_neg_integer(), binary(), boolean()) -> binary().
encode_short(DCID, PN, Payload, SpinBit) ->
    PNLen = pn_length(PN),
    PNLenBits = PNLen - 1,

    %% First byte: 0 | 1 | S | Reserved (2) | Key Phase | PN Len (2)
    %% S = Spin bit, Key Phase = 0 for now
    SpinBitVal = case SpinBit of true -> 1; false -> 0 end,
    FirstByte = 2#01000000 bor (SpinBitVal bsl 5) bor PNLenBits,

    PNBin = encode_pn(PN, PNLen),
    <<FirstByte, DCID/binary, PNBin/binary, Payload/binary>>.

%% @doc Decode a QUIC packet.
%% DCIDLen is used for short header packets where DCID length is implicit.
%% Returns {ok, Packet, Rest} or {error, Reason}.
-spec decode(binary(), non_neg_integer()) ->
    {ok, packet(), binary()} | {error, term()}.
decode(<<1:1, _:7, _/binary>> = Bin, _DCIDLen) ->
    decode_long(Bin);
decode(<<0:1, _:7, _/binary>> = Bin, DCIDLen) ->
    decode_short(Bin, DCIDLen);
decode(<<>>, _) ->
    {error, empty}.

%% @doc Encode a packet number.
-spec encode_pn(non_neg_integer(), 1..4) -> binary().
encode_pn(PN, 1) -> <<PN:8>>;
encode_pn(PN, 2) -> <<PN:16>>;
encode_pn(PN, 3) -> <<PN:24>>;
encode_pn(PN, 4) -> <<PN:32>>.

%% @doc Decode a packet number.
-spec decode_pn(binary(), 1..4) -> {non_neg_integer(), binary()}.
decode_pn(<<PN:8, Rest/binary>>, 1) -> {PN, Rest};
decode_pn(<<PN:16, Rest/binary>>, 2) -> {PN, Rest};
decode_pn(<<PN:24, Rest/binary>>, 3) -> {PN, Rest};
decode_pn(<<PN:32, Rest/binary>>, 4) -> {PN, Rest}.

%% @doc Calculate the minimum number of bytes needed for a packet number.
-spec pn_length(non_neg_integer()) -> 1..4.
pn_length(PN) when PN < 256 -> 1;
pn_length(PN) when PN < 65536 -> 2;
pn_length(PN) when PN < 16777216 -> 3;
pn_length(_) -> 4.

%%====================================================================
%% Internal Functions
%%====================================================================

decode_long(<<FirstByte, Version:32, DCIDLen, Rest/binary>>) ->
    <<DCID:DCIDLen/binary, SCIDLen, Rest2/binary>> = Rest,
    <<SCID:SCIDLen/binary, Rest3/binary>> = Rest2,
    Type = bits_to_type((FirstByte bsr 4) band 2#11),
    PNLenBits = FirstByte band 2#11,
    PNLen = PNLenBits + 1,

    case Type of
        initial ->
            {TokenLen, Rest4} = quic_varint:decode(Rest3),
            <<Token:TokenLen/binary, Rest5/binary>> = Rest4,
            {PayloadLen, Rest6} = quic_varint:decode(Rest5),
            {PN, Rest7} = decode_pn(Rest6, PNLen),
            PayloadSize = PayloadLen - PNLen,
            <<Payload:PayloadSize/binary, Rest8/binary>> = Rest7,
            Packet = #quic_packet{
                type = initial,
                version = Version,
                dcid = DCID,
                scid = SCID,
                token = Token,
                pn = PN,
                payload = Payload
            },
            {ok, Packet, Rest8};
        handshake ->
            {PayloadLen, Rest4} = quic_varint:decode(Rest3),
            {PN, Rest5} = decode_pn(Rest4, PNLen),
            PayloadSize = PayloadLen - PNLen,
            <<Payload:PayloadSize/binary, Rest6/binary>> = Rest5,
            Packet = #quic_packet{
                type = handshake,
                version = Version,
                dcid = DCID,
                scid = SCID,
                pn = PN,
                payload = Payload
            },
            {ok, Packet, Rest6};
        zero_rtt ->
            {PayloadLen, Rest4} = quic_varint:decode(Rest3),
            {PN, Rest5} = decode_pn(Rest4, PNLen),
            PayloadSize = PayloadLen - PNLen,
            <<Payload:PayloadSize/binary, Rest6/binary>> = Rest5,
            Packet = #quic_packet{
                type = zero_rtt,
                version = Version,
                dcid = DCID,
                scid = SCID,
                pn = PN,
                payload = Payload
            },
            {ok, Packet, Rest6};
        retry ->
            %% Retry packet: no length field, rest is token + integrity tag
            Packet = #quic_packet{
                type = retry,
                version = Version,
                dcid = DCID,
                scid = SCID,
                payload = Rest3
            },
            {ok, Packet, <<>>}
    end;
decode_long(_) ->
    {error, invalid_packet}.

decode_short(<<FirstByte, Rest/binary>>, DCIDLen) ->
    <<DCID:DCIDLen/binary, Rest2/binary>> = Rest,
    PNLenBits = FirstByte band 2#11,
    PNLen = PNLenBits + 1,
    {PN, Payload} = decode_pn(Rest2, PNLen),
    %% Note: Payload here is still encrypted and includes AEAD tag
    Packet = #quic_packet{
        type = one_rtt,
        dcid = DCID,
        pn = PN,
        payload = Payload
    },
    {ok, Packet, <<>>}.

type_to_bits(initial) -> 0;
type_to_bits(zero_rtt) -> 1;
type_to_bits(handshake) -> 2;
type_to_bits(retry) -> 3.

bits_to_type(0) -> initial;
bits_to_type(1) -> zero_rtt;
bits_to_type(2) -> handshake;
bits_to_type(3) -> retry.
