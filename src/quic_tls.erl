%%% -*- erlang -*-
%%%
%%% QUIC TLS 1.3 Message Handling
%%% RFC 8446 - TLS 1.3
%%% RFC 9001 - Using TLS to Secure QUIC
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc TLS 1.3 message generation and parsing for QUIC.
%%%
%%% This module handles TLS 1.3 handshake messages as they appear in
%%% QUIC CRYPTO frames. Messages are encoded without the TLS record layer.
%%%
%%% == TLS Messages in QUIC ==
%%%
%%% QUIC uses TLS 1.3 for the cryptographic handshake, but without the
%%% TLS record layer. TLS handshake messages are sent directly in
%%% CRYPTO frames.
%%%

-module(quic_tls).

-include("quic.hrl").

-export([
    %% ClientHello
    build_client_hello/1,

    %% Server message parsing
    parse_server_hello/1,
    parse_encrypted_extensions/1,
    parse_certificate/1,
    parse_certificate_verify/1,
    parse_finished/1,

    %% Client Finished
    build_finished/1,
    verify_finished/3,
    verify_finished/4,

    %% Transport parameters
    encode_transport_params/1,
    decode_transport_params/1,

    %% TLS message framing
    encode_handshake_message/2,
    decode_handshake_message/1
]).

%%====================================================================
%% ClientHello
%%====================================================================

%% @doc Build a TLS 1.3 ClientHello message for QUIC.
%% Options:
%%   - server_name: SNI hostname (binary)
%%   - alpn: List of ALPN protocols (list of binaries)
%%   - transport_params: QUIC transport parameters (map)
%%
%% Returns: {ClientHelloMsg, PrivateKey, Random}
-spec build_client_hello(map()) -> {binary(), binary(), binary()}.
build_client_hello(Opts) ->
    %% Generate client random (32 bytes)
    Random = crypto:strong_rand_bytes(32),

    %% Generate ECDHE key pair (x25519)
    {PubKey, PrivKey} = crypto:generate_key(ecdh, x25519),

    %% Build extensions
    Extensions = build_client_hello_extensions(PubKey, Opts),

    %% Legacy session ID (empty for TLS 1.3)
    SessionId = <<>>,

    %% Cipher suites (TLS 1.3 only)
    %% Only offering AES-128-GCM for now until AES-256-GCM derivation is fixed
    CipherSuites = <<?TLS_AES_128_GCM_SHA256:16>>,

    %% Legacy compression methods (null only)
    CompressionMethods = <<1, 0>>,

    %% Build ClientHello body
    ClientHello = <<
        ?TLS_VERSION_1_2:16,          % legacy_version (always 0x0303)
        Random:32/binary,              % random
        (byte_size(SessionId)):8,      % legacy_session_id length
        SessionId/binary,              % legacy_session_id
        (byte_size(CipherSuites)):16,  % cipher_suites length
        CipherSuites/binary,           % cipher_suites
        CompressionMethods/binary,     % legacy_compression_methods
        (byte_size(Extensions)):16,    % extensions length
        Extensions/binary              % extensions
    >>,

    %% Wrap in handshake message
    Msg = encode_handshake_message(?TLS_CLIENT_HELLO, ClientHello),
    {Msg, PrivKey, Random}.

%% Build ClientHello extensions
build_client_hello_extensions(PubKey, Opts) ->
    ServerName = maps:get(server_name, Opts, undefined),
    Alpn = maps:get(alpn, Opts, []),
    TransportParams = maps:get(transport_params, Opts, #{}),

    %% Supported versions (TLS 1.3 only)
    %% Length is in bytes (2 bytes per version), not version count
    SupportedVersions = encode_extension(?EXT_SUPPORTED_VERSIONS,
        <<2, ?TLS_VERSION_1_3:16>>),

    %% Supported groups (x25519)
    SupportedGroups = encode_extension(?EXT_SUPPORTED_GROUPS,
        <<2:16, ?GROUP_X25519:16>>),

    %% Signature algorithms
    SigAlgs = encode_extension(?EXT_SIGNATURE_ALGORITHMS,
        <<8:16,
          ?SIG_ECDSA_SECP256R1_SHA256:16,
          ?SIG_RSA_PSS_RSAE_SHA256:16,
          ?SIG_RSA_PKCS1_SHA256:16,
          ?SIG_ED25519:16>>),

    %% Key share (x25519 public key)
    KeyShareEntry = <<?GROUP_X25519:16, 32:16, PubKey:32/binary>>,
    KeyShare = encode_extension(?EXT_KEY_SHARE,
        <<(byte_size(KeyShareEntry)):16, KeyShareEntry/binary>>),

    %% Server Name Indication
    SNI = case ServerName of
        undefined -> <<>>;
        Name when is_binary(Name) ->
            NameLen = byte_size(Name),
            NameList = <<0, NameLen:16, Name/binary>>,
            encode_extension(?EXT_SERVER_NAME,
                <<(byte_size(NameList)):16, NameList/binary>>)
    end,

    %% ALPN
    AlpnExt = case Alpn of
        [] -> <<>>;
        Protocols ->
            ProtocolList = encode_alpn_list(Protocols),
            encode_extension(?EXT_ALPN,
                <<(byte_size(ProtocolList)):16, ProtocolList/binary>>)
    end,

    %% QUIC Transport Parameters
    TransportParamsData = encode_transport_params(TransportParams),
    TransportParamsExt = encode_extension(?EXT_QUIC_TRANSPORT_PARAMS,
        TransportParamsData),

    %% PSK Key Exchange Modes (psk_dhe_ke only)
    PskModes = encode_extension(?EXT_PSK_KEY_EXCHANGE_MODES,
        <<1, 1>>),  % psk_dhe_ke = 1

    iolist_to_binary([
        SupportedVersions,
        SupportedGroups,
        SigAlgs,
        KeyShare,
        SNI,
        AlpnExt,
        TransportParamsExt,
        PskModes
    ]).

encode_alpn_list(Protocols) ->
    iolist_to_binary([<<(byte_size(P)):8, P/binary>> || P <- Protocols]).

%%====================================================================
%% Server Message Parsing
%%====================================================================

%% @doc Parse a ServerHello message.
%% Returns server's public key and selected cipher suite.
-spec parse_server_hello(binary()) ->
    {ok, #{public_key := binary(), cipher := atom(), random := binary()}} |
    {error, term()}.
parse_server_hello(<<
    ?TLS_VERSION_1_2:16,    % legacy_version
    Random:32/binary,
    SessionIdLen:8,
    SessionId:SessionIdLen/binary,
    CipherSuite:16,
    0,                       % legacy_compression_method
    ExtensionsLen:16,
    Extensions:ExtensionsLen/binary,
    _Rest/binary
>>) ->
    %% Parse extensions to get key_share
    case parse_extensions(Extensions) of
        {ok, ExtMap} ->
            case maps:find(?EXT_KEY_SHARE, ExtMap) of
                {ok, KeyShareData} ->
                    case parse_server_key_share(KeyShareData) of
                        {ok, PubKey} ->
                            Cipher = cipher_from_suite(CipherSuite),
                            {ok, #{
                                public_key => PubKey,
                                cipher => Cipher,
                                random => Random,
                                session_id => SessionId,
                                extensions => ExtMap
                            }};
                        Error ->
                            Error
                    end;
                error ->
                    {error, missing_key_share}
            end;
        Error ->
            Error
    end;
parse_server_hello(_) ->
    {error, invalid_server_hello}.

%% @doc Parse EncryptedExtensions message.
-spec parse_encrypted_extensions(binary()) ->
    {ok, #{alpn => binary(), transport_params => map()}} |
    {error, term()}.
parse_encrypted_extensions(<<ExtensionsLen:16, Extensions:ExtensionsLen/binary, _Rest/binary>>) ->
    case parse_extensions(Extensions) of
        {ok, ExtMap} ->
            Alpn = case maps:find(?EXT_ALPN, ExtMap) of
                {ok, <<_ListLen:16, ProtoLen:8, Proto:ProtoLen/binary, _/binary>>} ->
                    Proto;
                _ ->
                    undefined
            end,
            TransportParams = case maps:find(?EXT_QUIC_TRANSPORT_PARAMS, ExtMap) of
                {ok, TPData} ->
                    case decode_transport_params(TPData) of
                        {ok, TP} -> TP;
                        _ -> #{}
                    end;
                _ ->
                    #{}
            end,
            {ok, #{alpn => Alpn, transport_params => TransportParams}};
        Error ->
            Error
    end;
parse_encrypted_extensions(_) ->
    {error, invalid_encrypted_extensions}.

%% @doc Parse Certificate message.
-spec parse_certificate(binary()) ->
    {ok, #{context := binary(), certificates := [binary()]}} |
    {error, term()}.
parse_certificate(<<ContextLen:8, Context:ContextLen/binary,
                    CertsLen:24, CertsData:CertsLen/binary, _Rest/binary>>) ->
    Certs = parse_certificate_list(CertsData),
    {ok, #{context => Context, certificates => Certs}};
parse_certificate(_) ->
    {error, invalid_certificate}.

parse_certificate_list(<<>>) ->
    [];
parse_certificate_list(<<CertLen:24, Cert:CertLen/binary,
                         ExtLen:16, _Ext:ExtLen/binary, Rest/binary>>) ->
    [Cert | parse_certificate_list(Rest)].

%% @doc Parse CertificateVerify message.
-spec parse_certificate_verify(binary()) ->
    {ok, #{algorithm := non_neg_integer(), signature := binary()}} |
    {error, term()}.
parse_certificate_verify(<<Algorithm:16, SigLen:16, Signature:SigLen/binary, _Rest/binary>>) ->
    {ok, #{algorithm => Algorithm, signature => Signature}};
parse_certificate_verify(_) ->
    {error, invalid_certificate_verify}.

%% @doc Parse Finished message.
-spec parse_finished(binary()) -> {ok, binary()} | {error, term()}.
parse_finished(VerifyData) when byte_size(VerifyData) >= 32 ->
    %% SHA-256 produces 32 bytes
    <<Data:32/binary, _/binary>> = VerifyData,
    {ok, Data};
parse_finished(_) ->
    {error, invalid_finished}.

%%====================================================================
%% Client Finished
%%====================================================================

%% @doc Build a Finished message.
%% VerifyData should be computed using quic_crypto:compute_finished_verify/2.
-spec build_finished(binary()) -> binary().
build_finished(VerifyData) ->
    encode_handshake_message(?TLS_FINISHED, VerifyData).

%% @doc Verify a Finished message (default SHA-256).
%% TrafficSecret is the sender's traffic secret.
%% TranscriptHash is the hash of all messages up to (but not including) Finished.
-spec verify_finished(binary(), binary(), binary()) -> boolean().
verify_finished(ReceivedVerifyData, TrafficSecret, TranscriptHash) ->
    FinishedKey = quic_crypto:derive_finished_key(TrafficSecret),
    ExpectedVerifyData = quic_crypto:compute_finished_verify(FinishedKey, TranscriptHash),
    crypto:hash_equals(ReceivedVerifyData, ExpectedVerifyData).

%% @doc Verify a Finished message with cipher-specific hash.
-spec verify_finished(binary(), binary(), binary(), atom()) -> boolean().
verify_finished(ReceivedVerifyData, TrafficSecret, TranscriptHash, Cipher) ->
    FinishedKey = quic_crypto:derive_finished_key(Cipher, TrafficSecret),
    ExpectedVerifyData = quic_crypto:compute_finished_verify(Cipher, FinishedKey, TranscriptHash),
    crypto:hash_equals(ReceivedVerifyData, ExpectedVerifyData).

%%====================================================================
%% Transport Parameters
%%====================================================================

%% @doc Encode QUIC transport parameters.
%% Params is a map with keys like:
%%   original_dcid, max_idle_timeout, max_udp_payload_size,
%%   initial_max_data, initial_max_stream_data_bidi_local, etc.
-spec encode_transport_params(map()) -> binary().
encode_transport_params(Params) ->
    Encoded = maps:fold(fun(Key, Value, Acc) ->
        case encode_transport_param(Key, Value) of
            <<>> -> Acc;
            Bin -> [Bin | Acc]
        end
    end, [], Params),
    iolist_to_binary(lists:reverse(Encoded)).

encode_transport_param(original_dcid, Value) ->
    encode_tp(?TP_ORIGINAL_DCID, Value);
encode_transport_param(max_idle_timeout, Value) ->
    encode_tp(?TP_MAX_IDLE_TIMEOUT, quic_varint:encode(Value));
encode_transport_param(max_udp_payload_size, Value) ->
    encode_tp(?TP_MAX_UDP_PAYLOAD_SIZE, quic_varint:encode(Value));
encode_transport_param(initial_max_data, Value) ->
    encode_tp(?TP_INITIAL_MAX_DATA, quic_varint:encode(Value));
encode_transport_param(initial_max_stream_data_bidi_local, Value) ->
    encode_tp(?TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, quic_varint:encode(Value));
encode_transport_param(initial_max_stream_data_bidi_remote, Value) ->
    encode_tp(?TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, quic_varint:encode(Value));
encode_transport_param(initial_max_stream_data_uni, Value) ->
    encode_tp(?TP_INITIAL_MAX_STREAM_DATA_UNI, quic_varint:encode(Value));
encode_transport_param(initial_max_streams_bidi, Value) ->
    encode_tp(?TP_INITIAL_MAX_STREAMS_BIDI, quic_varint:encode(Value));
encode_transport_param(initial_max_streams_uni, Value) ->
    encode_tp(?TP_INITIAL_MAX_STREAMS_UNI, quic_varint:encode(Value));
encode_transport_param(ack_delay_exponent, Value) ->
    encode_tp(?TP_ACK_DELAY_EXPONENT, quic_varint:encode(Value));
encode_transport_param(max_ack_delay, Value) ->
    encode_tp(?TP_MAX_ACK_DELAY, quic_varint:encode(Value));
encode_transport_param(disable_active_migration, true) ->
    encode_tp(?TP_DISABLE_ACTIVE_MIGRATION, <<>>);
encode_transport_param(active_connection_id_limit, Value) ->
    encode_tp(?TP_ACTIVE_CONNECTION_ID_LIMIT, quic_varint:encode(Value));
encode_transport_param(initial_scid, Value) ->
    encode_tp(?TP_INITIAL_SCID, Value);
encode_transport_param(_, _) ->
    <<>>.

encode_tp(Id, Value) ->
    IdBin = quic_varint:encode(Id),
    LenBin = quic_varint:encode(byte_size(Value)),
    <<IdBin/binary, LenBin/binary, Value/binary>>.

%% @doc Decode QUIC transport parameters.
-spec decode_transport_params(binary()) -> {ok, map()} | {error, term()}.
decode_transport_params(Data) ->
    decode_transport_params(Data, #{}).

decode_transport_params(<<>>, Acc) ->
    {ok, Acc};
decode_transport_params(Data, Acc) ->
    {Id, Rest1} = quic_varint:decode(Data),
    {Len, Rest2} = quic_varint:decode(Rest1),
    <<Value:Len/binary, Rest3/binary>> = Rest2,
    Key = tp_id_to_key(Id),
    DecodedValue = decode_tp_value(Id, Value),
    decode_transport_params(Rest3, maps:put(Key, DecodedValue, Acc)).

tp_id_to_key(?TP_ORIGINAL_DCID) -> original_dcid;
tp_id_to_key(?TP_MAX_IDLE_TIMEOUT) -> max_idle_timeout;
tp_id_to_key(?TP_STATELESS_RESET_TOKEN) -> stateless_reset_token;
tp_id_to_key(?TP_MAX_UDP_PAYLOAD_SIZE) -> max_udp_payload_size;
tp_id_to_key(?TP_INITIAL_MAX_DATA) -> initial_max_data;
tp_id_to_key(?TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL) -> initial_max_stream_data_bidi_local;
tp_id_to_key(?TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE) -> initial_max_stream_data_bidi_remote;
tp_id_to_key(?TP_INITIAL_MAX_STREAM_DATA_UNI) -> initial_max_stream_data_uni;
tp_id_to_key(?TP_INITIAL_MAX_STREAMS_BIDI) -> initial_max_streams_bidi;
tp_id_to_key(?TP_INITIAL_MAX_STREAMS_UNI) -> initial_max_streams_uni;
tp_id_to_key(?TP_ACK_DELAY_EXPONENT) -> ack_delay_exponent;
tp_id_to_key(?TP_MAX_ACK_DELAY) -> max_ack_delay;
tp_id_to_key(?TP_DISABLE_ACTIVE_MIGRATION) -> disable_active_migration;
tp_id_to_key(?TP_PREFERRED_ADDRESS) -> preferred_address;
tp_id_to_key(?TP_ACTIVE_CONNECTION_ID_LIMIT) -> active_connection_id_limit;
tp_id_to_key(?TP_INITIAL_SCID) -> initial_scid;
tp_id_to_key(?TP_RETRY_SCID) -> retry_scid;
tp_id_to_key(Id) -> {unknown, Id}.

decode_tp_value(?TP_ORIGINAL_DCID, Value) -> Value;
decode_tp_value(?TP_STATELESS_RESET_TOKEN, Value) -> Value;
decode_tp_value(?TP_INITIAL_SCID, Value) -> Value;
decode_tp_value(?TP_RETRY_SCID, Value) -> Value;
decode_tp_value(?TP_DISABLE_ACTIVE_MIGRATION, <<>>) -> true;
decode_tp_value(?TP_PREFERRED_ADDRESS, Value) -> Value;
decode_tp_value(_, Value) ->
    %% Most parameters are varints
    {Int, _} = quic_varint:decode(Value),
    Int.

%%====================================================================
%% TLS Message Framing
%%====================================================================

%% @doc Encode a TLS handshake message with type and length.
-spec encode_handshake_message(non_neg_integer(), binary()) -> binary().
encode_handshake_message(Type, Body) ->
    Length = byte_size(Body),
    <<Type:8, Length:24, Body/binary>>.

%% @doc Decode a TLS handshake message.
%% Returns {Type, Body, Rest} or {error, Reason}.
-spec decode_handshake_message(binary()) ->
    {ok, {non_neg_integer(), binary()}, binary()} |
    {error, term()}.
decode_handshake_message(<<Type:8, Length:24, Body:Length/binary, Rest/binary>>) ->
    {ok, {Type, Body}, Rest};
decode_handshake_message(<<_Type:8, Length:24, Data/binary>>) when byte_size(Data) < Length ->
    {error, incomplete};
decode_handshake_message(_) ->
    {error, invalid}.

%%====================================================================
%% Internal Functions
%%====================================================================

encode_extension(Type, Data) ->
    <<Type:16, (byte_size(Data)):16, Data/binary>>.

parse_extensions(Data) ->
    parse_extensions(Data, #{}).

parse_extensions(<<>>, Acc) ->
    {ok, Acc};
parse_extensions(<<Type:16, Len:16, Data:Len/binary, Rest/binary>>, Acc) ->
    parse_extensions(Rest, maps:put(Type, Data, Acc));
parse_extensions(_, _) ->
    {error, invalid_extensions}.

parse_server_key_share(<<?GROUP_X25519:16, 32:16, PubKey:32/binary, _/binary>>) ->
    {ok, PubKey};
parse_server_key_share(<<?GROUP_SECP256R1:16, Len:16, PubKey:Len/binary, _/binary>>) ->
    {ok, PubKey};
parse_server_key_share(_) ->
    {error, unsupported_key_share}.

cipher_from_suite(?TLS_AES_128_GCM_SHA256) -> aes_128_gcm;
cipher_from_suite(?TLS_AES_256_GCM_SHA384) -> aes_256_gcm;
cipher_from_suite(?TLS_CHACHA20_POLY1305_SHA256) -> chacha20_poly1305;
cipher_from_suite(_) -> aes_128_gcm.
