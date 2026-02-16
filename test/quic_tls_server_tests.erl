%%% -*- erlang -*-
%%%
%%% Tests for QUIC Server TLS Functions
%%% RFC 9001 Section 4.1 - TLS Handshake
%%%

-module(quic_tls_server_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% ServerHello Building Tests
%%====================================================================

build_server_hello_basic_test() ->
    {PubKey, _PrivKey} = quic_crypto:generate_key_pair(x25519),
    SessionId = <<>>,

    {ServerHello, ServerRandom} = quic_tls:build_server_hello(#{
        cipher => aes_128_gcm,
        public_key => PubKey,
        session_id => SessionId
    }),

    %% Check it's a valid TLS handshake message
    <<Type, Len:24, _Body/binary>> = ServerHello,
    ?assertEqual(?TLS_SERVER_HELLO, Type),
    ?assertEqual(byte_size(ServerHello) - 4, Len),
    ?assertEqual(32, byte_size(ServerRandom)).

build_server_hello_aes_256_test() ->
    {PubKey, _PrivKey} = quic_crypto:generate_key_pair(x25519),

    {ServerHello, _} = quic_tls:build_server_hello(#{
        cipher => aes_256_gcm,
        public_key => PubKey,
        session_id => <<>>
    }),

    <<Type, _/binary>> = ServerHello,
    ?assertEqual(?TLS_SERVER_HELLO, Type).

build_server_hello_chacha_test() ->
    {PubKey, _PrivKey} = quic_crypto:generate_key_pair(x25519),

    {ServerHello, _} = quic_tls:build_server_hello(#{
        cipher => chacha20_poly1305,
        public_key => PubKey,
        session_id => <<>>
    }),

    <<Type, _/binary>> = ServerHello,
    ?assertEqual(?TLS_SERVER_HELLO, Type).

build_server_hello_with_session_id_test() ->
    {PubKey, _PrivKey} = quic_crypto:generate_key_pair(x25519),
    SessionId = crypto:strong_rand_bytes(32),

    {ServerHello, _} = quic_tls:build_server_hello(#{
        cipher => aes_128_gcm,
        public_key => PubKey,
        session_id => SessionId
    }),

    %% ServerHello should include the echoed session ID
    ?assert(byte_size(ServerHello) > 0).

%%====================================================================
%% EncryptedExtensions Tests
%%====================================================================

build_encrypted_extensions_basic_test() ->
    EncExt = quic_tls:build_encrypted_extensions(#{
        alpn => <<"h3">>,
        transport_params => #{
            initial_scid => crypto:strong_rand_bytes(8),
            initial_max_data => 1000000,
            initial_max_stream_data_bidi_local => 100000,
            initial_max_stream_data_bidi_remote => 100000,
            initial_max_stream_data_uni => 100000,
            initial_max_streams_bidi => 100,
            initial_max_streams_uni => 100
        }
    }),

    <<Type, _/binary>> = EncExt,
    ?assertEqual(?TLS_ENCRYPTED_EXTENSIONS, Type).

build_encrypted_extensions_no_alpn_test() ->
    EncExt = quic_tls:build_encrypted_extensions(#{
        transport_params => #{
            initial_scid => crypto:strong_rand_bytes(8)
        }
    }),

    <<Type, _/binary>> = EncExt,
    ?assertEqual(?TLS_ENCRYPTED_EXTENSIONS, Type).

%%====================================================================
%% Certificate Building Tests
%%====================================================================

build_certificate_single_cert_test() ->
    %% Simplified test cert
    Cert = crypto:strong_rand_bytes(256),
    CertMsg = quic_tls:build_certificate(<<>>, [Cert]),

    <<Type, _/binary>> = CertMsg,
    ?assertEqual(?TLS_CERTIFICATE, Type).

build_certificate_chain_test() ->
    Cert = crypto:strong_rand_bytes(256),
    IntCert = crypto:strong_rand_bytes(256),
    RootCert = crypto:strong_rand_bytes(256),

    CertMsg = quic_tls:build_certificate(<<>>, [Cert, IntCert, RootCert]),

    <<Type, _/binary>> = CertMsg,
    ?assertEqual(?TLS_CERTIFICATE, Type).

build_certificate_with_context_test() ->
    Cert = crypto:strong_rand_bytes(256),
    Context = <<1, 2, 3, 4>>,

    CertMsg = quic_tls:build_certificate(Context, [Cert]),

    <<Type, _/binary>> = CertMsg,
    ?assertEqual(?TLS_CERTIFICATE, Type).

%%====================================================================
%% Full ServerHello Roundtrip Tests
%%====================================================================

server_hello_roundtrip_test() ->
    {PubKey, _PrivKey} = quic_crypto:generate_key_pair(x25519),

    {ServerHello, _} = quic_tls:build_server_hello(#{
        cipher => aes_128_gcm,
        public_key => PubKey,
        session_id => <<>>
    }),

    %% Parse it back
    <<_Type, _Len:24, Body/binary>> = ServerHello,
    {ok, Parsed} = quic_tls:parse_server_hello(Body),

    %% Check that we got the expected cipher
    ?assertEqual(aes_128_gcm, maps:get(cipher, Parsed)),
    %% Check that we got a 32-byte public key
    ParsedPubKey = maps:get(public_key, Parsed),
    ?assertEqual(32, byte_size(ParsedPubKey)).
