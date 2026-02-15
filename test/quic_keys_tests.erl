%%% -*- erlang -*-
%%%
%%% Tests for QUIC Key Derivation
%%% RFC 9001 Appendix A Test Vectors
%%%

-module(quic_keys_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% RFC 9001 Appendix A.1 - Initial Secrets
%%====================================================================

%% Test vector from RFC 9001 Appendix A.1
%% DCID = 0x8394c8f03e515708
%% Initial Secret = 7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44
%% client_initial_secret = c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea
%% server_initial_secret = 3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b

rfc9001_initial_secret_test() ->
    DCID = hexstr_to_bin("8394c8f03e515708"),
    Expected = hexstr_to_bin("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"),
    InitialSecret = quic_keys:derive_initial_secret(DCID),
    ?assertEqual(Expected, InitialSecret).

rfc9001_client_initial_secret_test() ->
    DCID = hexstr_to_bin("8394c8f03e515708"),
    InitialSecret = quic_keys:derive_initial_secret(DCID),
    ExpectedClientSecret = hexstr_to_bin("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
    ClientSecret = quic_hkdf:expand_label(InitialSecret, <<"client in">>, <<>>, 32),
    ?assertEqual(ExpectedClientSecret, ClientSecret).

rfc9001_server_initial_secret_test() ->
    DCID = hexstr_to_bin("8394c8f03e515708"),
    InitialSecret = quic_keys:derive_initial_secret(DCID),
    ExpectedServerSecret = hexstr_to_bin("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"),
    ServerSecret = quic_hkdf:expand_label(InitialSecret, <<"server in">>, <<>>, 32),
    ?assertEqual(ExpectedServerSecret, ServerSecret).

%%====================================================================
%% RFC 9001 Appendix A.1 - Client Initial Keys
%%====================================================================

%% From the client_initial_secret, derive:
%% key = 1f369613dd76d5467730efcbe3b1a22d
%% iv = fa044b2f42a3fd3b46fb255c
%% hp = 9f50449e04a0e810283a1e9933adedd2

rfc9001_client_initial_keys_test() ->
    DCID = hexstr_to_bin("8394c8f03e515708"),
    ExpectedKey = hexstr_to_bin("1f369613dd76d5467730efcbe3b1a22d"),
    ExpectedIV = hexstr_to_bin("fa044b2f42a3fd3b46fb255c"),
    ExpectedHP = hexstr_to_bin("9f50449e04a0e810283a1e9933adedd2"),

    {Key, IV, HP} = quic_keys:derive_initial_client(DCID),

    ?assertEqual(ExpectedKey, Key),
    ?assertEqual(ExpectedIV, IV),
    ?assertEqual(ExpectedHP, HP).

%%====================================================================
%% RFC 9001 Appendix A.1 - Server Initial Keys
%%====================================================================

%% From the server_initial_secret, derive:
%% key = cf3a5331653c364c88f0f379b6067e37
%% iv = 0ac1493ca1905853b0bba03e
%% hp = c206b8d9b9f0f37644430b490eeaa314

rfc9001_server_initial_keys_test() ->
    DCID = hexstr_to_bin("8394c8f03e515708"),
    ExpectedKey = hexstr_to_bin("cf3a5331653c364c88f0f379b6067e37"),
    ExpectedIV = hexstr_to_bin("0ac1493ca1905853b0bba03e"),
    ExpectedHP = hexstr_to_bin("c206b8d9b9f0f37644430b490eeaa314"),

    {Key, IV, HP} = quic_keys:derive_initial_server(DCID),

    ?assertEqual(ExpectedKey, Key),
    ?assertEqual(ExpectedIV, IV),
    ?assertEqual(ExpectedHP, HP).

%%====================================================================
%% Key Size Tests
%%====================================================================

aes_128_gcm_key_sizes_test() ->
    Secret = crypto:strong_rand_bytes(32),
    {Key, IV, HP} = quic_keys:derive_keys(Secret, aes_128_gcm),
    ?assertEqual(16, byte_size(Key)),
    ?assertEqual(12, byte_size(IV)),
    ?assertEqual(16, byte_size(HP)).

aes_256_gcm_key_sizes_test() ->
    Secret = crypto:strong_rand_bytes(32),
    {Key, IV, HP} = quic_keys:derive_keys(Secret, aes_256_gcm),
    ?assertEqual(32, byte_size(Key)),
    ?assertEqual(12, byte_size(IV)),
    ?assertEqual(32, byte_size(HP)).

chacha20_poly1305_key_sizes_test() ->
    Secret = crypto:strong_rand_bytes(32),
    {Key, IV, HP} = quic_keys:derive_keys(Secret, chacha20_poly1305),
    ?assertEqual(32, byte_size(Key)),
    ?assertEqual(12, byte_size(IV)),
    ?assertEqual(32, byte_size(HP)).

%%====================================================================
%% Consistency Tests
%%====================================================================

derive_initial_deterministic_test() ->
    DCID = crypto:strong_rand_bytes(8),
    Keys1 = quic_keys:derive_initial_client(DCID),
    Keys2 = quic_keys:derive_initial_client(DCID),
    ?assertEqual(Keys1, Keys2).

different_dcid_different_keys_test() ->
    DCID1 = <<1,2,3,4,5,6,7,8>>,
    DCID2 = <<8,7,6,5,4,3,2,1>>,
    Keys1 = quic_keys:derive_initial_client(DCID1),
    Keys2 = quic_keys:derive_initial_client(DCID2),
    ?assertNotEqual(Keys1, Keys2).

client_server_different_keys_test() ->
    DCID = crypto:strong_rand_bytes(8),
    ClientKeys = quic_keys:derive_initial_client(DCID),
    ServerKeys = quic_keys:derive_initial_server(DCID),
    ?assertNotEqual(ClientKeys, ServerKeys).

%%====================================================================
%% QUIC Version Tests
%%====================================================================

quic_v1_salt_test() ->
    DCID = <<1,2,3,4,5,6,7,8>>,
    %% Should use v1 salt
    Keys1 = quic_keys:derive_initial_client(DCID, ?QUIC_VERSION_1),
    Keys2 = quic_keys:derive_initial_client(DCID),
    ?assertEqual(Keys1, Keys2).

quic_v2_different_from_v1_test() ->
    DCID = <<1,2,3,4,5,6,7,8>>,
    KeysV1 = quic_keys:derive_initial_client(DCID, ?QUIC_VERSION_1),
    KeysV2 = quic_keys:derive_initial_client(DCID, ?QUIC_VERSION_2),
    ?assertNotEqual(KeysV1, KeysV2).

%%====================================================================
%% Helper Functions
%%====================================================================

hexstr_to_bin(HexStr) ->
    hexstr_to_bin(HexStr, <<>>).

hexstr_to_bin([], Acc) ->
    Acc;
hexstr_to_bin([H1, H2 | Rest], Acc) ->
    Byte = list_to_integer([H1, H2], 16),
    hexstr_to_bin(Rest, <<Acc/binary, Byte>>).
