%%% -*- erlang -*-
%%%
%%% QUIC Key Derivation
%%% RFC 9001 Section 5 - Packet Protection
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC key derivation for packet protection.
%%%
%%% This module derives the cryptographic keys used for QUIC packet
%%% protection at each encryption level (Initial, Handshake, Application).
%%%
%%% == Initial Keys ==
%%%
%%% Initial keys are derived from the Destination Connection ID using
%%% a fixed salt defined in RFC 9001.
%%%
%%% == Key Derivation ==
%%%
%%% Keys are derived using HKDF-Expand-Label with the following labels:
%%% - "quic key" for the AEAD key
%%% - "quic iv" for the AEAD IV/nonce
%%% - "quic hp" for header protection key
%%%

-module(quic_keys).

-include("quic.hrl").

-export([
    derive_initial_secret/1,
    derive_initial_secret/2,
    derive_initial_client/1,
    derive_initial_client/2,
    derive_initial_server/1,
    derive_initial_server/2,
    derive_keys/2,
    derive_traffic_keys/1
]).

-export_type([keys/0]).

-type keys() :: {Key :: binary(), IV :: binary(), HP :: binary()}.

%%====================================================================
%% API
%%====================================================================

%% @doc Derive the initial secret from DCID using QUIC v1 salt.
-spec derive_initial_secret(binary()) -> binary().
derive_initial_secret(DCID) ->
    derive_initial_secret(DCID, ?QUIC_VERSION_1).

%% @doc Derive the initial secret from DCID.
%% Version determines which salt to use.
-spec derive_initial_secret(binary(), non_neg_integer()) -> binary().
derive_initial_secret(DCID, Version) ->
    Salt = initial_salt(Version),
    quic_hkdf:extract(Salt, DCID).

%% @doc Derive initial client keys from DCID.
%% Returns {Key, IV, HP} for client Initial packets.
-spec derive_initial_client(binary()) -> keys().
derive_initial_client(DCID) ->
    derive_initial_client(DCID, ?QUIC_VERSION_1).

%% @doc Derive initial client keys from DCID with version.
-spec derive_initial_client(binary(), non_neg_integer()) -> keys().
derive_initial_client(DCID, Version) ->
    InitialSecret = derive_initial_secret(DCID, Version),
    ClientSecret = quic_hkdf:expand_label(InitialSecret, ?QUIC_LABEL_CLIENT_IN, <<>>, 32),
    derive_traffic_keys(ClientSecret).

%% @doc Derive initial server keys from DCID.
%% Returns {Key, IV, HP} for server Initial packets.
-spec derive_initial_server(binary()) -> keys().
derive_initial_server(DCID) ->
    derive_initial_server(DCID, ?QUIC_VERSION_1).

%% @doc Derive initial server keys from DCID with version.
-spec derive_initial_server(binary(), non_neg_integer()) -> keys().
derive_initial_server(DCID, Version) ->
    InitialSecret = derive_initial_secret(DCID, Version),
    ServerSecret = quic_hkdf:expand_label(InitialSecret, ?QUIC_LABEL_SERVER_IN, <<>>, 32),
    derive_traffic_keys(ServerSecret).

%% @doc Derive keys from a traffic secret.
%% Returns {Key, IV, HP} for the given secret.
-spec derive_keys(binary(), aes_128_gcm | aes_256_gcm | chacha20_poly1305) -> keys().
derive_keys(Secret, aes_128_gcm) ->
    Key = quic_hkdf:expand_label(Secret, ?QUIC_LABEL_QUIC_KEY, <<>>, 16),
    IV = quic_hkdf:expand_label(Secret, ?QUIC_LABEL_QUIC_IV, <<>>, 12),
    HP = quic_hkdf:expand_label(Secret, ?QUIC_LABEL_QUIC_HP, <<>>, 16),
    {Key, IV, HP};
derive_keys(Secret, aes_256_gcm) ->
    Key = quic_hkdf:expand_label(Secret, ?QUIC_LABEL_QUIC_KEY, <<>>, 32),
    IV = quic_hkdf:expand_label(Secret, ?QUIC_LABEL_QUIC_IV, <<>>, 12),
    HP = quic_hkdf:expand_label(Secret, ?QUIC_LABEL_QUIC_HP, <<>>, 32),
    {Key, IV, HP};
derive_keys(Secret, chacha20_poly1305) ->
    Key = quic_hkdf:expand_label(Secret, ?QUIC_LABEL_QUIC_KEY, <<>>, 32),
    IV = quic_hkdf:expand_label(Secret, ?QUIC_LABEL_QUIC_IV, <<>>, 12),
    HP = quic_hkdf:expand_label(Secret, ?QUIC_LABEL_QUIC_HP, <<>>, 32),
    {Key, IV, HP}.

%% @doc Derive traffic keys (Key, IV, HP) from a traffic secret.
%% Uses AES-128-GCM key sizes (16-byte key, 12-byte IV, 16-byte HP).
%% This is used for Initial and Handshake encryption levels.
-spec derive_traffic_keys(binary()) -> keys().
derive_traffic_keys(Secret) ->
    derive_keys(Secret, aes_128_gcm).

%%====================================================================
%% Internal Functions
%%====================================================================

%% Get the initial salt for a QUIC version
initial_salt(?QUIC_VERSION_1) ->
    ?QUIC_V1_INITIAL_SALT;
initial_salt(?QUIC_VERSION_2) ->
    ?QUIC_V2_INITIAL_SALT;
initial_salt(_) ->
    %% Default to v1 salt for unknown versions
    ?QUIC_V1_INITIAL_SALT.
