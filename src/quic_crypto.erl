%%% -*- erlang -*-
%%%
%%% QUIC TLS 1.3 Cryptographic Operations
%%% RFC 8446 - TLS 1.3
%%% RFC 9001 - Using TLS to Secure QUIC
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc TLS 1.3 key schedule and cryptographic operations for QUIC.
%%%
%%% This module implements the TLS 1.3 key schedule used by QUIC for
%%% deriving encryption keys at each handshake stage.
%%%
%%% == Key Schedule ==
%%%
%%% TLS 1.3 uses a three-stage key schedule:
%%% 1. Early Secret (from PSK, or zeros for non-PSK)
%%% 2. Handshake Secret (from ECDHE shared secret)
%%% 3. Master Secret (for application data)
%%%
%%% == Traffic Secrets ==
%%%
%%% From each secret, traffic secrets are derived for both client and
%%% server directions.
%%%

-module(quic_crypto).

-export([
    %% Key Schedule
    derive_early_secret/0,
    derive_early_secret/1,
    derive_handshake_secret/2,
    derive_master_secret/1,

    %% Traffic Secrets
    derive_client_handshake_secret/2,
    derive_server_handshake_secret/2,
    derive_client_app_secret/2,
    derive_server_app_secret/2,

    %% Derive-Secret function
    derive_secret/3,
    derive_secret/4,

    %% Finished key and verify data
    derive_finished_key/1,
    compute_finished_verify/2,

    %% Transcript hash
    transcript_hash/1,

    %% ECDHE
    generate_key_pair/1,
    compute_shared_secret/3
]).

%% Hash length for SHA-256
-define(HASH_LEN, 32).

%%====================================================================
%% Key Schedule (RFC 8446 Section 7.1)
%%====================================================================

%% @doc Derive early secret without PSK (zeros).
%% early_secret = HKDF-Extract(0, 0)
-spec derive_early_secret() -> binary().
derive_early_secret() ->
    derive_early_secret(<<0:?HASH_LEN/unit:8>>).

%% @doc Derive early secret with PSK.
%% early_secret = HKDF-Extract(0, PSK)
-spec derive_early_secret(binary()) -> binary().
derive_early_secret(PSK) ->
    %% Salt is all zeros
    Salt = <<0:?HASH_LEN/unit:8>>,
    quic_hkdf:extract(Salt, PSK).

%% @doc Derive handshake secret from early secret and ECDHE shared secret.
%% handshake_secret = HKDF-Extract(
%%     Derive-Secret(early_secret, "derived", ""),
%%     shared_secret)
-spec derive_handshake_secret(binary(), binary()) -> binary().
derive_handshake_secret(EarlySecret, SharedSecret) ->
    Salt = derive_secret(EarlySecret, <<"derived">>, <<>>),
    quic_hkdf:extract(Salt, SharedSecret).

%% @doc Derive master secret from handshake secret.
%% master_secret = HKDF-Extract(
%%     Derive-Secret(handshake_secret, "derived", ""),
%%     0)
-spec derive_master_secret(binary()) -> binary().
derive_master_secret(HandshakeSecret) ->
    Salt = derive_secret(HandshakeSecret, <<"derived">>, <<>>),
    IKM = <<0:?HASH_LEN/unit:8>>,
    quic_hkdf:extract(Salt, IKM).

%%====================================================================
%% Traffic Secrets (RFC 8446 Section 7.1)
%%====================================================================

%% @doc Derive client handshake traffic secret.
%% client_handshake_traffic_secret = Derive-Secret(
%%     handshake_secret, "c hs traffic", ClientHello...ServerHello)
-spec derive_client_handshake_secret(binary(), binary()) -> binary().
derive_client_handshake_secret(HandshakeSecret, TranscriptHash) ->
    derive_secret(HandshakeSecret, <<"c hs traffic">>, TranscriptHash).

%% @doc Derive server handshake traffic secret.
%% server_handshake_traffic_secret = Derive-Secret(
%%     handshake_secret, "s hs traffic", ClientHello...ServerHello)
-spec derive_server_handshake_secret(binary(), binary()) -> binary().
derive_server_handshake_secret(HandshakeSecret, TranscriptHash) ->
    derive_secret(HandshakeSecret, <<"s hs traffic">>, TranscriptHash).

%% @doc Derive client application traffic secret.
%% client_application_traffic_secret_0 = Derive-Secret(
%%     master_secret, "c ap traffic", ClientHello...server Finished)
-spec derive_client_app_secret(binary(), binary()) -> binary().
derive_client_app_secret(MasterSecret, TranscriptHash) ->
    derive_secret(MasterSecret, <<"c ap traffic">>, TranscriptHash).

%% @doc Derive server application traffic secret.
%% server_application_traffic_secret_0 = Derive-Secret(
%%     master_secret, "s ap traffic", ClientHello...server Finished)
-spec derive_server_app_secret(binary(), binary()) -> binary().
derive_server_app_secret(MasterSecret, TranscriptHash) ->
    derive_secret(MasterSecret, <<"s ap traffic">>, TranscriptHash).

%%====================================================================
%% Derive-Secret Function
%%====================================================================

%% @doc Derive-Secret with raw messages (will be hashed).
%% Derive-Secret(Secret, Label, Messages) =
%%     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
-spec derive_secret(binary(), binary(), binary()) -> binary().
derive_secret(Secret, Label, Messages) ->
    derive_secret(sha256, Secret, Label, Messages).

%% @doc Derive-Secret with specified hash algorithm.
-spec derive_secret(atom(), binary(), binary(), binary()) -> binary().
derive_secret(Hash, Secret, Label, Messages) ->
    HashLen = hash_len(Hash),
    %% If Messages is already hash-length, assume it's pre-hashed
    Context = case byte_size(Messages) of
        HashLen -> Messages;
        _ -> transcript_hash(Messages)
    end,
    quic_hkdf:expand_label(Hash, Secret, Label, Context, HashLen).

%%====================================================================
%% Finished Key and Verify Data (RFC 8446 Section 4.4.4)
%%====================================================================

%% @doc Derive the finished key from a traffic secret.
%% finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
-spec derive_finished_key(binary()) -> binary().
derive_finished_key(TrafficSecret) ->
    quic_hkdf:expand_label(TrafficSecret, <<"finished">>, <<>>, ?HASH_LEN).

%% @doc Compute the Finished verify_data.
%% verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
-spec compute_finished_verify(binary(), binary()) -> binary().
compute_finished_verify(FinishedKey, TranscriptHash) ->
    crypto:mac(hmac, sha256, FinishedKey, TranscriptHash).

%%====================================================================
%% Transcript Hash
%%====================================================================

%% @doc Compute transcript hash of handshake messages.
-spec transcript_hash(binary()) -> binary().
transcript_hash(Messages) ->
    crypto:hash(sha256, Messages).

%%====================================================================
%% ECDHE Key Exchange
%%====================================================================

%% @doc Generate an ECDHE key pair for the specified curve.
%% Returns {PublicKey, PrivateKey}
-spec generate_key_pair(x25519 | x448 | secp256r1 | secp384r1) ->
    {binary(), binary()}.
generate_key_pair(Curve) ->
    {PubKey, PrivKey} = crypto:generate_key(ecdh, Curve),
    {PubKey, PrivKey}.

%% @doc Compute ECDHE shared secret.
%% shared_secret = ECDH(our_private, their_public)
-spec compute_shared_secret(x25519 | x448 | secp256r1 | secp384r1,
                            binary(), binary()) -> binary().
compute_shared_secret(Curve, OurPrivate, TheirPublic) ->
    crypto:compute_key(ecdh, TheirPublic, OurPrivate, Curve).

%%====================================================================
%% Internal Functions
%%====================================================================

hash_len(sha256) -> 32;
hash_len(sha384) -> 48;
hash_len(sha512) -> 64.
