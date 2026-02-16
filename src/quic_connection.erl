%%% -*- erlang -*-
%%%
%%% QUIC Connection State Machine
%%% RFC 9000 - QUIC Transport
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC connection state machine implemented as gen_statem.
%%%
%%% This module manages the lifecycle of a QUIC connection, handling:
%%% - TLS 1.3 handshake via CRYPTO frames
%%% - Packet encryption/decryption at each level
%%% - Stream management
%%% - Flow control
%%% - Timer management
%%%
%%% == Connection States ==
%%%
%%% idle -> handshaking -> connected -> draining -> closed
%%%
%%% == Messages to Owner ==
%%%
%%% {quic, ConnRef, {connected, Info}}
%%% {quic, ConnRef, {stream_headers, StreamId, Headers, Fin}}
%%% {quic, ConnRef, {stream_data, StreamId, Data, Fin}}
%%% {quic, ConnRef, {stream_opened, StreamId}}
%%% {quic, ConnRef, {closed, Reason}}
%%%

-module(quic_connection).

-behaviour(gen_statem).

-include("quic.hrl").

%% Registry API
-export([
    register_conn/2,
    unregister_conn/1,
    lookup/1
]).

%% API
-export([
    start_link/4,
    start_link/5,
    connect/4,
    send_data/4,
    send_headers/4,
    open_stream/1,
    open_unidirectional_stream/1,
    close/2,
    close_stream/3,
    reset_stream/3,
    handle_timeout/1,
    process/1,
    get_state/1,
    peername/1,
    sockname/1,
    setopts/2,
    %% Key update (RFC 9001 Section 6)
    key_update/1
]).

%% gen_statem callbacks
-export([
    init/1,
    callback_mode/0,
    terminate/3,
    code_change/4
]).

%% State functions
-export([
    idle/3,
    handshaking/3,
    connected/3,
    draining/3,
    closed/3
]).

%% Registry table name
-define(REGISTRY, quic_connection_registry).

%% TLS handshake states
-define(TLS_AWAITING_SERVER_HELLO, awaiting_server_hello).
-define(TLS_AWAITING_ENCRYPTED_EXT, awaiting_encrypted_extensions).
-define(TLS_AWAITING_CERT, awaiting_certificate).
-define(TLS_AWAITING_CERT_VERIFY, awaiting_certificate_verify).
-define(TLS_AWAITING_FINISHED, awaiting_finished).
-define(TLS_HANDSHAKE_COMPLETE, handshake_complete).

%% Connection state record
-record(state, {
    %% Connection identity
    scid :: binary(),
    dcid :: binary(),
    original_dcid :: binary(),
    role :: client | server,
    version = ?QUIC_VERSION_1 :: non_neg_integer(),

    %% Socket
    socket :: gen_udp:socket() | undefined,
    remote_addr :: {inet:ip_address(), inet:port_number()},
    local_addr :: {inet:ip_address(), inet:port_number()} | undefined,

    %% Owner process (receives {quic, Ref, Event} messages)
    owner :: pid(),
    conn_ref :: reference(),

    %% Options
    server_name :: binary() | undefined,
    verify :: boolean(),

    %% Encryption keys per level
    initial_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,
    handshake_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,
    app_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,  % Convenience accessor (= key_state.current_keys)

    %% Key update state (RFC 9001 Section 6)
    key_state :: #key_update_state{} | undefined,

    %% TLS state
    tls_state :: atom(),
    tls_private_key :: binary() | undefined,
    tls_transcript = <<>> :: binary(),
    handshake_secret :: binary() | undefined,
    master_secret :: binary() | undefined,
    server_hs_secret :: binary() | undefined,
    client_hs_secret :: binary() | undefined,

    %% CRYPTO frame buffer (per level: initial, handshake, app)
    crypto_buffer = #{initial => #{}, handshake => #{}, app => #{}} :: map(),
    crypto_offset = #{initial => 0, handshake => 0, app => 0} :: map(),
    %% Incomplete TLS message buffer (data that couldn't be parsed yet)
    tls_buffer = #{initial => <<>>, handshake => <<>>, app => <<>>} :: map(),

    %% Negotiated ALPN
    alpn :: binary() | undefined,
    alpn_list :: [binary()],

    %% Packet number spaces
    pn_initial :: #pn_space{},
    pn_handshake :: #pn_space{},
    pn_app :: #pn_space{},

    %% Flow control
    max_data_local :: non_neg_integer(),
    max_data_remote :: non_neg_integer(),
    data_sent = 0 :: non_neg_integer(),
    data_received = 0 :: non_neg_integer(),

    %% Stream management
    streams = #{} :: #{non_neg_integer() => #stream_state{}},
    next_stream_id_bidi :: non_neg_integer(),
    next_stream_id_uni :: non_neg_integer(),
    max_streams_bidi_local :: non_neg_integer(),
    max_streams_bidi_remote :: non_neg_integer(),
    max_streams_uni_local :: non_neg_integer(),
    max_streams_uni_remote :: non_neg_integer(),

    %% Transport parameters (received from peer)
    transport_params = #{} :: map(),

    %% Timers
    idle_timeout :: non_neg_integer(),
    last_activity :: non_neg_integer(),
    timer_ref :: reference() | undefined,

    %% Congestion control and loss detection
    cc_state :: quic_cc:cc_state() | undefined,
    loss_state :: quic_loss:loss_state() | undefined,
    pto_timer :: reference() | undefined,

    %% Pending data
    send_queue = [] :: [term()],

    %% Close reason
    close_reason :: term(),

    %% Connection Migration (RFC 9000 Section 9)
    %% Current path (active remote address)
    current_path :: #path_state{} | undefined,
    %% Alternative paths being validated
    alt_paths = [] :: [#path_state{}],

    %% Connection ID Pool (RFC 9000 Section 5.1)
    %% Our CIDs that we've issued to the peer (via NEW_CONNECTION_ID)
    local_cid_pool = [] :: [#cid_entry{}],
    %% Next sequence number for our CIDs
    local_cid_seq = 1 :: non_neg_integer(),
    %% Peer's CIDs that we can use (received via NEW_CONNECTION_ID)
    peer_cid_pool = [] :: [#cid_entry{}],
    %% Active connection ID limit (from transport params)
    active_cid_limit = 2 :: non_neg_integer()
}).

%%====================================================================
%% Registry API
%%====================================================================

%% @doc Register a connection reference to a pid.
-spec register_conn(reference(), pid()) -> ok.
register_conn(ConnRef, Pid) ->
    ensure_registry(),
    ets:insert(?REGISTRY, {ConnRef, Pid}),
    ok.

%% @doc Unregister a connection reference.
-spec unregister_conn(reference()) -> ok.
unregister_conn(ConnRef) ->
    catch ets:delete(?REGISTRY, ConnRef),
    ok.

%% @doc Lookup a connection pid by reference.
-spec lookup(reference()) -> {ok, pid()} | error.
lookup(ConnRef) ->
    ensure_registry(),
    case ets:lookup(?REGISTRY, ConnRef) of
        [{_, Pid}] -> {ok, Pid};
        [] -> error
    end.

ensure_registry() ->
    case ets:whereis(?REGISTRY) of
        undefined ->
            try
                ets:new(?REGISTRY, [named_table, public, set, {read_concurrency, true}])
            catch
                error:badarg -> ok  % Already exists (race condition)
            end;
        _ ->
            ok
    end.

%%====================================================================
%% API
%%====================================================================

%% @doc Start a QUIC connection process.
-spec start_link(inet:hostname() | inet:ip_address(),
                 inet:port_number(),
                 map(),
                 pid()) -> {ok, pid()} | {error, term()}.
start_link(Host, Port, Opts, Owner) ->
    start_link(Host, Port, Opts, Owner, undefined).

%% @doc Start a QUIC connection with optional pre-opened socket.
-spec start_link(inet:hostname() | inet:ip_address(),
                 inet:port_number(),
                 map(),
                 pid(),
                 gen_udp:socket() | undefined) -> {ok, pid()} | {error, term()}.
start_link(Host, Port, Opts, Owner, Socket) ->
    gen_statem:start_link(?MODULE, [Host, Port, Opts, Owner, Socket], []).

%% @doc Initiate a connection to a QUIC server.
%% This is a convenience wrapper that starts the process and initiates handshake.
-spec connect(inet:hostname() | inet:ip_address(),
              inet:port_number(),
              map(),
              pid()) -> {ok, reference(), pid()} | {error, term()}.
connect(Host, Port, Opts, Owner) ->
    case start_link(Host, Port, Opts, Owner) of
        {ok, Pid} ->
            ConnRef = gen_statem:call(Pid, get_ref),
            {ok, ConnRef, Pid};
        Error ->
            Error
    end.

%% @doc Send data on a stream.
-spec send_data(pid(), non_neg_integer(), iodata(), boolean()) ->
    ok | {error, term()}.
send_data(Conn, StreamId, Data, Fin) ->
    gen_statem:call(Conn, {send_data, StreamId, Data, Fin}).

%% @doc Send headers on a stream (HTTP/3).
-spec send_headers(pid(), non_neg_integer(), [{binary(), binary()}], boolean()) ->
    ok | {error, term()}.
send_headers(Conn, StreamId, Headers, Fin) ->
    gen_statem:call(Conn, {send_headers, StreamId, Headers, Fin}).

%% @doc Open a new bidirectional stream.
-spec open_stream(pid()) -> {ok, non_neg_integer()} | {error, term()}.
open_stream(Conn) ->
    gen_statem:call(Conn, open_stream).

%% @doc Open a new unidirectional stream.
-spec open_unidirectional_stream(pid()) -> {ok, non_neg_integer()} | {error, term()}.
open_unidirectional_stream(Conn) ->
    gen_statem:call(Conn, open_unidirectional_stream).

%% @doc Close the connection.
-spec close(pid(), term()) -> ok.
close(Conn, Reason) ->
    gen_statem:cast(Conn, {close, Reason}).

%% @doc Close a specific stream.
-spec close_stream(pid(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
close_stream(Conn, StreamId, ErrorCode) ->
    gen_statem:call(Conn, {close_stream, StreamId, ErrorCode}).

%% @doc Reset a stream.
-spec reset_stream(pid(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
reset_stream(Conn, StreamId, ErrorCode) ->
    gen_statem:call(Conn, {close_stream, StreamId, ErrorCode}).

%% @doc Handle a timeout event.
-spec handle_timeout(pid()) -> ok.
handle_timeout(Conn) ->
    gen_statem:cast(Conn, handle_timeout).

%% @doc Process pending events (called when socket is ready).
-spec process(pid()) -> ok.
process(Conn) ->
    gen_statem:cast(Conn, process).

%% @doc Get current connection state (for debugging).
-spec get_state(pid()) -> {atom(), map()}.
get_state(Conn) ->
    gen_statem:call(Conn, get_state).

%% @doc Get remote address.
-spec peername(pid()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
peername(Conn) ->
    gen_statem:call(Conn, peername).

%% @doc Get local address.
-spec sockname(pid()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
sockname(Conn) ->
    gen_statem:call(Conn, sockname).

%% @doc Set connection options.
-spec setopts(pid(), [{atom(), term()}]) -> ok | {error, term()}.
setopts(Conn, Opts) ->
    gen_statem:call(Conn, {setopts, Opts}).

%% @doc Initiate a key update (RFC 9001 Section 6).
%% This triggers a key update cycle, deriving new encryption keys.
%% Only valid when connection is in connected state.
-spec key_update(pid()) -> ok | {error, term()}.
key_update(Conn) ->
    gen_statem:call(Conn, key_update).

%%====================================================================
%% gen_statem callbacks
%%====================================================================

callback_mode() ->
    [state_functions, state_enter].

init([Host, Port, Opts, Owner, Socket]) ->
    process_flag(trap_exit, true),

    %% Generate connection IDs
    SCID = generate_connection_id(),
    DCID = generate_connection_id(),

    %% Determine remote address
    RemoteAddr = resolve_address(Host, Port),

    %% Create or use provided socket
    {ok, Sock, LocalAddr} = case Socket of
        undefined ->
            {ok, S} = gen_udp:open(0, [binary, {active, false}]),
            {ok, LA} = inet:sockname(S),
            {ok, S, LA};
        S ->
            {ok, LA} = inet:sockname(S),
            {ok, S, LA}
    end,

    %% Generate initial keys
    InitialKeys = derive_initial_keys(DCID),

    %% Initialize packet number spaces
    PNSpace = #pn_space{
        next_pn = 0,
        largest_acked = undefined,
        largest_recv = undefined,
        recv_time = undefined,
        ack_ranges = [],
        ack_eliciting_in_flight = 0,
        loss_time = undefined,
        sent_packets = #{}
    },

    %% Create connection reference and register
    ConnRef = make_ref(),
    register_conn(ConnRef, self()),

    %% Get server name for SNI
    ServerName = case maps:get(server_name, Opts, undefined) of
        undefined when is_binary(Host) -> Host;
        undefined when is_list(Host) -> list_to_binary(Host);
        SN -> SN
    end,

    %% Get ALPN list
    AlpnOpt = maps:get(alpn, Opts, [<<"h3">>]),
    AlpnList = normalize_alpn_list(AlpnOpt),

    %% Initialize congestion control and loss detection
    CCState = quic_cc:new(),
    LossState = quic_loss:new(),

    %% Initialize state
    State = #state{
        scid = SCID,
        dcid = DCID,
        original_dcid = DCID,
        role = client,
        socket = Sock,
        remote_addr = RemoteAddr,
        local_addr = LocalAddr,
        owner = Owner,
        conn_ref = ConnRef,
        server_name = ServerName,
        verify = maps:get(verify, Opts, false),
        initial_keys = InitialKeys,
        tls_state = ?TLS_AWAITING_SERVER_HELLO,
        alpn_list = AlpnList,
        pn_initial = PNSpace,
        pn_handshake = PNSpace,
        pn_app = PNSpace,
        max_data_local = maps:get(max_data, Opts, ?DEFAULT_INITIAL_MAX_DATA),
        max_data_remote = ?DEFAULT_INITIAL_MAX_DATA,
        next_stream_id_bidi = 0,  % Client-initiated bidi: 0, 4, 8, ...
        next_stream_id_uni = 2,   % Client-initiated uni: 2, 6, 10, ...
        max_streams_bidi_local = maps:get(max_streams_bidi, Opts, ?DEFAULT_MAX_STREAMS_BIDI),
        max_streams_bidi_remote = ?DEFAULT_MAX_STREAMS_BIDI,
        max_streams_uni_local = maps:get(max_streams_uni, Opts, ?DEFAULT_MAX_STREAMS_UNI),
        max_streams_uni_remote = ?DEFAULT_MAX_STREAMS_UNI,
        idle_timeout = maps:get(idle_timeout, Opts, ?DEFAULT_MAX_IDLE_TIMEOUT),
        last_activity = erlang:monotonic_time(millisecond),
        cc_state = CCState,
        loss_state = LossState
    },

    {ok, idle, State}.

terminate(_Reason, _StateName, #state{socket = Socket, conn_ref = ConnRef}) ->
    unregister_conn(ConnRef),
    case Socket of
        undefined -> ok;
        _ -> gen_udp:close(Socket)
    end,
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%====================================================================
%% State Functions
%%====================================================================

%% ----- IDLE STATE -----

idle(enter, _OldState, State) ->
    %% Start the handshake by sending Initial packet with ClientHello
    NewState = send_client_hello(State),
    {keep_state, NewState};

idle({call, From}, get_ref, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

idle({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {idle, state_to_map(State)}}]};

idle({call, From}, peername, #state{remote_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

idle({call, From}, sockname, #state{local_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

idle(info, {udp, Socket, _IP, _Port, Data}, #state{socket = Socket} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(idle, NewState);

idle(cast, process, State) ->
    %% Re-enable socket for receiving
    inet:setopts(State#state.socket, [{active, once}]),
    {keep_state, State};

idle(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, idle, State).

%% ----- HANDSHAKING STATE -----

handshaking(enter, idle, State) ->
    %% Continue handshake
    {keep_state, State};

handshaking({call, From}, get_ref, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

handshaking({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {handshaking, state_to_map(State)}}]};

handshaking({call, From}, peername, #state{remote_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

handshaking({call, From}, sockname, #state{local_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

handshaking(info, {udp, Socket, _IP, _Port, Data}, #state{socket = Socket} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(handshaking, NewState);

handshaking(cast, process, State) ->
    inet:setopts(State#state.socket, [{active, once}]),
    {keep_state, State};

handshaking(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, handshaking, State).

%% ----- CONNECTED STATE -----

connected(enter, handshaking, #state{owner = Owner, conn_ref = Ref, alpn = Alpn} = State) ->
    %% Notify owner that connection is established
    Info = #{
        alpn => Alpn,
        alpn_protocol => Alpn
    },
    Owner ! {quic, Ref, {connected, Info}},
    {keep_state, State};

connected({call, From}, get_ref, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

connected({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {connected, state_to_map(State)}}]};

connected({call, From}, peername, #state{remote_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

connected({call, From}, sockname, #state{local_addr = Addr} = State) ->
    {keep_state, State, [{reply, From, {ok, Addr}}]};

connected({call, From}, {send_data, StreamId, Data, Fin}, State) ->
    case do_send_data(StreamId, Data, Fin, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, {send_headers, StreamId, Headers, Fin}, State) ->
    %% HTTP/3 headers - encode and send on stream
    case do_send_headers(StreamId, Headers, Fin, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, open_stream, State) ->
    case do_open_stream(State) of
        {ok, StreamId, NewState} ->
            {keep_state, NewState, [{reply, From, {ok, StreamId}}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, open_unidirectional_stream, State) ->
    case do_open_unidirectional_stream(State) of
        {ok, StreamId, NewState} ->
            {keep_state, NewState, [{reply, From, {ok, StreamId}}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, {close_stream, StreamId, ErrorCode}, State) ->
    case do_close_stream(StreamId, ErrorCode, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

connected({call, From}, {setopts, _Opts}, State) ->
    {keep_state, State, [{reply, From, ok}]};

connected({call, From}, key_update, #state{key_state = undefined} = State) ->
    {keep_state, State, [{reply, From, {error, no_keys}}]};
connected({call, From}, key_update, #state{key_state = KeyState} = State) ->
    case KeyState#key_update_state.update_state of
        idle ->
            %% Initiate key update
            NewState = initiate_key_update(State),
            {keep_state, NewState, [{reply, From, ok}]};
        _ ->
            %% Key update already in progress
            {keep_state, State, [{reply, From, {error, key_update_in_progress}}]}
    end;

connected(info, {udp, Socket, _IP, _Port, Data}, #state{socket = Socket} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(connected, NewState);

connected(cast, {close, Reason}, State) ->
    NewState = initiate_close(Reason, State),
    {next_state, draining, NewState};

connected(cast, process, State) ->
    inet:setopts(State#state.socket, [{active, once}]),
    {keep_state, State};

connected(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, connected, State).

%% ----- DRAINING STATE -----

draining(enter, _OldState, #state{owner = Owner, conn_ref = Ref, close_reason = Reason} = State) ->
    Owner ! {quic, Ref, {closed, Reason}},
    %% Start drain timer (3 * PTO)
    TimerRef = erlang:send_after(3000, self(), drain_timeout),
    {keep_state, State#state{timer_ref = TimerRef}};

draining({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {draining, state_to_map(State)}}]};

draining(info, drain_timeout, State) ->
    {next_state, closed, State};

draining(info, {udp, _Socket, _IP, _Port, _Data}, State) ->
    %% Ignore packets in draining state
    {keep_state, State};

draining(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, draining, State).

%% ----- CLOSED STATE -----

closed(enter, _OldState, State) ->
    {stop, normal, State};

closed({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {closed, state_to_map(State)}}]};

closed(_EventType, _EventContent, State) ->
    {keep_state, State}.

%%====================================================================
%% Common Event Handling
%%====================================================================

handle_common_event({call, From}, get_ref, _StateName, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

handle_common_event(cast, handle_timeout, _StateName, State) ->
    %% Handle loss detection / idle timeout
    NewState = check_timeouts(State),
    {keep_state, NewState};

handle_common_event(info, pto_timeout, StateName, State)
  when StateName =:= connected; StateName =:= handshaking ->
    %% Handle PTO timeout - send probe packet
    NewState = handle_pto_timeout(State),
    {keep_state, NewState};

handle_common_event(info, pto_timeout, _StateName, State) ->
    %% Ignore PTO in other states
    {keep_state, State};

handle_common_event(info, {'EXIT', _Pid, _Reason}, _StateName, State) ->
    {keep_state, State};

handle_common_event(_EventType, _EventContent, _StateName, State) ->
    {keep_state, State}.

%%====================================================================
%% Internal Functions - TLS Handshake
%%====================================================================

%% Send ClientHello in an Initial packet
send_client_hello(State) ->
    #state{
        scid = SCID,
        server_name = ServerName,
        alpn_list = AlpnList,
        max_data_local = MaxData,
        max_streams_bidi_local = MaxStreamsBidi,
        max_streams_uni_local = MaxStreamsUni
    } = State,

    %% Build transport parameters
    TransportParams = #{
        initial_scid => SCID,
        initial_max_data => MaxData,
        initial_max_stream_data_bidi_local => ?DEFAULT_INITIAL_MAX_STREAM_DATA,
        initial_max_stream_data_bidi_remote => ?DEFAULT_INITIAL_MAX_STREAM_DATA,
        initial_max_stream_data_uni => ?DEFAULT_INITIAL_MAX_STREAM_DATA,
        initial_max_streams_bidi => MaxStreamsBidi,
        initial_max_streams_uni => MaxStreamsUni,
        max_idle_timeout => State#state.idle_timeout,
        active_connection_id_limit => 2
    },

    %% Build ClientHello
    {ClientHello, PrivKey, _Random} = quic_tls:build_client_hello(#{
        server_name => ServerName,
        alpn => AlpnList,
        transport_params => TransportParams
    }),

    %% Update transcript
    Transcript = ClientHello,

    %% Create CRYPTO frame
    CryptoFrame = quic_frame:encode({crypto, 0, ClientHello}),

    %% Encrypt and send Initial packet
    NewState = send_initial_packet(CryptoFrame, State#state{
        tls_private_key = PrivKey,
        tls_transcript = Transcript
    }),

    %% Enable socket for receiving
    inet:setopts(NewState#state.socket, [{active, once}]),

    NewState.

%% Send an Initial packet
send_initial_packet(Payload, State) ->
    #state{
        scid = SCID,
        dcid = DCID,
        version = Version,
        socket = Socket,
        remote_addr = {IP, Port},
        initial_keys = {ClientKeys, _ServerKeys},
        pn_initial = PNSpace
    } = State,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% Build header (without packet number, for AAD)
    HeaderBody = <<
        Version:32,
        (byte_size(DCID)):8, DCID/binary,
        (byte_size(SCID)):8, SCID/binary,
        0,  % Token length (varint = 0)
        (quic_varint:encode(byte_size(Payload) + PNLen + 16))/binary  % +16 for AEAD tag
    >>,

    %% First byte: 1100 0000 | (PNLen - 1)
    FirstByte = 16#C0 bor (PNLen - 1),
    Header = <<FirstByte, HeaderBody/binary>>,

    %% AAD is the header with encoded PN appended
    PNBin = quic_packet:encode_pn(PN, PNLen),
    AAD = <<Header/binary, PNBin/binary>>,

    %% Encrypt payload
    #crypto_keys{key = Key, iv = IV, hp = HP} = ClientKeys,
    Encrypted = quic_aead:encrypt(Key, IV, PN, AAD, Payload),

    %% Apply header protection
    PNOffset = byte_size(Header),
    ProtectedHeader = quic_aead:protect_header(HP, <<Header/binary, PNBin/binary>>, Encrypted, PNOffset),

    %% Build final packet
    Packet = <<ProtectedHeader/binary, Encrypted/binary>>,

    %% Pad Initial packets to at least 1200 bytes
    PaddedPacket = pad_initial_packet(Packet),

    %% Send
    gen_udp:send(Socket, IP, Port, PaddedPacket),

    %% Update packet number space
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    State#state{pn_initial = NewPNSpace}.

%% Send an Initial ACK packet
send_initial_ack(State) ->
    #state{pn_initial = PNSpace} = State,
    case PNSpace#pn_space.ack_ranges of
        [] ->
            State;  % Nothing to ACK
        Ranges ->
            %% Build ACK frame
            AckFrame = build_ack_frame(Ranges),
            send_initial_packet(AckFrame, State)
    end.

%% Send a Handshake ACK packet
send_handshake_ack(State) ->
    #state{pn_handshake = PNSpace} = State,
    case PNSpace#pn_space.ack_ranges of
        [] ->
            State;
        Ranges ->
            AckFrame = build_ack_frame(Ranges),
            send_handshake_packet(AckFrame, State)
    end.

%% Send an app-level ACK packet (1-RTT)
send_app_ack(State) ->
    #state{pn_app = PNSpace} = State,
    case PNSpace#pn_space.ack_ranges of
        [] ->
            State;
        Ranges ->
            AckFrame = build_ack_frame(Ranges),
            send_app_packet(AckFrame, State)
    end.

%% Build an ACK frame from ranges
%% Our internal format is [{Start, End}, ...] where Start <= End
%% quic_frame expects [{LargestAcked, FirstRange}, {Gap, Range}, ...]
%% where FirstRange = LargestAcked - SmallestAcked (count)
build_ack_frame(Ranges) ->
    %% Convert from {Start, End} to encoder format
    EncoderRanges = convert_ack_ranges_for_encode(Ranges),
    AckDelay = 0,  % For simplicity
    quic_frame:encode({ack, EncoderRanges, AckDelay, undefined}).

%% Convert internal ACK ranges to encoder format
convert_ack_ranges_for_encode([{Start, End} | Rest]) ->
    %% First range: LargestAcked = End, FirstRange = End - Start
    FirstRange = End - Start,
    RestConverted = convert_rest_ranges(Start, Rest),
    [{End, FirstRange} | RestConverted].

convert_rest_ranges(_PrevStart, []) ->
    [];
convert_rest_ranges(PrevStart, [{Start, End} | Rest]) ->
    %% Gap = PrevStart - End - 2 (number of missing packets between ranges)
    Gap = PrevStart - End - 2,
    %% Range = End - Start (number of packets in this block)
    Range = End - Start,
    [{Gap, Range} | convert_rest_ranges(Start, Rest)].

%% Send a Handshake packet
send_handshake_packet(Payload, State) ->
    #state{
        scid = SCID,
        dcid = DCID,
        version = Version,
        socket = Socket,
        remote_addr = {IP, Port},
        handshake_keys = {ClientKeys, _ServerKeys},
        pn_handshake = PNSpace
    } = State,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% First byte for Handshake: 1110 0000 | (PNLen - 1)
    FirstByte = 16#E0 bor (PNLen - 1),

    %% Build header
    HeaderBody = <<
        Version:32,
        (byte_size(DCID)):8, DCID/binary,
        (byte_size(SCID)):8, SCID/binary,
        (quic_varint:encode(byte_size(Payload) + PNLen + 16))/binary
    >>,
    Header = <<FirstByte, HeaderBody/binary>>,

    %% AAD
    PNBin = quic_packet:encode_pn(PN, PNLen),
    AAD = <<Header/binary, PNBin/binary>>,

    %% Encrypt
    #crypto_keys{key = Key, iv = IV, hp = HP} = ClientKeys,
    Encrypted = quic_aead:encrypt(Key, IV, PN, AAD, Payload),

    %% Header protection
    PNOffset = byte_size(Header),
    ProtectedHeader = quic_aead:protect_header(HP, <<Header/binary, PNBin/binary>>, Encrypted, PNOffset),

    %% Build and send
    Packet = <<ProtectedHeader/binary, Encrypted/binary>>,
    gen_udp:send(Socket, IP, Port, Packet),

    %% Update PN space
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    State#state{pn_handshake = NewPNSpace}.

%% Send a 1-RTT (application) packet (without tracking frames for retransmission)
send_app_packet(Payload, State) ->
    send_app_packet_internal(Payload, [], State).

%% Send a 1-RTT packet with explicit frames list for retransmission tracking
send_app_packet_internal(Payload, Frames, State) ->
    #state{
        dcid = DCID,
        socket = Socket,
        remote_addr = {IP, Port},
        app_keys = {ClientKeys, _ServerKeys},
        pn_app = PNSpace,
        cc_state = CCState,
        loss_state = LossState
    } = State,

    PN = PNSpace#pn_space.next_pn,
    PNLen = quic_packet:pn_length(PN),

    %% Get current key phase for encoding
    KeyPhase = get_current_key_phase(State),

    %% First byte for short header: 01XX XXXX
    %% Bit 5 = spin bit (0), bits 3-4 reserved (0), bit 2 = key phase, bits 0-1 = PN length
    FirstByte = 16#40 bor (KeyPhase bsl 2) bor (PNLen - 1),

    %% Header is just first byte + DCID
    Header = <<FirstByte, DCID/binary>>,

    %% AAD
    PNBin = quic_packet:encode_pn(PN, PNLen),
    AAD = <<Header/binary, PNBin/binary>>,

    %% Encrypt
    #crypto_keys{key = Key, iv = IV, hp = HP} = ClientKeys,
    Encrypted = quic_aead:encrypt(Key, IV, PN, AAD, Payload),

    %% Header protection
    PNOffset = byte_size(Header),
    ProtectedHeader = quic_aead:protect_header(HP, <<Header/binary, PNBin/binary>>, Encrypted, PNOffset),

    %% Build and send
    Packet = <<ProtectedHeader/binary, Encrypted/binary>>,
    PacketSize = byte_size(Packet),
    gen_udp:send(Socket, IP, Port, Packet),

    %% Track sent packet for loss detection and congestion control
    %% Determine if ack-eliciting (not ACK-only or padding-only)
    AckEliciting = is_ack_eliciting_payload(Payload),
    NewLossState = quic_loss:on_packet_sent(LossState, PN, PacketSize, AckEliciting, Frames),
    NewCCState = case AckEliciting of
        true -> quic_cc:on_packet_sent(CCState, PacketSize);
        false -> CCState
    end,

    %% Update PN space
    NewPNSpace = PNSpace#pn_space{next_pn = PN + 1},
    State1 = State#state{
        pn_app = NewPNSpace,
        cc_state = NewCCState,
        loss_state = NewLossState
    },

    %% Set PTO timer for retransmission
    set_pto_timer(State1).

%% Pad Initial packet to minimum 1200 bytes
pad_initial_packet(Packet) when byte_size(Packet) >= 1200 ->
    Packet;
pad_initial_packet(Packet) ->
    PadLen = 1200 - byte_size(Packet),
    <<Packet/binary, 0:PadLen/unit:8>>.

%%====================================================================
%% Internal Functions - Packet Processing
%%====================================================================

%% Handle incoming packet (may be coalesced with multiple QUIC packets)
handle_packet(Data, State) ->
    handle_packet_loop(Data, State).

handle_packet_loop(<<>>, State) ->
    %% No more data to process
    inet:setopts(State#state.socket, [{active, once}]),
    State;
handle_packet_loop(Data, State) ->
    case decode_and_decrypt_packet(Data, State) of
        {ok, _Type, Frames, RemainingData, NewState} ->
            %% Process frames from this packet
            State1 = process_frames_noreenbl(_Type, Frames, NewState),
            %% Continue with remaining coalesced packets
            handle_packet_loop(RemainingData, State1);
        {error, _Reason} ->
            %% Re-enable socket
            inet:setopts(State#state.socket, [{active, once}]),
            State
    end.

%% Decode and decrypt a packet
decode_and_decrypt_packet(Data, State) ->
    %% Check header form (first bit)
    case Data of
        <<1:1, _:7, _/binary>> ->
            decode_long_header_packet(Data, State);
        <<0:1, _:7, _/binary>> ->
            decode_short_header_packet(Data, State);
        _ ->
            {error, invalid_packet}
    end.

%% Decode long header packet (Initial, Handshake, etc.)
decode_long_header_packet(Data, State) ->
    %% Parse unprotected header to get DCID length
    <<FirstByte, _Version:32, DCIDLen, Rest/binary>> = Data,
    <<DCID:DCIDLen/binary, SCIDLen, Rest2/binary>> = Rest,
    <<SCID:SCIDLen/binary, Rest3/binary>> = Rest2,

    Type = (FirstByte bsr 4) band 2#11,

    case Type of
        0 -> %% Initial
            decode_initial_packet(Data, FirstByte, DCID, SCID, Rest3, State);
        2 -> %% Handshake
            decode_handshake_packet(Data, FirstByte, DCID, SCID, Rest3, State);
        _ ->
            {error, unsupported_packet_type}
    end.

decode_initial_packet(FullPacket, FirstByte, _DCID, ServerSCID, Rest, State) ->
    #state{initial_keys = {_ClientKeys, ServerKeys}} = State,

    %% Parse token and length
    {TokenLen, Rest2} = quic_varint:decode(Rest),
    <<_Token:TokenLen/binary, Rest3/binary>> = Rest2,
    {PayloadLen, Rest4} = quic_varint:decode(Rest3),

    %% Header ends here, payload starts
    HeaderLen = byte_size(FullPacket) - byte_size(Rest4),
    <<Header:HeaderLen/binary, Payload/binary>> = FullPacket,

    %% Update DCID to server's SCID (this becomes our destination for future packets)
    State1 = case State#state.dcid =:= State#state.original_dcid of
        true -> State#state{dcid = ServerSCID};  % First packet from server, update DCID
        false -> State  % Already updated
    end,

    %% Ensure we have enough data
    case byte_size(Payload) >= PayloadLen of
        true ->
            <<EncryptedPayload:PayloadLen/binary, RemainingData/binary>> = Payload,
            decrypt_packet(initial, Header, FirstByte, EncryptedPayload, RemainingData, ServerKeys, State1);
        false ->
            {error, incomplete_packet}
    end.

decode_handshake_packet(FullPacket, FirstByte, _DCID, _SCID, Rest, State) ->
    case State#state.handshake_keys of
        undefined ->
            {error, no_handshake_keys};
        {_ClientKeys, ServerKeys} ->
            %% Parse length
            {PayloadLen, Rest2} = quic_varint:decode(Rest),
            HeaderLen = byte_size(FullPacket) - byte_size(Rest2),
            <<Header:HeaderLen/binary, Payload/binary>> = FullPacket,

            case byte_size(Payload) >= PayloadLen of
                true ->
                    <<EncryptedPayload:PayloadLen/binary, RemainingData/binary>> = Payload,
                    decrypt_packet(handshake, Header, FirstByte, EncryptedPayload, RemainingData, ServerKeys, State);
                false ->
                    {error, incomplete_packet}
            end
    end.

decode_short_header_packet(Data, State) ->
    case State#state.app_keys of
        undefined ->
            {error, no_app_keys};
        {_ClientKeys, ServerKeys} ->
            %% Short header: first byte + DCID (assume 8 bytes based on our SCID)
            %% Short header packets don't have length field, so they consume all remaining data
            DCIDLen = byte_size(State#state.scid),
            <<FirstByte, DCID:DCIDLen/binary, EncryptedPayload/binary>> = Data,
            Header = <<FirstByte, DCID/binary>>,
            %% No remaining data after short header packet
            %% For key update support, we use the current server keys for HP removal
            %% and then check key_phase after unprotection
            decrypt_app_packet(Header, EncryptedPayload, ServerKeys, State)
    end.

%% Decrypt an application (1-RTT) packet with key phase handling
decrypt_app_packet(Header, EncryptedPayload, ServerKeys, State) ->
    #crypto_keys{hp = HP} = ServerKeys,

    %% Remove header protection using current keys
    PNOffset = byte_size(Header),
    {UnprotectedHeader, PNLen} = quic_aead:unprotect_header(HP, Header, EncryptedPayload, PNOffset),

    %% Extract the unprotected first byte to get key_phase
    <<UnprotectedFirstByte, _/binary>> = UnprotectedHeader,
    ReceivedKeyPhase = quic_packet:decode_short_key_phase(UnprotectedFirstByte),

    %% Select appropriate decryption keys based on key_phase
    {DecryptKeys, State1} = select_decrypt_keys(ReceivedKeyPhase, State),
    {_, ServerDecryptKeys} = DecryptKeys,

    %% Extract PN and decrypt
    UnprotHeaderLen = byte_size(UnprotectedHeader),
    <<_:((UnprotHeaderLen - PNLen) * 8), PN:PNLen/unit:8>> = UnprotectedHeader,
    AAD = UnprotectedHeader,
    Ciphertext = binary:part(EncryptedPayload, PNLen, byte_size(EncryptedPayload) - PNLen),

    #crypto_keys{key = Key, iv = IV} = ServerDecryptKeys,
    case quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext) of
        {ok, Plaintext} ->
            case quic_frame:decode_all(Plaintext) of
                {ok, Frames} ->
                    State2 = record_received_pn(app, PN, State1),
                    NewState = update_last_activity(State2),
                    {ok, app, Frames, <<>>, NewState};
                {error, Reason} ->
                    {error, {frame_decode_error, Reason}}
            end;
        {error, bad_tag} ->
            {error, decryption_failed}
    end.

%% Decrypt a packet
%% RemainingData is the data after this packet (for coalesced packets)
decrypt_packet(Level, Header, _FirstByte, EncryptedPayload, RemainingData, Keys, State) ->
    #crypto_keys{key = Key, iv = IV, hp = HP} = Keys,

    %% Remove header protection
    %% unprotect_header returns UnprotectedHeader which includes the unprotected PN at the end
    PNOffset = byte_size(Header),
    {UnprotectedHeader, PNLen} = quic_aead:unprotect_header(HP, Header, EncryptedPayload, PNOffset),

    %% Extract unprotected PN from the end of UnprotectedHeader
    UnprotHeaderLen = byte_size(UnprotectedHeader),
    <<_:((UnprotHeaderLen - PNLen) * 8), PN:PNLen/unit:8>> = UnprotectedHeader,

    %% AAD is the full unprotected header (already includes PN)
    AAD = UnprotectedHeader,

    %% Actual ciphertext starts after PN bytes in EncryptedPayload
    Ciphertext = binary:part(EncryptedPayload, PNLen, byte_size(EncryptedPayload) - PNLen),

    %% Decrypt
    case quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext) of
        {ok, Plaintext} ->
            %% Decode frames
            case quic_frame:decode_all(Plaintext) of
                {ok, Frames} ->
                    %% Track received packet number for ACK generation
                    State1 = record_received_pn(Level, PN, State),
                    NewState = update_last_activity(State1),
                    {ok, Level, Frames, RemainingData, NewState};
                {error, Reason} ->
                    {error, {frame_decode_error, Reason}}
            end;
        {error, bad_tag} ->
            {error, decryption_failed}
    end.

%% Process decoded frames (re-enables socket when done)
process_frames(_Level, [], State) ->
    inet:setopts(State#state.socket, [{active, once}]),
    State;
process_frames(Level, [Frame | Rest], State) ->
    NewState = process_frame(Level, Frame, State),
    process_frames(Level, Rest, NewState).

%% Process decoded frames without re-enabling socket (for coalesced packets)
process_frames_noreenbl(_Level, [], State) ->
    State;
process_frames_noreenbl(Level, [Frame | Rest], State) ->
    NewState = process_frame(Level, Frame, State),
    process_frames_noreenbl(Level, Rest, NewState).

%% Process individual frames
process_frame(_Level, padding, State) ->
    State;

process_frame(_Level, ping, State) ->
    %% Should trigger ACK
    State;

process_frame(Level, {crypto, Offset, Data}, State) ->
    buffer_crypto_data(Level, Offset, Data, State);

process_frame(_Level, {ack, Ranges, AckDelay, _ECN}, State) ->
    %% Process ACK - update loss detection and congestion control
    #state{loss_state = LossState, cc_state = CCState} = State,

    %% Convert Ranges list to the format expected by quic_loss
    %% Ranges is a list of {Start, End} tuples from largest to smallest
    case Ranges of
        [] ->
            State;
        [{LargestAcked, _} | _] ->
            %% Convert ranges to ACK frame format for quic_loss
            %% quic_loss expects {ack, LargestAcked, AckDelay, FirstRange, AckRanges}
            {FirstRange, RestRanges} = ranges_to_ack_format(Ranges),
            AckFrame = {ack, LargestAcked, AckDelay, FirstRange, RestRanges},

            Now = erlang:monotonic_time(millisecond),
            {NewLossState, AckedPackets, LostPackets} =
                quic_loss:on_ack_received(LossState, AckFrame, Now),

            %% Calculate total bytes acked and lost
            AckedBytes = lists:sum([P#sent_packet.size || P <- AckedPackets]),
            LostBytes = lists:sum([P#sent_packet.size || P <- LostPackets]),

            %% Update congestion control
            CCState1 = quic_cc:on_packets_acked(CCState, AckedBytes),
            CCState2 = quic_cc:on_packets_lost(CCState1, LostBytes),

            %% If there was loss, signal congestion event
            CCState3 = case LostPackets of
                [] ->
                    CCState2;
                [#sent_packet{time_sent = SentTime} | _] ->
                    quic_cc:on_congestion_event(CCState2, SentTime)
            end,

            State1 = State#state{
                loss_state = NewLossState,
                cc_state = CCState3
            },

            %% Retransmit lost packets
            State2 = retransmit_lost_packets(LostPackets, State1),

            %% Reset PTO timer after ACK processing
            State3 = set_pto_timer(State2),

            %% Try to send queued data now that cwnd may have freed up
            process_send_queue(State3)
    end;

process_frame(_Level, handshake_done, State) ->
    %% Server confirmed handshake complete
    State;

process_frame(app, {stream, StreamId, Offset, Data, Fin}, State) ->
    process_stream_data(StreamId, Offset, Data, Fin, State);

process_frame(_Level, {max_data, MaxData}, State) ->
    State#state{max_data_remote = MaxData};

process_frame(_Level, {max_stream_data, StreamId, MaxData}, State) ->
    case maps:find(StreamId, State#state.streams) of
        {ok, Stream} ->
            NewStream = Stream#stream_state{send_max_data = MaxData},
            State#state{streams = maps:put(StreamId, NewStream, State#state.streams)};
        error ->
            State
    end;

process_frame(_Level, {max_streams, bidi, Max}, State) ->
    State#state{max_streams_bidi_remote = Max};

process_frame(_Level, {max_streams, uni, Max}, State) ->
    State#state{max_streams_uni_remote = Max};

%% PATH_CHALLENGE: Peer is probing the path, respond with PATH_RESPONSE
process_frame(app, {path_challenge, ChallengeData}, State) ->
    %% Send PATH_RESPONSE with the same data
    ResponseFrame = quic_frame:encode({path_response, ChallengeData}),
    send_app_packet(ResponseFrame, State);

%% PATH_RESPONSE: Response to our PATH_CHALLENGE
process_frame(app, {path_response, ResponseData}, State) ->
    handle_path_response(ResponseData, State);

%% NEW_CONNECTION_ID: Peer is providing a new CID for us to use
process_frame(app, {new_connection_id, SeqNum, RetirePrior, CID, ResetToken}, State) ->
    handle_new_connection_id(SeqNum, RetirePrior, CID, ResetToken, State);

%% RETIRE_CONNECTION_ID: Peer is retiring one of our CIDs
process_frame(app, {retire_connection_id, SeqNum}, State) ->
    handle_retire_connection_id(SeqNum, State);

process_frame(_Level, {connection_close, _Type, _Code, _FrameType, _Reason}, State) ->
    State#state{close_reason = connection_closed};

process_frame(_Level, _Frame, State) ->
    %% Ignore unknown frames
    State.

%% Buffer CRYPTO data and process when complete messages are available
buffer_crypto_data(Level, Offset, Data, State) ->
    LevelAtom = case Level of
        initial -> initial;
        handshake -> handshake;
        app -> app;
        _ -> initial
    end,

    %% Get current buffer
    Buffer = maps:get(LevelAtom, State#state.crypto_buffer, #{}),

    %% Add data to buffer
    NewBuffer = maps:put(Offset, Data, Buffer),
    NewCryptoBuffer = maps:put(LevelAtom, NewBuffer, State#state.crypto_buffer),

    State1 = State#state{crypto_buffer = NewCryptoBuffer},

    %% Try to process contiguous data
    process_crypto_buffer(LevelAtom, State1).

%% Process contiguous CRYPTO data
process_crypto_buffer(Level, State) ->
    Buffer = maps:get(Level, State#state.crypto_buffer, #{}),
    ExpectedOffset = maps:get(Level, State#state.crypto_offset, 0),

    case maps:find(ExpectedOffset, Buffer) of
        {ok, Data} ->
            %% Process this data
            State1 = process_tls_data(Level, Data, State),

            %% Update offset and remove from buffer
            NewOffset = ExpectedOffset + byte_size(Data),
            NewBuffer = maps:remove(ExpectedOffset, Buffer),
            NewCryptoBuffer = maps:put(Level, NewBuffer, State1#state.crypto_buffer),
            NewCryptoOffset = maps:put(Level, NewOffset, State1#state.crypto_offset),

            State2 = State1#state{
                crypto_buffer = NewCryptoBuffer,
                crypto_offset = NewCryptoOffset
            },

            %% Try to process more
            process_crypto_buffer(Level, State2);
        error ->
            State
    end.

%% Process TLS handshake data from CRYPTO frames
process_tls_data(Level, Data, State) ->
    %% Prepend any buffered incomplete TLS data
    BufferedData = maps:get(Level, State#state.tls_buffer, <<>>),
    FullData = <<BufferedData/binary, Data/binary>>,
    %% Clear the buffer before processing
    State1 = State#state{tls_buffer = maps:put(Level, <<>>, State#state.tls_buffer)},
    process_tls_messages(Level, FullData, State1).

%% Process TLS messages
process_tls_messages(_Level, <<>>, State) ->
    State;
process_tls_messages(Level, Data, State) ->
    case quic_tls:decode_handshake_message(Data) of
        {ok, {Type, Body}, Rest} ->
            %% Capture the ORIGINAL bytes from the wire (including TLS header)
            OriginalMsg = binary:part(Data, 0, 4 + byte_size(Body)),
            %% Pass the original bytes to process_tls_message for transcript
            State1 = process_tls_message(Level, Type, Body, OriginalMsg, State),
            process_tls_messages(Level, Rest, State1);
        {error, incomplete} ->
            %% Buffer the incomplete data for next CRYPTO frame
            State#state{tls_buffer = maps:put(Level, Data, State#state.tls_buffer)};
        {error, _Err} ->
            State
    end.

%% Process individual TLS messages
%% OriginalMsg contains the exact bytes from the wire for transcript computation
process_tls_message(_Level, ?TLS_SERVER_HELLO, Body, OriginalMsg, State) ->
    case quic_tls:parse_server_hello(Body) of
        {ok, #{public_key := ServerPubKey, cipher := Cipher}} ->
            %% Compute shared secret
            SharedSecret = quic_crypto:compute_shared_secret(
                x25519, State#state.tls_private_key, ServerPubKey),

            %% Update transcript - USE ORIGINAL BYTES FROM WIRE
            Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
            %% Use cipher-appropriate hash for transcript
            TranscriptHash = quic_crypto:transcript_hash(Cipher, Transcript),

            %% Derive handshake secrets (cipher-aware for SHA-384 with AES-256-GCM)
            HashLen = case Cipher of
                aes_256_gcm -> 48;  % SHA-384
                _ -> 32  % SHA-256
            end,
            EarlySecret = quic_crypto:derive_early_secret(Cipher, <<0:HashLen/unit:8>>),
            HandshakeSecret = quic_crypto:derive_handshake_secret(Cipher, EarlySecret, SharedSecret),

            ClientHsSecret = quic_crypto:derive_client_handshake_secret(Cipher, HandshakeSecret, TranscriptHash),
            ServerHsSecret = quic_crypto:derive_server_handshake_secret(Cipher, HandshakeSecret, TranscriptHash),

            %% Derive handshake keys
            {ClientKey, ClientIV, ClientHP} = quic_keys:derive_keys(ClientHsSecret, Cipher),
            {ServerKey, ServerIV, ServerHP} = quic_keys:derive_keys(ServerHsSecret, Cipher),

            ClientHsKeys = #crypto_keys{key = ClientKey, iv = ClientIV, hp = ClientHP, cipher = Cipher},
            ServerHsKeys = #crypto_keys{key = ServerKey, iv = ServerIV, hp = ServerHP, cipher = Cipher},

            State1 = State#state{
                tls_state = ?TLS_AWAITING_ENCRYPTED_EXT,
                tls_transcript = Transcript,
                handshake_secret = HandshakeSecret,
                client_hs_secret = ClientHsSecret,
                server_hs_secret = ServerHsSecret,
                handshake_keys = {ClientHsKeys, ServerHsKeys}
            },
            %% Send ACK for the Initial packet that contained ServerHello
            send_initial_ack(State1);
        {error, _} ->
            State
    end;

process_tls_message(_Level, ?TLS_ENCRYPTED_EXTENSIONS, Body, OriginalMsg, State) ->
    %% Update transcript - USE ORIGINAL BYTES
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,

    case quic_tls:parse_encrypted_extensions(Body) of
        {ok, #{alpn := Alpn, transport_params := TP}} ->
            State#state{
                tls_state = ?TLS_AWAITING_CERT,
                tls_transcript = Transcript,
                alpn = Alpn,
                transport_params = TP
            };
        _ ->
            State#state{
                tls_state = ?TLS_AWAITING_CERT,
                tls_transcript = Transcript
            }
    end;

process_tls_message(_Level, ?TLS_CERTIFICATE, _Body, OriginalMsg, State) ->
    %% Update transcript (we don't verify certs if verify = false)
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
    State#state{
        tls_state = ?TLS_AWAITING_CERT_VERIFY,
        tls_transcript = Transcript
    };

process_tls_message(_Level, ?TLS_CERTIFICATE_VERIFY, _Body, OriginalMsg, State) ->
    %% Update transcript
    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
    State#state{
        tls_state = ?TLS_AWAITING_FINISHED,
        tls_transcript = Transcript
    };

process_tls_message(_Level, ?TLS_FINISHED, Body, OriginalMsg, State) ->
    %% Get cipher from handshake keys for cipher-aware operations
    {ClientHsKeys, _} = State#state.handshake_keys,
    Cipher = ClientHsKeys#crypto_keys.cipher,

    %% Verify server Finished
    case quic_tls:parse_finished(Body) of
        {ok, VerifyData} ->
            TranscriptHash = quic_crypto:transcript_hash(Cipher, State#state.tls_transcript),
            case quic_tls:verify_finished(VerifyData, State#state.server_hs_secret, TranscriptHash, Cipher) of
                true ->
                    %% Update transcript with server Finished - USE ORIGINAL BYTES
                    Transcript = <<(State#state.tls_transcript)/binary, OriginalMsg/binary>>,
                    TranscriptHashFinal = quic_crypto:transcript_hash(Cipher, Transcript),

                    %% Derive master secret and application keys (cipher-aware)
                    MasterSecret = quic_crypto:derive_master_secret(Cipher, State#state.handshake_secret),
                    ClientAppSecret = quic_crypto:derive_client_app_secret(Cipher, MasterSecret, TranscriptHashFinal),
                    ServerAppSecret = quic_crypto:derive_server_app_secret(Cipher, MasterSecret, TranscriptHashFinal),

                    %% Derive app keys
                    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_keys(ClientAppSecret, Cipher),
                    {ServerKey, ServerIV, ServerHP} = quic_keys:derive_keys(ServerAppSecret, Cipher),

                    ClientAppKeys = #crypto_keys{key = ClientKey, iv = ClientIV, hp = ClientHP, cipher = Cipher},
                    ServerAppKeys = #crypto_keys{key = ServerKey, iv = ServerIV, hp = ServerHP, cipher = Cipher},

                    %% Initialize key update state with app secrets for future key updates
                    KeyState = #key_update_state{
                        current_phase = 0,
                        current_keys = {ClientAppKeys, ServerAppKeys},
                        prev_keys = undefined,
                        client_app_secret = ClientAppSecret,
                        server_app_secret = ServerAppSecret,
                        update_state = idle
                    },

                    %% Send client Finished (cipher-aware)
                    %% Client Finished uses transcript INCLUDING server Finished (RFC 8446 Section 4.4.4)
                    ClientFinishedKey = quic_crypto:derive_finished_key(Cipher, State#state.client_hs_secret),
                    ClientVerifyData = quic_crypto:compute_finished_verify(Cipher, ClientFinishedKey, TranscriptHashFinal),
                    ClientFinishedMsg = quic_tls:build_finished(ClientVerifyData),
                    CryptoFrame = quic_frame:encode({crypto, 0, ClientFinishedMsg}),

                    State1 = State#state{
                        tls_state = ?TLS_HANDSHAKE_COMPLETE,
                        tls_transcript = <<Transcript/binary, ClientFinishedMsg/binary>>,
                        master_secret = MasterSecret,
                        app_keys = {ClientAppKeys, ServerAppKeys},
                        key_state = KeyState
                    },

                    %% Send client Finished in Handshake packet
                    send_handshake_packet(CryptoFrame, State1);
                false ->
                    %% Verification failed
                    error_logger:info_msg("[QUIC] Server Finished verification failed~n", []),
                    State
            end;
        {error, _} ->
            State
    end;

process_tls_message(_Level, _Type, _Body, _OriginalMsg, State) ->
    State.

%%====================================================================
%% Internal Functions - Stream Processing
%%====================================================================

process_stream_data(StreamId, Offset, Data, Fin, State) ->
    #state{owner = Owner, conn_ref = Ref, streams = Streams} = State,

    %% Get or create stream state
    Stream = case maps:find(StreamId, Streams) of
        {ok, S} -> S;
        error ->
            %% New stream from server
            #stream_state{
                id = StreamId,
                state = open,
                send_offset = 0,
                send_max_data = ?DEFAULT_INITIAL_MAX_STREAM_DATA,
                send_fin = false,
                send_buffer = [],
                recv_offset = 0,
                recv_max_data = ?DEFAULT_INITIAL_MAX_STREAM_DATA,
                recv_fin = false,
                recv_buffer = <<>>,
                final_size = undefined
            }
    end,

    %% For now, deliver data immediately (ignoring out-of-order for simplicity)
    Owner ! {quic, Ref, {stream_data, StreamId, Data, Fin}},

    NewRecvOffset = Offset + byte_size(Data),
    NewStream = Stream#stream_state{
        recv_offset = NewRecvOffset,
        recv_fin = Fin
    },

    State1 = State#state{streams = maps:put(StreamId, NewStream, Streams)},

    %% Check if we need to send MAX_STREAM_DATA to allow more data
    %% Send when we've consumed more than half our advertised limit
    RecvMaxData = Stream#stream_state.recv_max_data,
    State2 = case NewRecvOffset > (RecvMaxData div 2) of
        true ->
            %% Double the limit and send MAX_STREAM_DATA
            NewMaxData = RecvMaxData * 2,
            UpdatedStream = NewStream#stream_state{recv_max_data = NewMaxData},
            MaxStreamDataFrame = quic_frame:encode({max_stream_data, StreamId, NewMaxData}),
            State1a = State1#state{streams = maps:put(StreamId, UpdatedStream, Streams)},
            send_app_packet(MaxStreamDataFrame, State1a);
        false ->
            State1
    end,

    %% Send ACK for received data
    send_app_ack(State2).

%%====================================================================
%% Internal Functions - Helpers
%%====================================================================

%% Check if a payload contains ack-eliciting frames
%% ACK and PADDING are not ack-eliciting, everything else is
is_ack_eliciting_payload(Payload) when is_binary(Payload) ->
    %% For encoded frames, check the first byte (frame type)
    case Payload of
        <<16#00, _/binary>> -> false;  % PADDING
        <<16#02, _/binary>> -> false;  % ACK
        <<16#03, _/binary>> -> false;  % ACK_ECN
        <<>> -> false;
        _ -> true
    end.

%% Convert ACK ranges from quic_frame format to quic_loss format
%% Input from quic_frame: [{LargestAcked, FirstRange} | [{Gap, Range}, ...]]
%% Output for quic_loss: {FirstRange, [{Gap, Range}, ...]}
ranges_to_ack_format([{_LargestAcked, FirstRange} | RestRanges]) ->
    {FirstRange, RestRanges}.

%% Generate a random connection ID (8-20 bytes, using 8)
generate_connection_id() ->
    crypto:strong_rand_bytes(8).

%% Resolve hostname to IP address
resolve_address(Host, Port) when is_tuple(Host) ->
    {Host, Port};
resolve_address(Host, Port) when is_list(Host) ->
    case inet:getaddr(Host, inet) of
        {ok, IP} -> {IP, Port};
        _ ->
            case inet:getaddr(Host, inet6) of
                {ok, IP} -> {IP, Port};
                _ -> {{127,0,0,1}, Port}
            end
    end;
resolve_address(Host, Port) when is_binary(Host) ->
    resolve_address(binary_to_list(Host), Port).

%% Derive initial encryption keys
derive_initial_keys(DCID) ->
    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_initial_client(DCID),
    {ServerKey, ServerIV, ServerHP} = quic_keys:derive_initial_server(DCID),
    ClientKeys = #crypto_keys{
        key = ClientKey,
        iv = ClientIV,
        hp = ClientHP,
        cipher = aes_128_gcm
    },
    ServerKeys = #crypto_keys{
        key = ServerKey,
        iv = ServerIV,
        hp = ServerHP,
        cipher = aes_128_gcm
    },
    {ClientKeys, ServerKeys}.

%% Check if we should transition to a new state
check_state_transition(CurrentState, State) ->
    case {CurrentState, State#state.tls_state, has_app_keys(State)} of
        {idle, ?TLS_AWAITING_ENCRYPTED_EXT, _} ->
            %% Got ServerHello, have handshake keys
            {next_state, handshaking, State};
        {idle, ?TLS_AWAITING_CERT, _} ->
            {next_state, handshaking, State};
        {idle, ?TLS_AWAITING_CERT_VERIFY, _} ->
            {next_state, handshaking, State};
        {idle, ?TLS_AWAITING_FINISHED, _} ->
            {next_state, handshaking, State};
        {idle, ?TLS_HANDSHAKE_COMPLETE, true} ->
            {next_state, connected, State};
        {handshaking, ?TLS_HANDSHAKE_COMPLETE, true} ->
            {next_state, connected, State};
        _ ->
            {keep_state, State}
    end.

has_app_keys(#state{app_keys = undefined}) -> false;
has_app_keys(_) -> true.

%% Record a received packet number for ACK generation
record_received_pn(initial, PN, State) ->
    PNSpace = State#state.pn_initial,
    NewPNSpace = update_pn_space_recv(PN, PNSpace),
    State#state{pn_initial = NewPNSpace};
record_received_pn(handshake, PN, State) ->
    PNSpace = State#state.pn_handshake,
    NewPNSpace = update_pn_space_recv(PN, PNSpace),
    State#state{pn_handshake = NewPNSpace};
record_received_pn(app, PN, State) ->
    PNSpace = State#state.pn_app,
    NewPNSpace = update_pn_space_recv(PN, PNSpace),
    State#state{pn_app = NewPNSpace};
record_received_pn(_, _PN, State) ->
    State.

update_pn_space_recv(PN, PNSpace) ->
    #pn_space{largest_recv = LargestRecv, ack_ranges = Ranges} = PNSpace,
    NewLargest = case LargestRecv of
        undefined -> PN;
        L when PN > L -> PN;
        L -> L
    end,
    %% Add to ack_ranges (simple: just track largest for now)
    %% A complete implementation would maintain ACK ranges
    NewRanges = case Ranges of
        [] -> [{PN, PN}];
        [{Start, End} | Rest] when PN =:= End + 1 ->
            [{Start, PN} | Rest];
        _ ->
            [{PN, PN} | Ranges]
    end,
    PNSpace#pn_space{
        largest_recv = NewLargest,
        recv_time = erlang:monotonic_time(millisecond),
        ack_ranges = NewRanges
    }.

%% Update last activity timestamp
update_last_activity(State) ->
    State#state{last_activity = erlang:monotonic_time(millisecond)}.

%% Open a new stream
do_open_stream(#state{next_stream_id_bidi = NextId,
                      max_streams_bidi_remote = Max,
                      streams = Streams} = State) ->
    StreamCount = maps:size(maps:filter(fun(Id, _) ->
        (Id band 16#03) =:= 0  % Client-initiated bidi
    end, Streams)),
    if
        StreamCount >= Max ->
            {error, stream_limit};
        true ->
            StreamState = #stream_state{
                id = NextId,
                state = open,
                send_offset = 0,
                send_max_data = ?DEFAULT_INITIAL_MAX_STREAM_DATA,
                send_fin = false,
                send_buffer = [],
                recv_offset = 0,
                recv_max_data = ?DEFAULT_INITIAL_MAX_STREAM_DATA,
                recv_fin = false,
                recv_buffer = <<>>,
                final_size = undefined
            },
            NewState = State#state{
                next_stream_id_bidi = NextId + 4,
                streams = maps:put(NextId, StreamState, Streams)
            },
            {ok, NextId, NewState}
    end.

%% Open a new unidirectional stream
do_open_unidirectional_stream(#state{next_stream_id_uni = NextId,
                                      max_streams_uni_remote = Max,
                                      streams = Streams} = State) ->
    StreamCount = maps:size(maps:filter(fun(Id, _) ->
        (Id band 16#03) =:= 2  % Client-initiated uni
    end, Streams)),
    if
        StreamCount >= Max ->
            {error, stream_limit};
        true ->
            %% Unidirectional streams are send-only for the initiator
            StreamState = #stream_state{
                id = NextId,
                state = open,
                send_offset = 0,
                send_max_data = ?DEFAULT_INITIAL_MAX_STREAM_DATA,
                send_fin = false,
                send_buffer = [],
                recv_offset = 0,
                recv_max_data = 0,  % We don't receive on our uni streams
                recv_fin = true,    % No incoming data expected
                recv_buffer = <<>>,
                final_size = undefined
            },
            NewState = State#state{
                next_stream_id_uni = NextId + 4,
                streams = maps:put(NextId, StreamState, Streams)
            },
            {ok, NextId, NewState}
    end.

%% Max stream data per packet (leave room for headers, frame overhead, AEAD tag)
%% 1200 (min MTU for QUIC) - ~50 bytes overhead = ~1150 bytes
-define(MAX_STREAM_DATA_PER_PACKET, 1100).

%% Send data on a stream (with fragmentation for large data)
do_send_data(StreamId, Data, Fin, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            DataBin = iolist_to_binary(Data),
            Offset = StreamState#stream_state.send_offset,

            %% Fragment and send data
            NewState = send_stream_data_fragmented(StreamId, Offset, DataBin, Fin, State),

            %% Update stream state
            NewStreamState = StreamState#stream_state{
                send_offset = Offset + byte_size(DataBin),
                send_fin = Fin
            },

            {ok, NewState#state{
                streams = maps:put(StreamId, NewStreamState, Streams)
            }};
        error ->
            {error, unknown_stream}
    end.

%% Estimate packet overhead (header + AEAD tag + frame header)
-define(PACKET_OVERHEAD, 50).

%% Send stream data in fragments that fit in packets
%% Respects congestion window by checking before each send
send_stream_data_fragmented(StreamId, Offset, Data, Fin, State) when byte_size(Data) =< ?MAX_STREAM_DATA_PER_PACKET ->
    %% Data fits in one packet - check congestion window
    #state{cc_state = CCState} = State,
    PacketSize = byte_size(Data) + ?PACKET_OVERHEAD,

    case quic_cc:can_send(CCState, PacketSize) of
        true ->
            Frame = {stream, StreamId, Offset, Data, Fin},
            Payload = quic_frame:encode(Frame),
            send_app_packet_internal(Payload, [Frame], State);
        false ->
            %% Queue the data for later sending when cwnd allows
            queue_stream_data(StreamId, Offset, Data, Fin, State)
    end;
send_stream_data_fragmented(StreamId, Offset, Data, Fin, State) ->
    %% Split data into chunks and send what we can
    #state{cc_state = CCState} = State,
    PacketSize = ?MAX_STREAM_DATA_PER_PACKET + ?PACKET_OVERHEAD,

    case quic_cc:can_send(CCState, PacketSize) of
        true ->
            <<Chunk:?MAX_STREAM_DATA_PER_PACKET/binary, Rest/binary>> = Data,
            Frame = {stream, StreamId, Offset, Chunk, false},
            Payload = quic_frame:encode(Frame),
            State1 = send_app_packet_internal(Payload, [Frame], State),
            NewOffset = Offset + ?MAX_STREAM_DATA_PER_PACKET,
            send_stream_data_fragmented(StreamId, NewOffset, Rest, Fin, State1);
        false ->
            %% Queue remaining data for later
            queue_stream_data(StreamId, Offset, Data, Fin, State)
    end.

%% Queue stream data when congestion window is full
queue_stream_data(StreamId, Offset, Data, Fin, #state{send_queue = Queue} = State) ->
    QueueEntry = {stream_data, StreamId, Offset, Data, Fin},
    State#state{send_queue = Queue ++ [QueueEntry]}.

%% Process send queue when congestion window frees up
process_send_queue(#state{send_queue = []} = State) ->
    State;
process_send_queue(#state{send_queue = [{stream_data, StreamId, Offset, Data, Fin} | Rest]} = State) ->
    %% Try to send the queued data
    State1 = State#state{send_queue = Rest},
    State2 = send_stream_data_fragmented(StreamId, Offset, Data, Fin, State1),
    %% If data was queued again (cwnd still full), stop processing
    case State2#state.send_queue of
        [_ | _] -> State2;  % Queue has items, stop for now
        [] -> process_send_queue(State2)  % Keep processing
    end.

%% Send HTTP/3 headers on a stream
do_send_headers(_StreamId, _Headers, _Fin, State) ->
    %% TODO: Encode headers using QPACK and send
    {ok, State}.

%% Close a stream
do_close_stream(StreamId, ErrorCode, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            %% Send RESET_STREAM frame
            FinalSize = StreamState#stream_state.send_offset,
            ResetFrame = quic_frame:encode({reset_stream, StreamId, ErrorCode, FinalSize}),
            NewState = send_app_packet(ResetFrame, State),
            {ok, NewState#state{
                streams = maps:remove(StreamId, Streams)
            }};
        error ->
            {error, unknown_stream}
    end.

%% Initiate connection close
initiate_close(Reason, State) ->
    %% Send CONNECTION_CLOSE frame
    ErrorCode = case Reason of
        normal -> ?QUIC_NO_ERROR;
        _ -> ?QUIC_APPLICATION_ERROR
    end,
    CloseFrame = quic_frame:encode({connection_close, application, ErrorCode, undefined, <<>>}),

    case State#state.app_keys of
        undefined ->
            State#state{close_reason = Reason};
        _ ->
            send_app_packet(CloseFrame, State#state{close_reason = Reason})
    end.

%% Check timeouts
check_timeouts(State) ->
    Now = erlang:monotonic_time(millisecond),
    TimeSinceActivity = Now - State#state.last_activity,
    if
        TimeSinceActivity > State#state.idle_timeout ->
            initiate_close(idle_timeout, State);
        true ->
            State
    end.

%%====================================================================
%% Retransmission
%%====================================================================

%% Retransmit frames from lost packets
retransmit_lost_packets([], State) ->
    State;
retransmit_lost_packets([#sent_packet{frames = Frames} | Rest], State) ->
    RetransmitFrames = quic_loss:retransmittable_frames(Frames),
    State1 = send_retransmit_frames(RetransmitFrames, State),
    retransmit_lost_packets(Rest, State1).

%% Send frames for retransmission
send_retransmit_frames([], State) ->
    State;
send_retransmit_frames(Frames, State) ->
    %% Encode all frames and send in a single packet
    Payload = iolist_to_binary([quic_frame:encode(F) || F <- Frames]),
    send_app_packet_internal(Payload, Frames, State).

%% Handle PTO timeout - send probe packet
handle_pto_timeout(#state{loss_state = LossState} = State) ->
    %% Increment PTO count
    NewLossState = quic_loss:on_pto_expired(LossState),
    State1 = State#state{loss_state = NewLossState},

    %% Send probe packet (retransmit oldest unacked or send PING)
    State2 = send_probe_packet(State1),

    %% Set new PTO timer
    set_pto_timer(State2).

%% Send a probe packet for PTO
send_probe_packet(State) ->
    case get_oldest_unacked_frames(State) of
        {ok, Frames} ->
            %% Retransmit oldest data as probe
            send_retransmit_frames(Frames, State);
        none ->
            %% No data to retransmit, send PING
            Payload = quic_frame:encode(ping),
            send_app_packet_internal(Payload, [ping], State)
    end.

%% Get frames from the oldest unacked packet for probe retransmission
get_oldest_unacked_frames(#state{loss_state = LossState}) ->
    SentPackets = quic_loss:sent_packets(LossState),
    case maps:size(SentPackets) of
        0 ->
            none;
        _ ->
            %% Find the oldest packet (lowest PN)
            {_MinPN, OldestPacket} = maps:fold(
                fun(PN, Packet, undefined) ->
                        {PN, Packet};
                   (PN, Packet, {MinPN, _}) when PN < MinPN ->
                        {PN, Packet};
                   (_PN, _Packet, Acc) ->
                        Acc
                end,
                undefined,
                SentPackets
            ),
            #sent_packet{frames = Frames} = OldestPacket,
            RetransmitFrames = quic_loss:retransmittable_frames(Frames),
            case RetransmitFrames of
                [] -> none;
                _ -> {ok, RetransmitFrames}
            end
    end.

%%====================================================================
%% PTO Timer Management
%%====================================================================

%% Set PTO timer based on current loss state
set_pto_timer(#state{loss_state = LossState, pto_timer = OldTimer} = State) ->
    cancel_timer(OldTimer),
    case quic_loss:bytes_in_flight(LossState) > 0 of
        true ->
            PTO = quic_loss:get_pto(LossState),
            TimerRef = erlang:send_after(PTO, self(), pto_timeout),
            State#state{pto_timer = TimerRef};
        false ->
            State#state{pto_timer = undefined}
    end.

%% Cancel PTO timer
cancel_pto_timer(#state{pto_timer = undefined} = State) ->
    State;
cancel_pto_timer(#state{pto_timer = Ref} = State) ->
    cancel_timer(Ref),
    State#state{pto_timer = undefined}.

%% Helper to cancel a timer reference
cancel_timer(undefined) -> ok;
cancel_timer(Ref) -> erlang:cancel_timer(Ref).

%% Convert state to map for debugging
state_to_map(#state{} = S) ->
    #{
        scid => S#state.scid,
        dcid => S#state.dcid,
        role => S#state.role,
        version => S#state.version,
        tls_state => S#state.tls_state,
        alpn => S#state.alpn,
        streams => maps:size(S#state.streams),
        data_sent => S#state.data_sent,
        data_received => S#state.data_received
    }.

%% Normalize ALPN list - handles binary, list of binaries, list of strings
normalize_alpn_list(undefined) ->
    [];
normalize_alpn_list(V) when is_binary(V) ->
    [V];
normalize_alpn_list([]) ->
    [];
normalize_alpn_list([H|_] = L) when is_binary(H) ->
    L;
normalize_alpn_list([H|_] = L) when is_list(H) ->
    [list_to_binary(S) || S <- L];
normalize_alpn_list([H|_] = L) when is_atom(H) ->
    [atom_to_binary(A, utf8) || A <- L];
normalize_alpn_list(_) ->
    [].

%%====================================================================
%% Key Update (RFC 9001 Section 6)
%%====================================================================

%% @doc Initiate a key update.
%% Derives new application secrets and keys, switches to the new key phase.
initiate_key_update(#state{key_state = KeyState} = State) ->
    #key_update_state{
        current_phase = CurrentPhase,
        current_keys = CurrentKeys,
        client_app_secret = ClientSecret,
        server_app_secret = ServerSecret
    } = KeyState,

    %% Get cipher from current keys
    {ClientKeys, _} = CurrentKeys,
    Cipher = ClientKeys#crypto_keys.cipher,

    %% Derive new secrets using "quic ku" label
    {NewClientSecret, {NewClientKey, NewClientIV, NewClientHP}} =
        quic_keys:derive_updated_keys(ClientSecret, Cipher),
    {NewServerSecret, {NewServerKey, NewServerIV, NewServerHP}} =
        quic_keys:derive_updated_keys(ServerSecret, Cipher),

    %% Create new crypto_keys records
    NewClientKeys = #crypto_keys{
        key = NewClientKey,
        iv = NewClientIV,
        hp = NewClientHP,
        cipher = Cipher
    },
    NewServerKeys = #crypto_keys{
        key = NewServerKey,
        iv = NewServerIV,
        hp = NewServerHP,
        cipher = Cipher
    },

    %% Toggle key phase
    NewPhase = 1 - CurrentPhase,

    %% Update key state
    NewKeyState = KeyState#key_update_state{
        current_phase = NewPhase,
        current_keys = {NewClientKeys, NewServerKeys},
        prev_keys = CurrentKeys,  % Keep old keys for decryption during transition
        client_app_secret = NewClientSecret,
        server_app_secret = NewServerSecret,
        update_state = initiated
    },

    State#state{
        app_keys = {NewClientKeys, NewServerKeys},
        key_state = NewKeyState
    }.

%% @doc Handle receiving a packet with a different key phase.
%% This is called when we receive a packet with a key phase that differs
%% from our current phase, indicating the peer has initiated a key update.
handle_peer_key_update(#state{key_state = KeyState} = State) ->
    #key_update_state{
        current_phase = CurrentPhase,
        current_keys = CurrentKeys,
        client_app_secret = ClientSecret,
        server_app_secret = ServerSecret,
        update_state = UpdateState
    } = KeyState,

    case UpdateState of
        initiated ->
            %% We initiated, peer responded - complete the update
            NewKeyState = KeyState#key_update_state{
                prev_keys = undefined,
                update_state = idle
            },
            State#state{key_state = NewKeyState};
        idle ->
            %% Peer initiated - we need to respond by deriving new keys
            {ClientKeys, _} = CurrentKeys,
            Cipher = ClientKeys#crypto_keys.cipher,

            %% Derive new secrets
            {NewClientSecret, {NewClientKey, NewClientIV, NewClientHP}} =
                quic_keys:derive_updated_keys(ClientSecret, Cipher),
            {NewServerSecret, {NewServerKey, NewServerIV, NewServerHP}} =
                quic_keys:derive_updated_keys(ServerSecret, Cipher),

            NewClientKeys = #crypto_keys{
                key = NewClientKey,
                iv = NewClientIV,
                hp = NewClientHP,
                cipher = Cipher
            },
            NewServerKeys = #crypto_keys{
                key = NewServerKey,
                iv = NewServerIV,
                hp = NewServerHP,
                cipher = Cipher
            },

            NewPhase = 1 - CurrentPhase,
            NewKeyState = KeyState#key_update_state{
                current_phase = NewPhase,
                current_keys = {NewClientKeys, NewServerKeys},
                prev_keys = CurrentKeys,
                client_app_secret = NewClientSecret,
                server_app_secret = NewServerSecret,
                update_state = responding
            },
            State#state{
                app_keys = {NewClientKeys, NewServerKeys},
                key_state = NewKeyState
            };
        responding ->
            %% Already responding, just continue
            State
    end.

%% @doc Complete a key update after receiving an ACK for a packet with new keys.
%% Discards the previous keys.
complete_key_update(#state{key_state = KeyState} = State) ->
    NewKeyState = KeyState#key_update_state{
        prev_keys = undefined,
        update_state = idle
    },
    State#state{key_state = NewKeyState}.

%% @doc Select the appropriate keys for decryption based on the received key phase.
%% Returns {Keys, State} where State may be updated if a key update is detected.
select_decrypt_keys(_ReceivedKeyPhase, #state{key_state = undefined} = State) ->
    %% No key state yet, use app_keys directly (should not happen in practice)
    {State#state.app_keys, State};
select_decrypt_keys(ReceivedKeyPhase, #state{key_state = KeyState} = State) ->
    #key_update_state{
        current_phase = CurrentPhase,
        current_keys = CurrentKeys,
        prev_keys = PrevKeys
    } = KeyState,

    case ReceivedKeyPhase of
        CurrentPhase ->
            %% Same phase, use current keys
            {CurrentKeys, State};
        _ ->
            %% Different phase - could be peer initiating update or using prev keys
            case PrevKeys of
                undefined ->
                    %% No previous keys, peer is initiating update
                    %% Handle the key update and decrypt with new keys
                    State1 = handle_peer_key_update(State),
                    {State1#state.key_state#key_update_state.current_keys, State1};
                _ ->
                    %% Try previous keys (during transition period)
                    {PrevKeys, State}
            end
    end.

%% @doc Get the current key phase for sending.
get_current_key_phase(#state{key_state = undefined}) -> 0;
get_current_key_phase(#state{key_state = KeyState}) ->
    KeyState#key_update_state.current_phase.

%%====================================================================
%% Connection Migration (RFC 9000 Section 9)
%%====================================================================

%% @doc Initiate path validation by sending PATH_CHALLENGE.
%% Returns updated state with the path in validating status.
-spec initiate_path_validation({inet:ip_address(), inet:port_number()}, #state{}) -> #state{}.
initiate_path_validation(RemoteAddr, State) ->
    %% Generate 8-byte random challenge data
    ChallengeData = crypto:strong_rand_bytes(8),

    %% Create or update path state
    PathState = #path_state{
        remote_addr = RemoteAddr,
        status = validating,
        challenge_data = ChallengeData,
        challenge_count = 1,
        bytes_sent = 0,
        bytes_received = 0
    },

    %% Add to alternative paths
    AltPaths = [PathState | State#state.alt_paths],

    %% Send PATH_CHALLENGE frame
    ChallengeFrame = quic_frame:encode({path_challenge, ChallengeData}),
    State1 = State#state{alt_paths = AltPaths},

    %% Note: In a full implementation, we'd send to the specific path
    %% For now, send on the current path (for testing)
    send_app_packet(ChallengeFrame, State1).

%% @doc Handle PATH_RESPONSE frame.
%% Validates the response against pending challenges.
handle_path_response(ResponseData, State) ->
    %% Find the path with matching challenge data
    case find_path_by_challenge(ResponseData, State#state.alt_paths) of
        {ok, PathState, OtherPaths} ->
            %% Mark path as validated
            ValidatedPath = PathState#path_state{
                status = validated,
                challenge_data = undefined
            },
            State#state{alt_paths = [ValidatedPath | OtherPaths]};
        not_found ->
            %% Check current path (if we sent challenge on current path)
            case State#state.current_path of
                #path_state{challenge_data = ResponseData} = CurrentPath ->
                    ValidatedPath = CurrentPath#path_state{
                        status = validated,
                        challenge_data = undefined
                    },
                    State#state{current_path = ValidatedPath};
                _ ->
                    %% Unknown response, ignore
                    State
            end
    end.

%% Find a path by challenge data
find_path_by_challenge(_Data, []) ->
    not_found;
find_path_by_challenge(Data, [#path_state{challenge_data = Data} = Path | Rest]) ->
    {ok, Path, Rest};
find_path_by_challenge(Data, [Path | Rest]) ->
    case find_path_by_challenge(Data, Rest) of
        {ok, Found, Others} ->
            {ok, Found, [Path | Others]};
        not_found ->
            not_found
    end.

%% @doc Complete migration to a validated path.
%% Updates the current path and DCID if necessary.
-spec complete_migration(#path_state{}, #state{}) -> #state{}.
complete_migration(#path_state{status = validated} = NewPath, State) ->
    %% Update remote address
    State#state{
        remote_addr = NewPath#path_state.remote_addr,
        current_path = NewPath,
        alt_paths = lists:delete(NewPath, State#state.alt_paths)
    };
complete_migration(_, State) ->
    %% Can only migrate to validated paths
    State.

%% @doc Check if we can send data to a path (anti-amplification).
%% RFC 9000 Section 8.1: Can only send 3x received bytes on unvalidated path.
-spec can_send_to_path(#path_state{}, non_neg_integer(), #state{}) -> boolean().
can_send_to_path(#path_state{status = validated}, _Size, _State) ->
    true;
can_send_to_path(#path_state{bytes_sent = Sent, bytes_received = Recv}, Size, _State) ->
    (Sent + Size) =< (Recv * 3).

%% @doc Handle NEW_CONNECTION_ID frame from peer.
%% Adds the new CID to our pool of peer CIDs.
handle_new_connection_id(SeqNum, RetirePrior, CID, ResetToken, State) ->
    #state{peer_cid_pool = Pool, active_cid_limit = Limit} = State,

    %% Retire CIDs with seq < RetirePrior
    RetiredPool = lists:map(
        fun(#cid_entry{seq_num = S} = Entry) when S < RetirePrior ->
                Entry#cid_entry{status = retired};
           (Entry) ->
                Entry
        end, Pool),

    %% Add new CID entry
    NewEntry = #cid_entry{
        seq_num = SeqNum,
        cid = CID,
        stateless_reset_token = ResetToken,
        status = active
    },

    %% Check if already exists
    case lists:keyfind(SeqNum, #cid_entry.seq_num, RetiredPool) of
        false ->
            %% Add new entry, keeping within limit
            NewPool = [NewEntry | RetiredPool],
            ActiveCount = length([E || #cid_entry{status = active} = E <- NewPool]),
            FinalPool = if
                ActiveCount > Limit ->
                    %% Remove oldest active CID if over limit
                    trim_cid_pool(NewPool, Limit);
                true ->
                    NewPool
            end,
            %% Send RETIRE_CONNECTION_ID for CIDs with seq < RetirePrior
            State1 = retire_peer_cids(RetirePrior, State#state{peer_cid_pool = FinalPool}),
            State1;
        _ ->
            %% Duplicate, ignore
            State#state{peer_cid_pool = RetiredPool}
    end.

%% Trim CID pool to active limit by retiring oldest
trim_cid_pool(Pool, Limit) ->
    Active = [E || #cid_entry{status = active} = E <- Pool],
    Retired = [E || #cid_entry{status = retired} = E <- Pool],
    Sorted = lists:sort(fun(A, B) -> A#cid_entry.seq_num < B#cid_entry.seq_num end, Active),
    case length(Sorted) > Limit of
        true ->
            {ToRetire, ToKeep} = lists:split(length(Sorted) - Limit, Sorted),
            NewRetired = [E#cid_entry{status = retired} || E <- ToRetire],
            NewRetired ++ ToKeep ++ Retired;
        false ->
            Pool
    end.

%% Send RETIRE_CONNECTION_ID frames for CIDs that need to be retired
retire_peer_cids(_RetirePrior, State) ->
    %% In a full implementation, send RETIRE_CONNECTION_ID frames
    %% For now, just return state
    State.

%% @doc Handle RETIRE_CONNECTION_ID frame from peer.
%% Marks the specified CID in our local pool as retired.
handle_retire_connection_id(SeqNum, State) ->
    #state{local_cid_pool = Pool} = State,
    NewPool = lists:map(
        fun(#cid_entry{seq_num = S} = Entry) when S =:= SeqNum ->
                Entry#cid_entry{status = retired};
           (Entry) ->
                Entry
        end, Pool),
    State#state{local_cid_pool = NewPool}.

%% @doc Issue a new connection ID to the peer.
%% Sends NEW_CONNECTION_ID frame with a new CID.
issue_new_connection_id(State) ->
    #state{
        local_cid_pool = Pool,
        local_cid_seq = Seq,
        active_cid_limit = Limit
    } = State,

    %% Check if we can issue more CIDs
    ActiveCount = length([E || #cid_entry{status = active} = E <- Pool]),
    case ActiveCount < Limit of
        true ->
            %% Generate new CID and reset token
            NewCID = crypto:strong_rand_bytes(8),
            ResetToken = crypto:strong_rand_bytes(16),

            NewEntry = #cid_entry{
                seq_num = Seq,
                cid = NewCID,
                stateless_reset_token = ResetToken,
                status = active
            },

            %% Send NEW_CONNECTION_ID frame
            Frame = quic_frame:encode({new_connection_id, Seq, 0, NewCID, ResetToken}),
            State1 = State#state{
                local_cid_pool = [NewEntry | Pool],
                local_cid_seq = Seq + 1
            },
            send_app_packet(Frame, State1);
        false ->
            State
    end.

%% @doc Get an active peer CID for use.
%% Returns the CID with the lowest active sequence number.
get_active_peer_cid(#state{peer_cid_pool = Pool, dcid = CurrentDCID}) ->
    Active = [E || #cid_entry{status = active} = E <- Pool],
    case Active of
        [] ->
            CurrentDCID;  % Fall back to current DCID
        _ ->
            Sorted = lists:sort(fun(A, B) ->
                A#cid_entry.seq_num < B#cid_entry.seq_num
            end, Active),
            (hd(Sorted))#cid_entry.cid
    end.
