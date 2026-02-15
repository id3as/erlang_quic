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

%% API
-export([
    start_link/4,
    start_link/5,
    connect/4,
    send_data/4,
    send_headers/4,
    open_stream/1,
    close/2,
    close_stream/3,
    handle_timeout/1,
    process/1,
    get_state/1
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

    %% Encryption keys per level
    initial_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,
    handshake_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,
    app_keys :: {#crypto_keys{}, #crypto_keys{}} | undefined,

    %% TLS state
    tls_state :: term(),
    crypto_buffer = #{} :: #{atom() => binary()},
    alpn :: binary() | undefined,

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

    %% Pending data
    send_queue = [] :: [term()],

    %% Close reason
    close_reason :: term()
}).

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

%% @doc Close the connection.
-spec close(pid(), term()) -> ok.
close(Conn, Reason) ->
    gen_statem:cast(Conn, {close, Reason}).

%% @doc Close a specific stream.
-spec close_stream(pid(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
close_stream(Conn, StreamId, ErrorCode) ->
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

    %% Create connection reference
    ConnRef = make_ref(),

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
        initial_keys = InitialKeys,
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
        alpn = maps:get(alpn, Opts, undefined)
    },

    {ok, idle, State}.

terminate(_Reason, _StateName, #state{socket = Socket}) ->
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
    %% Start the handshake by sending Initial packet
    NewState = send_initial_crypto(State),
    {keep_state, NewState};

idle({call, From}, get_ref, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

idle({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {idle, state_to_map(State)}}]};

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

handshaking(info, {udp, Socket, _IP, _Port, Data}, #state{socket = Socket} = State) ->
    NewState = handle_packet(Data, State),
    check_state_transition(handshaking, NewState);

handshaking(cast, process, State) ->
    inet:setopts(State#state.socket, [{active, once}]),
    {keep_state, State};

handshaking(EventType, EventContent, State) ->
    handle_common_event(EventType, EventContent, handshaking, State).

%% ----- CONNECTED STATE -----

connected(enter, handshaking, #state{owner = Owner, conn_ref = Ref} = State) ->
    %% Notify owner that connection is established
    Owner ! {quic, Ref, {connected, #{alpn => State#state.alpn}}},
    {keep_state, State};

connected({call, From}, get_ref, #state{conn_ref = Ref} = State) ->
    {keep_state, State, [{reply, From, Ref}]};

connected({call, From}, get_state, State) ->
    {keep_state, State, [{reply, From, {connected, state_to_map(State)}}]};

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

connected({call, From}, {close_stream, StreamId, ErrorCode}, State) ->
    case do_close_stream(StreamId, ErrorCode, State) of
        {ok, NewState} ->
            {keep_state, NewState, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
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

handle_common_event(info, {'EXIT', _Pid, _Reason}, _StateName, State) ->
    {keep_state, State};

handle_common_event(_EventType, _EventContent, _StateName, State) ->
    {keep_state, State}.

%%====================================================================
%% Internal Functions
%%====================================================================

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

%% Send initial CRYPTO frame with ClientHello
send_initial_crypto(State) ->
    %% Generate ECDHE key pair
    {_PubKey, _PrivKey} = quic_crypto:generate_key_pair(x25519),

    %% For now, create a minimal CRYPTO frame placeholder
    %% Full TLS 1.3 ClientHello encoding would go here
    CryptoData = <<>>,

    %% Build Initial packet with CRYPTO frame
    _Frame = quic_frame:encode({crypto, 0, CryptoData}),

    %% Enable socket for receiving
    inet:setopts(State#state.socket, [{active, once}]),

    State.

%% Handle incoming packet
handle_packet(Data, State) ->
    case quic_packet:decode(Data, 8) of
        {ok, Packet, _Rest} ->
            process_packet(Packet, State);
        {error, _Reason} ->
            State
    end.

%% Process decoded packet
process_packet(#quic_packet{type = initial} = _Packet, State) ->
    %% Process Initial packet
    %% TODO: Decrypt and process frames
    State;
process_packet(#quic_packet{type = handshake} = _Packet, State) ->
    %% Process Handshake packet
    State;
process_packet(#quic_packet{type = one_rtt} = _Packet, State) ->
    %% Process 1-RTT packet
    State;
process_packet(_Packet, State) ->
    State.

%% Check if we should transition to a new state
check_state_transition(CurrentState, State) ->
    case {CurrentState, has_handshake_keys(State), has_app_keys(State)} of
        {idle, true, _} ->
            {next_state, handshaking, State};
        {handshaking, _, true} ->
            {next_state, connected, State};
        _ ->
            {keep_state, State}
    end.

has_handshake_keys(#state{handshake_keys = undefined}) -> false;
has_handshake_keys(_) -> true.

has_app_keys(#state{app_keys = undefined}) -> false;
has_app_keys(_) -> true.

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

%% Send data on a stream
do_send_data(StreamId, Data, Fin, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, StreamState} ->
            %% Queue data for sending
            DataBin = iolist_to_binary(Data),
            NewStreamState = StreamState#stream_state{
                send_buffer = [StreamState#stream_state.send_buffer | DataBin],
                send_fin = Fin
            },
            NewState = State#state{
                streams = maps:put(StreamId, NewStreamState, Streams)
            },
            %% TODO: Actually send the data in STREAM frames
            {ok, NewState};
        error ->
            {error, unknown_stream}
    end.

%% Send HTTP/3 headers on a stream
do_send_headers(_StreamId, _Headers, _Fin, State) ->
    %% TODO: Encode headers using QPACK and send
    {ok, State}.

%% Close a stream
do_close_stream(StreamId, ErrorCode, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, _StreamState} ->
            %% Send RESET_STREAM frame
            _Frame = quic_frame:encode({reset_stream, StreamId, ErrorCode, 0}),
            %% TODO: Actually send the frame
            NewState = State#state{
                streams = maps:remove(StreamId, Streams)
            },
            {ok, NewState};
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
    _Frame = quic_frame:encode({connection_close, ErrorCode, 0, <<>>}),
    %% TODO: Actually send the frame
    State#state{close_reason = Reason}.

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

%% Convert state to map for debugging
state_to_map(#state{} = S) ->
    #{
        scid => S#state.scid,
        dcid => S#state.dcid,
        role => S#state.role,
        version => S#state.version,
        streams => maps:size(S#state.streams),
        data_sent => S#state.data_sent,
        data_received => S#state.data_received
    }.
