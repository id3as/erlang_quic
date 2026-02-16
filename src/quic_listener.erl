%%% -*- erlang -*-
%%%
%%% QUIC Listener
%%% RFC 9000 Section 5 - Connections
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC server listener for accepting connections.
%%%
%%% This module handles:
%%% - UDP socket management
%%% - Initial packet routing to connections
%%% - Connection ID management
%%% - Stateless retry (optional)

-module(quic_listener).
-behaviour(gen_server).

%% Suppress warnings for functions prepared for future use
-compile([{nowarn_unused_function, [{register_cid, 3}, {unregister_cid, 2}]}]).
-dialyzer({nowarn_function, [register_cid/3, unregister_cid/2]}).

-export([
    start_link/2,
    stop/1,
    get_port/1,
    get_connections/1
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-include("quic.hrl").

-record(listener_state, {
    socket :: gen_udp:socket(),
    port :: inet:port_number(),
    cert :: binary(),
    cert_chain :: [binary()],
    private_key :: term(),
    alpn_list :: [binary()],
    %% Connection ID -> Pid mapping
    connections :: ets:tid(),
    %% Options
    opts :: map()
}).

%%====================================================================
%% API
%%====================================================================

%% @doc Start a QUIC listener on the given port.
%% Options:
%%   - cert: Server certificate (DER binary)
%%   - cert_chain: Certificate chain [binary()]
%%   - key: Private key
%%   - alpn: List of supported ALPN protocols
-spec start_link(inet:port_number(), map()) -> {ok, pid()} | {error, term()}.
start_link(Port, Opts) ->
    gen_server:start_link(?MODULE, {Port, Opts}, []).

%% @doc Stop the listener.
-spec stop(pid()) -> ok.
stop(Listener) ->
    gen_server:stop(Listener).

%% @doc Get the port the listener is bound to.
-spec get_port(pid()) -> inet:port_number().
get_port(Listener) ->
    gen_server:call(Listener, get_port).

%% @doc Get list of active connections.
-spec get_connections(pid()) -> [pid()].
get_connections(Listener) ->
    gen_server:call(Listener, get_connections).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init({Port, Opts}) ->
    process_flag(trap_exit, true),

    %% Extract required options
    Cert = maps:get(cert, Opts),
    CertChain = maps:get(cert_chain, Opts, []),
    PrivateKey = maps:get(key, Opts),
    ALPNList = maps:get(alpn, Opts, [<<"h3">>]),

    %% Open UDP socket
    SocketOpts = [
        binary,
        {active, true},
        {reuseaddr, true}
    ],

    case gen_udp:open(Port, SocketOpts) of
        {ok, Socket} ->
            %% Get actual port (useful if Port was 0)
            {ok, ActualPort} = inet:port(Socket),

            %% Create ETS table for connection tracking
            Connections = ets:new(quic_connections, [set, protected]),

            State = #listener_state{
                socket = Socket,
                port = ActualPort,
                cert = Cert,
                cert_chain = CertChain,
                private_key = PrivateKey,
                alpn_list = ALPNList,
                connections = Connections,
                opts = Opts
            },
            {ok, State};
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(get_port, _From, #listener_state{port = Port} = State) ->
    {reply, Port, State};

handle_call(get_connections, _From, #listener_state{connections = Conns} = State) ->
    Pids = ets:foldl(fun({_CID, Pid}, Acc) -> [Pid | Acc] end, [], Conns),
    {reply, lists:usort(Pids), State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Handle incoming UDP packets
handle_info({udp, Socket, SrcIP, SrcPort, Packet},
            #listener_state{socket = Socket} = State) ->
    handle_packet(Packet, {SrcIP, SrcPort}, State),
    {noreply, State};

%% Handle connection process exit
handle_info({'EXIT', Pid, _Reason}, #listener_state{connections = Conns} = State) ->
    %% Remove all CIDs associated with this connection
    ToDelete = ets:foldl(
        fun({CID, ConnPid}, Acc) when ConnPid =:= Pid -> [CID | Acc];
           (_, Acc) -> Acc
        end, [], Conns),
    lists:foreach(fun(CID) -> ets:delete(Conns, CID) end, ToDelete),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #listener_state{socket = Socket, connections = Conns}) ->
    gen_udp:close(Socket),
    ets:delete(Conns),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal Functions
%%====================================================================

handle_packet(Packet, RemoteAddr, State) ->
    case parse_packet_header(Packet) of
        {initial, DCID, _SCID, _Rest} ->
            handle_initial_packet(Packet, DCID, RemoteAddr, State);
        {short, DCID, _Rest} ->
            route_to_connection(DCID, Packet, RemoteAddr, State);
        {long, DCID, _SCID, _PacketType, _Rest} ->
            route_to_connection(DCID, Packet, RemoteAddr, State);
        {error, _Reason} ->
            %% Drop malformed packets
            ok
    end.

%% Parse packet header to extract DCID for routing
parse_packet_header(<<1:1, _:7, _Version:32, DCIDLen, DCID:DCIDLen/binary,
                      SCIDLen, SCID:SCIDLen/binary, Rest/binary>>) ->
    %% Long header - check packet type
    <<_:1, PacketType:2, _:5, _/binary>> = <<1:1, 0:7>>,
    case PacketType of
        0 -> {initial, DCID, SCID, Rest};
        _ -> {long, DCID, SCID, PacketType, Rest}
    end;
parse_packet_header(<<0:1, _:7, Rest/binary>>) ->
    %% Short header - DCID length is connection-specific
    %% For now, assume 8-byte DCID
    case Rest of
        <<DCID:8/binary, Remaining/binary>> ->
            {short, DCID, Remaining};
        _ ->
            {error, short_header_too_small}
    end;
parse_packet_header(_) ->
    {error, invalid_header}.

%% Handle Initial packet - may create new connection
handle_initial_packet(Packet, DCID, RemoteAddr,
                      #listener_state{connections = Conns} = State) ->
    case ets:lookup(Conns, DCID) of
        [{DCID, ConnPid}] ->
            %% Existing connection
            send_to_connection(ConnPid, Packet, RemoteAddr);
        [] ->
            %% New connection
            create_connection(Packet, DCID, RemoteAddr, State)
    end.

%% Route packet to existing connection
route_to_connection(DCID, Packet, RemoteAddr, #listener_state{connections = Conns}) ->
    case ets:lookup(Conns, DCID) of
        [{DCID, ConnPid}] ->
            send_to_connection(ConnPid, Packet, RemoteAddr);
        [] ->
            %% Unknown connection - drop packet
            ok
    end.

%% Create a new server-side connection
create_connection(Packet, DCID, RemoteAddr,
                  #listener_state{
                      socket = Socket,
                      cert = Cert,
                      cert_chain = CertChain,
                      private_key = PrivateKey,
                      alpn_list = ALPNList,
                      connections = Conns,
                      opts = Opts
                  }) ->
    %% Generate server connection ID
    ServerCID = crypto:strong_rand_bytes(8),

    %% Start connection process
    ConnOpts = #{
        role => server,
        socket => Socket,
        remote_addr => RemoteAddr,
        initial_dcid => DCID,
        scid => ServerCID,
        cert => Cert,
        cert_chain => CertChain,
        private_key => PrivateKey,
        alpn => ALPNList,
        listener => self()
    },

    case quic_connection:start_server(maps:merge(Opts, ConnOpts)) of
        {ok, ConnPid} ->
            %% Link to monitor connection
            link(ConnPid),

            %% Register connection ID
            ets:insert(Conns, {DCID, ConnPid}),
            ets:insert(Conns, {ServerCID, ConnPid}),

            %% Send initial packet to new connection
            send_to_connection(ConnPid, Packet, RemoteAddr),

            {ok, ConnPid};
        {error, Reason} ->
            {error, Reason}
    end.

send_to_connection(ConnPid, Packet, RemoteAddr) ->
    ConnPid ! {quic_packet, Packet, RemoteAddr}.

%% @doc Register an additional connection ID for a connection
-spec register_cid(pid(), binary(), pid()) -> ok.
register_cid(Listener, CID, ConnPid) ->
    gen_server:cast(Listener, {register_cid, CID, ConnPid}).

%% @doc Unregister a connection ID
-spec unregister_cid(pid(), binary()) -> ok.
unregister_cid(Listener, CID) ->
    gen_server:cast(Listener, {unregister_cid, CID}).
