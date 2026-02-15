%%% -*- erlang -*-
%%%
%%% Tests for QUIC Loss Detection
%%%

-module(quic_loss_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Basic State Tests
%%====================================================================

new_state_test() ->
    State = quic_loss:new(),
    ?assertEqual(#{}, quic_loss:sent_packets(State)),
    ?assertEqual(0, quic_loss:bytes_in_flight(State)),
    ?assertEqual(0, quic_loss:pto_count(State)).

new_state_with_opts_test() ->
    State = quic_loss:new(#{max_ack_delay => 50}),
    ?assertEqual(0, quic_loss:bytes_in_flight(State)).

%%====================================================================
%% Packet Tracking Tests
%%====================================================================

on_packet_sent_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(State, 0, 1200, true),
    ?assertEqual(1200, quic_loss:bytes_in_flight(S1)),
    Sent = quic_loss:sent_packets(S1),
    ?assert(maps:is_key(0, Sent)).

on_packet_sent_multiple_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(State, 0, 1000, true),
    S2 = quic_loss:on_packet_sent(S1, 1, 500, true),
    S3 = quic_loss:on_packet_sent(S2, 2, 300, true),
    ?assertEqual(1800, quic_loss:bytes_in_flight(S3)),
    ?assertEqual(3, maps:size(quic_loss:sent_packets(S3))).

non_ack_eliciting_no_bytes_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(State, 0, 100, false),
    ?assertEqual(0, quic_loss:bytes_in_flight(S1)).

%%====================================================================
%% RTT Tests
%%====================================================================

initial_rtt_test() ->
    State = quic_loss:new(),
    ?assertEqual(333, quic_loss:smoothed_rtt(State)).

first_rtt_sample_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),
    ?assertEqual(100, quic_loss:smoothed_rtt(S1)),
    ?assertEqual(50, quic_loss:rtt_var(S1)),
    ?assertEqual(100, quic_loss:min_rtt(S1)),
    ?assertEqual(100, quic_loss:latest_rtt(S1)).

rtt_update_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),
    S2 = quic_loss:update_rtt(S1, 120, 0),
    %% smoothed_rtt = 7/8 * 100 + 1/8 * 120 = 102.5 -> 102
    ?assertEqual(102, quic_loss:smoothed_rtt(S2)),
    ?assertEqual(100, quic_loss:min_rtt(S2)),
    ?assertEqual(120, quic_loss:latest_rtt(S2)).

rtt_with_ack_delay_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),
    %% Second sample with ACK delay
    S2 = quic_loss:update_rtt(S1, 150, 30),
    %% adjusted_rtt = 150 - 30 = 120 (since 150 > 100 + 30)
    %% But ACK delay is capped at max_ack_delay (25ms default)
    ?assert(quic_loss:smoothed_rtt(S2) > 100).

min_rtt_updates_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),
    S2 = quic_loss:update_rtt(S1, 80, 0),
    ?assertEqual(80, quic_loss:min_rtt(S2)),
    S3 = quic_loss:update_rtt(S2, 120, 0),
    ?assertEqual(80, quic_loss:min_rtt(S3)).

%%====================================================================
%% PTO Tests
%%====================================================================

initial_pto_test() ->
    State = quic_loss:new(),
    PTO = quic_loss:get_pto(State),
    %% Initial: smoothed_rtt=333, rtt_var=166, max_ack_delay=25
    %% PTO = 333 + max(4*166, 1) + 25 = 333 + 664 + 25 = 1022
    ?assertEqual(1022, PTO).

pto_after_rtt_sample_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 50, 0),
    PTO = quic_loss:get_pto(S1),
    %% smoothed_rtt=50, rtt_var=25, max_ack_delay=25
    %% PTO = 50 + max(4*25, 1) + 25 = 50 + 100 + 25 = 175
    ?assertEqual(175, PTO).

pto_exponential_backoff_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),
    PTO0 = quic_loss:get_pto(S1),

    S2 = quic_loss:on_pto_expired(S1),
    ?assertEqual(1, quic_loss:pto_count(S2)),
    PTO1 = quic_loss:get_pto(S2),
    ?assertEqual(PTO0 * 2, PTO1),

    S3 = quic_loss:on_pto_expired(S2),
    ?assertEqual(2, quic_loss:pto_count(S3)),
    PTO2 = quic_loss:get_pto(S3),
    ?assertEqual(PTO0 * 4, PTO2).

pto_reset_on_packet_sent_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_pto_expired(State),
    ?assertEqual(1, quic_loss:pto_count(S1)),
    S2 = quic_loss:on_packet_sent(S1, 0, 100, true),
    ?assertEqual(0, quic_loss:pto_count(S2)).

%%====================================================================
%% ACK Processing Tests
%%====================================================================

ack_single_packet_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(State, 0, 1000, true),
    AckFrame = {ack, 0, 0, 0, []},
    Now = erlang:monotonic_time(millisecond) + 50,
    {S2, Acked, Lost} = quic_loss:on_ack_received(S1, AckFrame, Now),
    ?assertEqual(1, length(Acked)),
    ?assertEqual(0, length(Lost)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S2)).

ack_multiple_packets_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(State, 0, 500, true),
    S2 = quic_loss:on_packet_sent(S1, 1, 500, true),
    S3 = quic_loss:on_packet_sent(S2, 2, 500, true),
    AckFrame = {ack, 2, 0, 2, []},  % Acks 0, 1, 2
    Now = erlang:monotonic_time(millisecond) + 50,
    {S4, Acked, _Lost} = quic_loss:on_ack_received(S3, AckFrame, Now),
    ?assertEqual(3, length(Acked)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S4)).

ack_updates_rtt_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(State, 0, 500, true),
    timer:sleep(10),
    Now = erlang:monotonic_time(millisecond),
    AckFrame = {ack, 0, 0, 0, []},
    {S2, _Acked, _Lost} = quic_loss:on_ack_received(S1, AckFrame, Now),
    %% RTT should be updated from the sample
    ?assert(quic_loss:latest_rtt(S2) >= 10).

%%====================================================================
%% Loss Detection Tests
%%====================================================================

loss_by_packet_threshold_test() ->
    State = quic_loss:new(),
    %% Send packets 0-5
    S1 = lists:foldl(
        fun(PN, Acc) ->
            quic_loss:on_packet_sent(Acc, PN, 100, true)
        end,
        State,
        lists:seq(0, 5)
    ),

    %% ACK only packet 5 (skipping 0-4)
    %% With packet threshold of 3, packets 0, 1, 2 should be lost
    AckFrame = {ack, 5, 0, 0, []},
    Now = erlang:monotonic_time(millisecond) + 1000,
    {_S2, _Acked, Lost} = quic_loss:on_ack_received(S1, AckFrame, Now),

    %% Packets 0, 1, 2 should be lost (5 - 3 = 2)
    LostPNs = [P#sent_packet.pn || P <- Lost],
    ?assert(lists:member(0, LostPNs)),
    ?assert(lists:member(1, LostPNs)),
    ?assert(lists:member(2, LostPNs)).

%%====================================================================
%% Loss Time Tests
%%====================================================================

get_loss_time_no_packets_test() ->
    State = quic_loss:new(),
    {LossTime, _Space} = quic_loss:get_loss_time_and_space(State),
    ?assertEqual(undefined, LossTime).

get_loss_time_with_packets_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(State, 0, 100, true),
    {LossTime, _Space} = quic_loss:get_loss_time_and_space(S1),
    ?assertNotEqual(undefined, LossTime).

%%====================================================================
%% Integration Tests
%%====================================================================

full_cycle_test() ->
    State = quic_loss:new(),

    %% Send some packets
    S1 = quic_loss:on_packet_sent(State, 0, 1000, true),
    S2 = quic_loss:on_packet_sent(S1, 1, 1000, true),
    ?assertEqual(2000, quic_loss:bytes_in_flight(S2)),

    %% Wait and receive ACK
    timer:sleep(10),
    Now = erlang:monotonic_time(millisecond),
    AckFrame = {ack, 1, 0, 1, []},
    {S3, Acked, _Lost} = quic_loss:on_ack_received(S2, AckFrame, Now),

    ?assertEqual(2, length(Acked)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S3)),
    ?assertEqual(0, quic_loss:pto_count(S3)).

%%====================================================================
%% ECN ACK Test
%%====================================================================

ack_ecn_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(State, 0, 500, true),
    AckFrame = {ack_ecn, 0, 0, 0, [], 10, 20, 5},
    Now = erlang:monotonic_time(millisecond) + 50,
    {S2, Acked, _Lost} = quic_loss:on_ack_received(S1, AckFrame, Now),
    ?assertEqual(1, length(Acked)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S2)).
