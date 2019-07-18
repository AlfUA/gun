-module(gun_socks5).

-define(VERSION, 5).
-define(CONNECT, 1).
-define(NMETHODS, 1).
-define(NO_AUTH, 0).
-define(USERPASS, 2).
-define(UNACCEPTABLE, 16#FF).
-define(RESERVED, 0).
-define(ATYP_IPV4, 1).
-define(ATYP_DOMAINNAME, 3).
-define(ATYP_IPV6, 4).
-define(SUCCEEDED, 0).

-export([name/0]).
-export([messages/0]).
-export([connect/4]).
-export([send/2]).
-export([setopts/2]).
-export([sockname/1]).
-export([close/1]).

name() -> socks5.

messages() -> {socks5, socks5_closed, socks5_error}.

-spec connect(inet:ip_address() | inet:hostname(),
    inet:port_number(), any(), timeout())
      -> {ok, inet:socket()} | {error, atom()}.

connect(Host, Port, Options, Timeout) ->
  io:format("Options: ~p~n", [Options]),
  {ok, Socket} = gen_tcp:connect(Host, Port, [binary, {active, false}, {packet, raw}], Timeout),
  ok = handshake(Socket, Options),
  io:format("after connect and handshake ~n"),
  {ok, Socket}.

-spec send(inet:socket(), iodata()) -> ok | {error, atom()}.
send(Socket, [[<<"CONNECT">>, _, [Host, _, Port], _, _, _, _, _]]) ->
  io:format("gun_socks5:send clause 1 ~n"),
  ok = setopts(Socket, [binary, {active, false}]),
  ok = connect_to_target(Host, binary_to_integer(Port), Socket),
  io:format("active once ~n"),
  ok = setopts(Socket, [{active, once}]);
send(Socket, Packet) ->
  io:format("gun_socks5:send clause 1 ~n"),
  gen_tcp:send(Socket, Packet).

-spec setopts(inet:socket(), list()) -> ok | {error, atom()}.
setopts(Socket, Opts) ->
  inet:setopts(Socket, Opts).

-spec sockname(inet:socket())
      -> {ok, {inet:ip_address(), inet:port_number()}} | {error, atom()}.
sockname(Socket) ->
  inet:sockname(Socket).

-spec close(inet:socket()) -> ok.
close(Socket) ->
  gen_tcp:close(Socket).

handshake(Socket, Options) when is_port(Socket) ->
  User = get_value(socks5_user, Options, <<>>),
  Password = get_value(socks5_password, Options, <<>>),
  Handshake_msg =
    case User of
      <<>> ->
        <<?VERSION, ?NMETHODS, ?NO_AUTH>>;
      User ->
        <<?VERSION, ?NMETHODS, ?USERPASS>>
    end,
  io:format("==========Handshake_msg: ~p~n", [Handshake_msg]),
  ok = gen_tcp:send(Socket, Handshake_msg),
  case gen_tcp:recv(Socket, 2) of
    {ok, <<?VERSION, ?NO_AUTH>>} ->
      ok;
    {ok, <<?VERSION, ?USERPASS>>} ->
      Auth_msg = list_to_binary([1,
        iolist_size(User), User,
        iolist_size(Password), Password]),
      ok = gen_tcp:send(Socket, Auth_msg),
      case gen_tcp:recv(Socket, 2) of
        {ok, <<1, ?SUCCEEDED>>} ->
          ok;
        _ ->
          {error, unacceptable}
      end;
    {ok, <<?VERSION, ?UNACCEPTABLE>>} ->
      {error, unacceptable};
    {error, Reason} ->
      {error, Reason}
  end.

connect_to_target(Host, Port, Socket) when is_list(Host) ->
  connect_to_target(list_to_binary(Host), Port, Socket);
connect_to_target(Host, Port, Socket) when is_binary(Host), is_integer(Port), is_port(Socket) ->
  {AddressType, Address} =
    case inet:parse_address(binary_to_list(Host)) of
      {ok, {IP1, IP2, IP3, IP4}} ->
        {?ATYP_IPV4, <<IP1,IP2,IP3,IP4>>};
      {ok, {IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8}} ->
        {?ATYP_IPV6, <<IP1,IP2,IP3,IP4,IP5,IP6,IP7,IP8>>};
      _ ->
        HostLength = byte_size(Host),
        {?ATYP_DOMAINNAME, <<HostLength,Host/binary>>}
    end,
  ok = gen_tcp:send(Socket, <<?VERSION, ?CONNECT, ?RESERVED, AddressType, Address/binary, (Port):16>>),
  case gen_tcp:recv(Socket, 10) of
    {ok, <<?VERSION, ?SUCCEEDED, ?RESERVED, _/binary>>} ->
      ok;
    {ok, <<?VERSION, Response, ?RESERVED, _/binary>>} ->
      {error, resolve(Response)};
    {error, Reason} ->
      {error, Reason}
  end.

resolve(0) -> succeeded;
resolve(1) -> general_socks_server_failure;
resolve(2) -> connection_not_allowed_by_ruleset;
resolve(3) -> network_unreachable;
resolve(4) -> host_unreachable;
resolve(5) -> connection_refused;
resolve(6) -> ttl_expired;
resolve(7) -> command_not_supported;
resolve(8) -> address_type_not_supported;
resolve(9) -> unassigned.

get_value(Key, OptsList, Default) ->
  case lists:keyfind(Key, 1, OptsList) of
    false ->
      Default;
    {Key, Value} ->
      Value
  end.