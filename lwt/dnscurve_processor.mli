module Dnscurve_protocol_only : sig
  type txn =
    Streamlined of Dnscurve.channel
  | Txt of Dnscurve.channel * Dns.Packet.t
  type 'a ctxt = 'a * Dns.Packet.t
  type context = txn ctxt
  val query_of_context : context -> Dns.Packet.t
  val parse :
    Sodium.secret Sodium.Box.key ->
    Sodium.Serialize.Bigarray.t -> context option
  val marshal :
    Dns.Buf.t ->
    context -> Dns.Packet.t -> Sodium.Serialize.Bigarray.t option
end

module Dnscurve_protocol : sig
  type context = Dnscurve_protocol_only.txn option Dnscurve_protocol_only.ctxt
  val query_of_context : context -> Dns.Packet.t
  val parse :
    Sodium.secret Sodium.Box.key ->
    Sodium.Serialize.Bigarray.t -> context option
  val marshal :
    Dns.Buf.t ->
    context -> Dns.Packet.t -> Sodium.Serialize.Bigarray.t option
end

val secure_of_process :
  Sodium.secret Sodium.Box.key ->
  Dns.Packet.t Dns_server.process -> (module Dns_server.PROCESSOR)
val split_of_process :
  Sodium.secret Sodium.Box.key ->
  Dns.Packet.t Dns_server.process ->
  Dns.Packet.t Dns_server.process -> (module Dns_server.PROCESSOR)
val fallback_of_process :
  Sodium.secret Sodium.Box.key ->
  Dns.Packet.t Dns_server.process -> (module Dns_server.PROCESSOR)
