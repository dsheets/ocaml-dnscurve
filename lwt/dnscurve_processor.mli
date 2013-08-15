open Dns.Protocol
open Dns_server
open Sodium

type 'a tunnel = secret Box.key -> (module SERVER) -> 'a -> (module PROCESSOR)

module type DNSCURVEPROCESSOR = sig
  include PROCESSOR

  val process : Dnscurve.channel -> context process
end

val of_process :
  (Dnscurve.channel -> Dns.Packet.t process) -> (module DNSCURVEPROCESSOR)

val encurve : (module DNSCURVEPROCESSOR) tunnel

val wrap : (module PROCESSOR) tunnel

val fallback_curve : (module PROCESSOR) -> (module DNSCURVEPROCESSOR) tunnel

val fallback_dns : (module PROCESSOR) -> (module PROCESSOR) tunnel

val secure_of_process :
  secret Box.key -> Dns.Packet.t process -> (module PROCESSOR)

val split_of_process :
  secret Box.key -> Dns.Packet.t process -> Dns.Packet.t process ->
  (module PROCESSOR)

val fallback_of_process :
  secret Box.key -> Dns.Packet.t process -> (module PROCESSOR)
