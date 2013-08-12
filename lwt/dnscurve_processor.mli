open Dns.Protocol
open Dns_server
open Sodium

val between :
  secret Box.key -> (module SERVER) -> (module PROCESSOR) -> (module PROCESSOR)

val fallback :
  (module PROCESSOR) ->
  secret Box.key -> (module SERVER) -> (module PROCESSOR) -> (module PROCESSOR)

val secure_of_process :
  secret Box.key -> Dns.Packet.t process -> (module PROCESSOR)

val split_of_process :
  secret Box.key -> Dns.Packet.t process -> Dns.Packet.t process ->
  (module PROCESSOR)

val fallback_of_process :
  secret Box.key -> Dns.Packet.t process -> (module PROCESSOR)
