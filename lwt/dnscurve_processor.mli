open Dns_server
open Sodium

val between :
  (module PROTOCOL) -> (module PROTOCOL) -> secret Box.key ->
  (module PROTOCOL)

val fallback :
  (module PROTOCOL) -> secret Box.key ->
  Dns.Packet.t process -> Dns.Packet.t process ->
  (module PROCESSOR)

val secure_of_process :
  secret Box.key -> Dns.Packet.t process -> (module Dns_server.PROCESSOR)

val split_of_process :
  secret Box.key -> Dns.Packet.t process -> Dns.Packet.t process ->
  (module PROCESSOR)

val fallback_of_process :
  secret Box.key -> Dns.Packet.t process -> (module PROCESSOR)
