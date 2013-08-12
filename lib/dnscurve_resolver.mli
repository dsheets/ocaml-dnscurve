open Sodium

type env = { mutable streamlined : bool option; mutable txt : bool option; }

val new_env : unit -> env
val reset_env : env -> unit

val between :
  (unit -> Dnscurve.keyring option * Box.keypair) ->
  env -> public Box.key -> Dns.Name.domain_name ->
  (module Dns.Protocol.CLIENT) ->
  (module Dns.Protocol.CLIENT) ->
  (module Dns.Protocol.CLIENT)
val fallback :
  (unit -> Dnscurve.keyring option * Box.keypair) ->
  env -> public Box.key -> Dns.Name.domain_name ->
  (module Dns.Protocol.CLIENT) ->
  (module Dns.Protocol.CLIENT)
