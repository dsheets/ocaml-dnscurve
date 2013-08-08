open Sodium

type env = { mutable streamlined : bool option; mutable txt : bool option; }

val new_env : unit -> env
val reset_env : env -> unit

val between :
  (module Dns_resolver.RESOLVER) ->
  (module Dns_resolver.RESOLVER) ->
  (unit -> Dnscurve.keyring option * Box.keypair) ->
  env -> public Box.key -> Dns.Name.domain_name ->
  (module Dns_resolver.RESOLVER)
val fallback :
  (module Dns_resolver.RESOLVER) ->
  (unit -> Dnscurve.keyring option * Box.keypair) ->
  env -> public Box.key -> Dns.Name.domain_name ->
  (module Dns_resolver.RESOLVER)
