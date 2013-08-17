open Sodium

type env = { mutable streamlined : bool option; mutable txt : bool option; }

module type DNSCURVECLIENT = sig
  include Dns.Protocol.CLIENT

  val marshal : Dnscurve.keyring option -> Sodium.Box.keypair -> Dns.Packet.t ->
    (context * Dns.Buf.t) list
end

val new_env : unit -> env
val reset_env : env -> unit

val streamlined : public Box.key -> (module Dns.Protocol.CLIENT) ->
  (module DNSCURVECLIENT)

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
