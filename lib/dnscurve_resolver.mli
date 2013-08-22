(*
 * Copyright (c) 2013 David Sheets <sheets@alum.mit.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

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
