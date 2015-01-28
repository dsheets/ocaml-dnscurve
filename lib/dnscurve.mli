(*
 * Copyright (c) 2013-2014 David Sheets <sheets@alum.mit.edu>
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

exception Protocol_error of string

type keyring = (public Box.key, channel Box.key) Hashtbl.t
type channel = {
  client_n : Box.Bigbytes.storage;
  client_pk : public Box.key;
  key : Sodium.channel Box.key;
}

val get_key : string list -> public Box.key option

val encode_streamlined_query :
  ?alloc:(unit -> Dns.Buf.t) ->
  ?keyring:keyring ->
  Box.keypair ->
  public Box.key ->
  Dns.Buf.t -> channel * Box.Bigbytes.storage

(** Raises { Protocol_error }, { Sodium.VerificationFailure } *)
val decode_streamlined_query :
  ?keyring:keyring -> secret Box.key ->
  Box.Bigbytes.storage -> channel * Dns.Buf.t

val encode_streamlined_response :
  ?alloc:(unit -> Dns.Buf.t) -> channel -> Dns.Buf.t -> Box.Bigbytes.storage

(** Raises { Protocol_error }, { Sodium.VerificationFailure } *)
val decode_streamlined_response :
  channel -> Box.Bigbytes.storage -> Dns.Buf.t

val encode_txt_query :
  ?keyring:keyring -> id:int ->
  Box.keypair ->
  public Box.key ->
  string list -> Dns.Buf.t -> channel * Dns.Packet.t

(** Raises { Protocol_error }, { Base32.Decode_error },
    { Sodium.VerificationFailure }
*)
val decode_txt_query :
  ?keyring:keyring -> secret Box.key ->
  Dns.Packet.t -> channel * Dns.Buf.t

val encode_txt_response :
  channel -> Dns.Packet.t -> Dns.Buf.t -> Dns.Packet.t

(** Raises [Protocol_error], { Sodium.VerificationFailure } *)
val decode_txt_response :
  channel -> Dns.Packet.t -> Dns.Buf.t
