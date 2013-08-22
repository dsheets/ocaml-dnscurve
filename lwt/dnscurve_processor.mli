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
