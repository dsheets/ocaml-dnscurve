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

open Dns
open Dns_server
open Dnscurve

module type DNSCURVEPROCESSOR = sig
  include PROCESSOR

  val process : channel -> context process
end

type 'a tunnel =
  Sodium.secret Sodium.Box.key -> (module Protocol.SERVER) -> 'a ->
  (module PROCESSOR)

type _ wrap =
| Plain : (module PROCESSOR) tunnel -> (module PROCESSOR) wrap
| Curve : (module DNSCURVEPROCESSOR) tunnel -> (module DNSCURVEPROCESSOR) wrap

let shrink (type a) : a wrap -> a tunnel = function
  | Plain tun -> tun
  | Curve tun -> tun

let encurve sk outside inside =
  let module O = (val outside : Protocol.SERVER) in
  let module I = (val inside : DNSCURVEPROCESSOR) in
  let module M = struct
    type context =
    | Streamlined of I.context * channel
    | Txt of I.context * channel * Dns.Packet.t * O.context

    let query_of_context = function
      | Streamlined (ctxt, _) | Txt (ctxt, _, _, _) -> I.query_of_context ctxt

    let parse buf =
      try
        let chan, buf = decode_streamlined_query sk buf in
        begin match I.parse buf with
        | Some ictxt ->
          Some (Streamlined (ictxt, chan))
        | None -> None (* TODO: log *)
        end
      with Protocol_error _ -> begin
        try begin match O.parse buf with
        | Some octxt ->
          let txt = O.query_of_context octxt in
          let chan, buf = decode_txt_query sk txt in
          begin match I.parse buf with
          | Some ictxt ->
            Some (Txt (ictxt, chan, txt, octxt))
          | None -> prerr_endline "inner parse fail\n"; None (* TODO: log *)
          end
        | None -> prerr_endline "outer parse fail\n"; None (* TODO: log *)
        end
        with Protocol_error _ | Base32.Decode_error _ ->
          None (* TODO: log *)
        | exn ->
          Printf.eprintf "Unknown exception: %s\nBacktrace:\n%!" (Printexc.to_string exn);
          Printexc.print_backtrace stderr;
          None (* TODO: log *)
      end
      | _exn -> None (* TODO: log *)

    let process ~src ~dst = function
      | Streamlined (ctxt,chan)
      | Txt (ctxt,chan,_,_) -> I.process chan ~src ~dst ctxt

    let marshal buf ctxt pkt = match ctxt with
      | Streamlined (ictxt, chan) ->
        begin match I.marshal buf ictxt pkt with
        | Some buf -> Some (encode_streamlined_response chan buf)
        | None -> None (* TODO: log *)
        end
      | Txt (ictxt, chan, txt, octxt) ->
        begin match I.marshal buf ictxt pkt with
        | Some buf ->
          let pkt = encode_txt_response chan txt buf in
          let obuf = Dns.Buf.create 4096 in
          O.marshal obuf octxt pkt
        | None -> None (* TODO: log *)
        end
  end in
  (module M : PROCESSOR)

let wrap sk outside inside =
  let module I = (val inside : PROCESSOR) in
  let module M = struct
    include I

    let process _chan = process
  end in
  encurve sk outside (module M : DNSCURVEPROCESSOR)

let fallback (type a) (wrap : a wrap) clear_processor
    sk outside (encrypt_processor : a) =
  let module D = (val clear_processor : PROCESSOR) in
  let module P = (val shrink wrap sk outside encrypt_processor : PROCESSOR) in
  let module M = struct
    type context = Curve of P.context | Clear of D.context

    let query_of_context = function
      | Curve c -> P.query_of_context c
      | Clear c -> D.query_of_context c

    let parse buf = match P.parse buf with
      | Some ctxt -> Some (Curve ctxt)
      | None -> begin match D.parse buf with
        | Some ctxt -> Some (Clear ctxt)
        | None -> prerr_endline "bad clear DNS query"; None (* TODO: log *)
      end

    let process ~src ~dst = function
      | Curve c -> P.process ~src ~dst c
      | Clear c -> D.process ~src ~dst c

    let marshal buf ctxt pkt = match ctxt with
      | Curve c -> P.marshal buf c pkt
      | Clear c -> D.marshal buf c pkt
  end in
  (module M : PROCESSOR)

let fallback_curve = fallback (Curve encurve)
let fallback_dns = fallback (Plain wrap)

let of_process process =
  let module M = struct
    include Protocol.Server

    let process = process
  end in
  (module M : DNSCURVEPROCESSOR)

let secure_of_process sk process =
  let dns = (module Protocol.Server : Protocol.SERVER) in
  let processor = (processor_of_process process :> (module PROCESSOR)) in
  wrap sk dns processor

let split_of_process sk clear_process encrypt_process =
  let dns = (module Protocol.Server : Protocol.SERVER) in
  fallback
    (Plain wrap)
    (processor_of_process clear_process :> (module PROCESSOR))
    sk dns
    (processor_of_process encrypt_process :> (module PROCESSOR))

let fallback_of_process sk process = split_of_process sk process process
