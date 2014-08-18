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

open Dns.Protocol
open Dns_resolver
open Dnscurve

type env = { mutable streamlined : bool option; mutable txt : bool option; }

module type DNSCURVECLIENT = sig
  include CLIENT

  val marshal : keyring option -> Sodium.Box.keypair -> Dns.Packet.t ->
    (context * Dns.Buf.t) list
end

let new_env () = { streamlined = None; txt = None; }
let reset_env env = env.streamlined <- None; env.txt <- None; ()
let get_id () =
  let s = Sodium.Random.Bytes.generate 2 in
  ((int_of_char s.[0]) lsl 8) lor (int_of_char s.[1])

let streamlined server_pk inside =
  let module I = (val inside : CLIENT) in
  let module M = struct
    type context = I.context * channel

    let get_id = get_id

    let marshal keyring ident pkt =
      List.rev_map
        (fun (ictxt, buf) ->
          let chan, buf = encode_streamlined_query ?keyring ident
            server_pk buf in
          (ictxt, chan), buf)
        (I.marshal pkt)

    let parse ((ictxt, chan) : context) buf =
      try I.parse ictxt (decode_streamlined_response chan buf)
      with exn ->
        Printf.eprintf "Exception: %s\nBacktrace:\n%!" (Printexc.to_string exn);
        Printexc.print_backtrace stderr;
        None (* TODO: tag context for timeout callback *)

    let timeout _ = Dns_resolve_timeout
  end in
  (module M : DNSCURVECLIENT)

let between keyf env server_pk zone outside inside =
  let module O = (val outside : CLIENT) in
  let module I = (val inside : CLIENT) in
  let module S = (val streamlined server_pk inside : DNSCURVECLIENT) in
  let module M = struct
    type context =
    | Streamlined of env * S.context
    | Txt of env * I.context * channel * O.context

    let get_id = get_id

    let marshal pkt =
      let keyring, ident = keyf () in
      let streamlined () =
        List.rev_map (fun (sctxt, buf) ->
          Streamlined (env, sctxt), buf) (S.marshal keyring ident pkt)
      in
      let txt () =
        let id = get_id () in
        List.fold_left
          (fun xs (ictxt,buf) ->
            let chan, pkt = encode_txt_query ?keyring ~id ident
              server_pk zone buf in
            List.fold_left
              (fun xs (octxt,buf) ->
                (Txt (env, ictxt, chan, octxt), buf)::xs
              ) xs (O.marshal pkt)
          ) [] (I.marshal pkt)
      in
      match env with (* TODO: factor streamlined+txt in DNSCurve *)
      | { streamlined=None; txt=None }             -> (streamlined ())@(txt ())
      | { streamlined=(None | Some true) }         -> streamlined ()
      | { txt=(None | Some true) }                 -> txt ()
      | { streamlined=Some false; txt=Some false } -> []

    let parse chan buf = try begin match chan with
      | Streamlined (env,sctxt) ->
        let pkt = S.parse sctxt buf in
        env.streamlined <- Some true;
        pkt
      | Txt (env,ictxt,chan,octxt) ->
        begin match O.parse octxt buf with
        | None -> None (* TODO: tag context for timeout callback *)
        | Some txt ->
          let pkt = I.parse ictxt (decode_txt_response chan txt) in
          env.txt <- Some true;
          pkt
        end
    end with exn ->
      Printf.eprintf "Exception: %s\nBacktrace:\n%!" (Printexc.to_string exn);
      Printexc.print_backtrace stderr;
      None (* TODO: tag context for timeout callback *)

    let timeout = function
      | Streamlined (env,_) ->
        env.streamlined <- Some false; Dns_resolve_timeout
      | Txt (env,_,_,_) ->
        env.txt <- Some false; Dns_resolve_timeout
  end in
  (module M : CLIENT)

let fallback keyf env server_pk zone resolver =
  let dnscurve = between keyf env server_pk zone resolver resolver in
  let module D = (val resolver : CLIENT) in
  let module M = struct
    module C = (val dnscurve : CLIENT)
    type context = Curve of C.context | Clear of D.context

    let get_id = C.get_id

    let marshal pkt =
      List.(rev_append
              (rev_map (fun (ctxt,buf) -> Clear ctxt, buf) (D.marshal pkt))
              (rev_map (fun (ctxt,buf) -> Curve ctxt, buf) (C.marshal pkt))
      )

    let parse ctxt buf = try begin match ctxt with
      | Curve c -> C.parse c buf
      | Clear c -> D.parse c buf
    end with _ -> None

    let timeout = function
      | Curve c -> C.timeout c
      | Clear c -> D.timeout c
  end in
  (module M : CLIENT)
