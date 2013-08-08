open Dns_server
open Dnscurve

let between inside outside sk =
  let module O = (val outside : PROTOCOL) in
  let module I = (val inside : PROTOCOL) in
  let module M = struct
    type txn =
    | Streamlined of I.context * channel
    | Txt of I.context * channel * Dns.Packet.t * O.context
    type 'a ctxt = 'a * Dns.Packet.t
    type context = txn ctxt

    let query_of_context = snd

    let parse buf =
      try
        let chan, buf = decode_streamlined_query sk buf in
        begin match I.parse buf with
        | Some ictxt ->
          Some (Streamlined (ictxt, chan), I.query_of_context ictxt)
        | None -> None (* TODO: log *)
        end
      with Protocol_error _ -> begin
        try begin match O.parse buf with
        | Some octxt ->
          let txt = O.query_of_context octxt in
          let chan, buf = decode_txt_query sk txt in
          begin match I.parse buf with
          | Some ictxt ->
            Some (Txt (ictxt, chan, txt, octxt), I.query_of_context ictxt)
          | None -> prerr_endline "inner parse fail\n"; None (* TODO: log *)
          end
        | None -> prerr_endline "outer parse fail\n"; None (* TODO: log *)
        end
        with (Protocol_error _ | Base32.Decode_error _) as exn ->
          Printf.eprintf "Exception: %s\nBacktrace:\n%!" (Printexc.to_string exn);
          Printexc.print_backtrace stderr;
          None (* TODO: log *)
        | exn ->
          Printf.eprintf "Unknown exception: %s\nBacktrace:\n%!" (Printexc.to_string exn);
          Printexc.print_backtrace stderr;
          None (* TODO: log *)
      end
      | _exn -> None (* TODO: log *)

    let marshal buf (txn, _) pkt = match txn with
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
  (module M : PROTOCOL)

let fallback protocol sk clear_process encrypt_process =
  let module D = (val protocol : PROTOCOL) in
  let module P = (val (between protocol protocol sk) : PROTOCOL) in
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

    let process ~src ~dst ctxt =
      (match ctxt with
      | Curve _ -> encrypt_process
      | Clear _ -> clear_process) ~src ~dst (query_of_context ctxt)

    let marshal buf ctxt pkt = match ctxt with
      | Curve c -> P.marshal buf c pkt
      | Clear c -> D.marshal buf c pkt
  end in
  (module M : PROCESSOR)

let secure_of_process sk process =
  let dns = (module Dns_protocol : PROTOCOL) in
  let module C = (val (between dns dns sk) : PROTOCOL) in
  let module P = struct
    include C

    let process ~src ~dst ctxt = process ~src ~dst (C.query_of_context ctxt)
  end in
  (module P : PROCESSOR)

let split_of_process sk clear_process encrypt_process =
  let dns = (module Dns_protocol : PROTOCOL) in
  fallback dns sk clear_process encrypt_process

let fallback_of_process sk process = split_of_process sk process process
