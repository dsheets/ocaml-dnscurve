open Dns
open Dns_server
open Dnscurve

let between sk outside inside =
  let module O = (val outside : Protocol.SERVER) in
  let module I = (val inside : PROCESSOR) in
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
      | Streamlined (ctxt,_) | Txt (ctxt,_,_,_) -> I.process ~src ~dst ctxt

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

let fallback clear_processor sk outside encrypt_processor =
  let module D = (val clear_processor : PROCESSOR) in
  let module P = (val between sk outside encrypt_processor : PROCESSOR) in
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

let secure_of_process sk process =
  let dns = (module Protocol.Server : Protocol.SERVER) in
  let processor = (processor_of_process process :> (module PROCESSOR)) in
  between sk dns processor

let split_of_process sk clear_process encrypt_process =
  let dns = (module Protocol.Server : Protocol.SERVER) in
  fallback
    (processor_of_process clear_process :> (module PROCESSOR))
    sk dns
    (processor_of_process encrypt_process :> (module PROCESSOR))

let fallback_of_process sk process = split_of_process sk process process
