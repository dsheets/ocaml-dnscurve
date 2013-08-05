open Dns_server
open Dnscurve

module Dnscurve_protocol_only = struct
  type txn = Streamlined of channel | Txt of channel * Dns.Packet.t
  type 'a ctxt = 'a * Dns.Packet.t
  type context = txn ctxt

  let query_of_context = snd

  let parse sk buf =
    try
      let chan, pkt = decode_streamlined_query sk buf in
      Some (Streamlined chan, pkt)
    with Protocol_error _ -> begin
      try
        let txt_wrapper = Dns.Packet.parse buf in
        let chan, pkt = decode_txt_query sk txt_wrapper in
        Some (Txt (chan, txt_wrapper), pkt)
      with Protocol_error _ | Base32.Decode_error _ -> None (* TODO: log *)
      | _exn -> None (* TODO: log *)
    end
    | _exn -> None (* TODO: log *)

  let marshal buf (txn, _) pkt = Some (match txn with
    | Streamlined chan -> encode_streamlined_response chan pkt
    | Txt (chan, query) ->
      Dns.Packet.marshal buf (encode_txt_response chan query pkt)
  )
end

module Dnscurve_protocol = struct
  module P = Dnscurve_protocol_only
  type context = P.txn option P.ctxt

  let query_of_context = P.query_of_context

  let parse sk buf = match P.parse sk buf with
    | Some (chan, pkt) -> Some (Some chan, pkt)
    | None -> begin
      try Some (None, Dns.Packet.parse buf)
      with _ -> prerr_endline "bad clear DNS query"; None (* TODO: log *)
    end

  let marshal buf (otxn, _) pkt = Some (match otxn with
    | Some (P.Streamlined chan) -> encode_streamlined_response chan pkt
    | Some (P.Txt (chan, query)) ->
      Dns.Packet.marshal buf (encode_txt_response chan query pkt)
    | None -> Dns.Packet.marshal buf pkt
  )
end

let secure_of_process sk process =
  let module P = struct
    include Dnscurve_protocol_only

    let parse = parse sk
    let process ~src ~dst (_,pkt) = process ~src ~dst pkt
  end in
  (module P : PROCESSOR)

let split_of_process sk clear_process encrypt_process =
  let module P = struct
    include Dnscurve_protocol

    let parse = parse sk
    let process ~src ~dst (chan,pkt) =
      (match chan with Some _ -> encrypt_process | None -> clear_process)
        ~src ~dst pkt
  end in
  (module P : PROCESSOR)

let fallback_of_process sk process = split_of_process sk process process
