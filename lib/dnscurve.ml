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

(* <http://tools.ietf.org/html/draft-dempsky-dnscurve-01> *)

open Sodium
module B = Bigarray
module B1 = B.Array1

let create_buf = B1.create B.char B.c_layout

let buf_into_string b off s soff len =
  for i=0 to len - 1 do
    Bytes.set s (i + soff) b.{i + off};
  done

let string_into_buf s soff b off len =
  for i=0 to len - 1 do
    b.{i + off} <- s.[i + soff];
  done

exception Protocol_error of string

(* Use by server can divulge prior pk contacts via timing. *)
(* TODO: weak table? *)
type keyring = (public Box.key, channel Box.key) Hashtbl.t
type channel = {
  client_n : Box.Bigbytes.storage;
  client_pk: public Box.key;
  key      : Sodium.channel Box.key;
}

let ns_pk_magic = "uz5"
let rec get_key = function
  | [] -> None
  | label::xs ->
    if String.length label = 54
    then
      if String.lowercase (String.sub label 0 3) = ns_pk_magic
      then
        try let buf = Base32.to_octets (String.sub label 3 51) in
            Some (Box.Bigbytes.to_public_key buf)
        with Base32.Decode_error _ -> get_key xs
      else get_key xs
    else get_key xs

let gen_key keyring sk pk =
  match keyring with
  | Some keyring ->
    begin try Hashtbl.find keyring pk
      with Not_found ->
        let ck = Box.precompute sk pk in
        Hashtbl.replace keyring pk ck;
        ck
    end
  | None -> Box.precompute sk pk

let nonce_len = Box.nonce_size
let nonce_hlen = nonce_len / 2

let new_half_nonce () =
  (* TODO: FIXME with timer/counter + randomness + nonce separation? *)
  Random.Bigbytes.generate nonce_hlen

let extend_nonce client_n =
  let nonce = create_buf nonce_len in
  B1.blit client_n (B1.sub nonce 0 nonce_hlen);
  B1.fill (B1.sub nonce nonce_hlen nonce_hlen) '\000';
  Box.Bigbytes.to_nonce nonce

let combine_nonce client_n server_n =
  let nonce = create_buf nonce_len in
  B1.blit client_n (B1.sub nonce 0 nonce_hlen);
  B1.blit server_n (B1.sub nonce nonce_hlen nonce_hlen);
  Box.Bigbytes.to_nonce nonce

let sq_magic = "Q6fnvWj8"
let sq_magic_len = String.length sq_magic
let pk_sz = Box.public_key_size
let sq_hdr_sz = sq_magic_len + pk_sz + nonce_hlen
let encode_streamlined_query ?alloc ?keyring (sk,pk) server_pk buffer =
  let client_n = new_half_nonce () in
  let nonce = extend_nonce client_n in
  let key = gen_key keyring sk server_pk in
  let c = Box.Bigbytes.(fast_box key buffer nonce) in
  let txbuf = Dns.Buf.create ?alloc ((B1.dim c) + sq_hdr_sz) in
  string_into_buf sq_magic 0 txbuf 0 sq_magic_len;
  B1.blit (Box.Bigbytes.of_public_key pk) (B1.sub txbuf sq_magic_len pk_sz);
  B1.blit client_n (B1.sub txbuf (sq_magic_len + pk_sz) nonce_hlen);
  B1.blit c (B1.sub txbuf sq_hdr_sz (B1.dim c));
  { client_n; client_pk = pk; key }, txbuf

let decode_streamlined_query ?keyring sk buf =
  for i=0 to sq_magic_len - 1 do
    if buf.{i} <> sq_magic.[i] then raise (Protocol_error "Bad magic")
  done;
  let client_pk = Box.Bigbytes.to_public_key (B1.sub buf sq_magic_len pk_sz) in
  let key = gen_key keyring sk client_pk in
  let client_n = create_buf nonce_hlen in
  B1.blit (B1.sub buf (sq_magic_len + pk_sz) nonce_hlen) client_n;
  let nonce = extend_nonce client_n in
  let c = B1.(sub buf sq_hdr_sz (dim buf - sq_hdr_sz)) in
  { client_n; client_pk; key }, Box.Bigbytes.fast_box_open key c nonce

let sr_magic = "R6fnvWJ8"
let sr_magic_len = String.length sr_magic
let sr_hdr_sz = sr_magic_len + nonce_len
let encode_streamlined_response ?alloc ({ client_n; key }) buffer =
  let server_n = new_half_nonce () in
  let nonce = combine_nonce client_n server_n in
  let c = Box.Bigbytes.fast_box key buffer nonce in
  let txbuf = Dns.Buf.create ?alloc ((B1.dim c) + sr_hdr_sz) in
  string_into_buf sr_magic 0 txbuf 0 sr_magic_len;
  B1.blit (Box.Bigbytes.of_nonce nonce) (B1.sub txbuf sr_magic_len nonce_len);
  B1.blit c (B1.sub txbuf sr_hdr_sz (B1.dim c));
  txbuf

let decode_streamlined_response ({ client_n; key }) buf =
  for i=0 to sr_magic_len - 1 do
    if buf.{i} <> sr_magic.[i] then raise (Protocol_error "Bad magic")
  done;
  let buf_cn = B1.sub buf sr_magic_len nonce_hlen in
  if buf_cn <> client_n then raise (Protocol_error "Mismatched client nonce");
  let nonce = Box.Bigbytes.to_nonce (B1.sub buf sr_magic_len nonce_len) in
  let c = B1.(sub buf sr_hdr_sz (dim buf - sr_hdr_sz)) in
  Box.Bigbytes.fast_box_open key c nonce

let tq_key_magic = "x1a"
let encode_txt_query ?keyring ~id (sk,pk) server_pk zone buffer =
  let client_n = new_half_nonce () in
  let nonce = extend_nonce client_n in
  let key = gen_key keyring sk server_pk in
  let c = Box.Bigbytes.fast_box key buffer nonce in
  let buf = create_buf (nonce_hlen + (B1.dim c)) in
  B1.blit client_n (B1.sub buf 0 nonce_hlen);
  B1.blit c (B1.sub buf nonce_hlen (B1.dim c));
  let p32 = Base32.of_octets buf in
  let len = String.length p32 in
  let p = ref [] in
  for i=0 to (len / 50) - 1 do
    p := (String.sub p32 (i*50) 50) :: !p
  done;
  let over = len mod 50 in
  if over <> 0 then p := (String.sub p32 (len - over) over) :: !p;
  let k32 = Base32.of_octets (Box.Bigbytes.of_public_key pk) in
  let k32 = tq_key_magic ^ (String.sub k32 0 51) in
  let q_name = List.rev_append !p (k32::zone) in
  { client_n; client_pk = pk; key },
  Dns.Packet.({
    id;
    detail = {
      qr = Query;
      opcode = Standard;
      aa = false;
      tc = false;
      rd = false;
      ra = false;
      rcode = NoError;
    };
    questions = [{ q_name; q_type = Q_TXT; q_class = Q_IN; q_unicast = QM }];
    answers = []; authorities = []; additionals = [];
  })

let decode_txt_query ?keyring sk dns =
  if Dns.Packet.(dns.detail.qr = Response)
  then raise (Protocol_error "TXT query should not have QR bit set");
  match dns.Dns.Packet.questions with
  | [] -> raise (Protocol_error "No questions")
  | _::_::_ -> raise (Protocol_error "Too many questions")
  | [{Dns.Packet.q_name}] ->
    let buf = create_buf 4096 in (* TODO: ??? *)
    let rec decode_name off = function
      | lbl::lbls when String.length lbl = 54 ->
        if (String.sub lbl 0 3) = tq_key_magic
        then (off + 7) / 8, Base32.to_octets (String.sub lbl 3 51)
        else raise (Protocol_error "TXT query name bad public key magic")
      | lbl::lbls ->
        let off = Base32.into_octets lbl off buf in
        decode_name off lbls
      | [] -> raise (Protocol_error "TXT query name not encoded for DNSCurve")
    in
    let written, pk_octets = decode_name 0 q_name in
    let written = written - (if buf.{written - 1} = '\000' then 1 else 0) in
    let client_pk = Box.Bigbytes.to_public_key pk_octets in
    let key = gen_key keyring sk client_pk in
    let client_n = B1.sub buf 0 nonce_hlen in
    let nonce = extend_nonce client_n in
    let c = B1.sub buf nonce_hlen (written - nonce_hlen) in
    { client_n; client_pk; key }, Box.Bigbytes.fast_box_open key c nonce

let encode_txt_response ({ client_n; key }) query buffer =
  let server_n = new_half_nonce () in
  let nonce = combine_nonce client_n server_n in
  let c = Box.Bigbytes.fast_box key buffer nonce in
  let clen = B1.dim c in
  let len = nonce_hlen + clen in
  let txt0 = Bytes.create (min len 255) in
  let txts = ref [txt0] in
  buf_into_string server_n 0 txt0 0 nonce_hlen;
  if len < 256
  then buf_into_string c 0 txt0 nonce_hlen clen
  else begin
    let hdsz = 255 - nonce_hlen in
    buf_into_string c 0 txt0 nonce_hlen hdsz;
    let rec mktxts off buf =
      let sz = clen - off in
      let blksz = min sz 255 in
      let s = Bytes.create blksz in
      buf_into_string buf off s 0 blksz;
      txts := s :: !txts;
      if sz > 255 then mktxts (off + 255) buf
    in mktxts hdsz c
  end;
  Dns.Packet.({
    id = query.id;
    detail = {
      qr = Response;
      opcode = Standard;
      aa = true;
      tc = false;
      rd = query.detail.rd;
      ra = false;
      rcode = NoError;
    };
    questions = query.questions;
    answers = [{ name = (List.hd query.questions).q_name;
                 cls = RR_IN;
                 ttl = 0_l;
                 rdata = TXT (List.rev !txts);
                 flush = false;
               }];
    authorities = []; additionals = [];
  })

let decode_txt_response ({ client_n; key }) dns =
  let open Dns.Packet in
  match dns.answers with
  | [{rdata = TXT (txt0::txts)}] ->
    let server_n = create_buf nonce_hlen in
    string_into_buf txt0 0 server_n 0 nonce_hlen;
    let nonce = combine_nonce client_n server_n in
    let tlsz = List.fold_left (fun acc txt -> acc + String.length txt) 0 txts in
    let hdsz = String.length txt0 - nonce_hlen in
    let c = create_buf (tlsz + hdsz) in
    string_into_buf txt0 nonce_hlen c 0 hdsz;
    let _clen = List.fold_left (fun off txt ->
      let len = String.length txt in
      string_into_buf txt 0 c off len;
      off + len
    ) hdsz txts in
    Box.Bigbytes.fast_box_open key c nonce
  | _ -> raise (Protocol_error "TXT response should only have 1 TXT answer")
