
(* <http://tools.ietf.org/html/draft-dempsky-dnscurve-01> *)

open Sodium
module Crypto = Make(Serialize.Bigarray)
module B = Bigarray
module B1 = B.Array1

let create_octets = Serialize.Bigarray.create

let octets_into_string o off s soff len =
  for i=0 to len - 1 do
    s.[i + soff] <- o.{i + off};
  done

let string_into_octets s soff o off len =
  for i=0 to len - 1 do
    o.{i + off} <- s.[i + soff];
  done

exception Protocol_error of string

(* Use by server can divulge prior pk contacts via timing. *)
(* TODO: weak table? *)
type keyring = (public Box.key, channel Box.key) Hashtbl.t
type channel = {
  client_n : Serialize.Bigarray.t;
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
            Some (Crypto.box_read_public_key buf)
        with Base32.Decode_error _ -> get_key xs
      else get_key xs
    else get_key xs

let gen_key keyring sk pk =
  match keyring with
  | Some keyring ->
    begin try Hashtbl.find keyring pk
      with Not_found ->
        let ck = Crypto.box_beforenm sk pk in
        Hashtbl.replace keyring pk ck;
        ck
    end
  | None -> Crypto.box_beforenm sk pk

let nonce_len = Box.(bytes.nonce)
let nonce_hlen = nonce_len / 2

let new_half_nonce () =
  (* TODO: FIXME with timer/counter + randomness + nonce separation? *)
  Crypto.random nonce_hlen

let extend_nonce client_n =
  let nonce = create_octets nonce_len in
  B1.blit client_n (B1.sub nonce 0 nonce_hlen);
  B1.fill (B1.sub nonce nonce_hlen nonce_hlen) '\000';
  Crypto.box_read_nonce nonce

let combine_nonce client_n server_n =
  let nonce = create_octets nonce_len in
  B1.blit client_n (B1.sub nonce 0 nonce_hlen);
  B1.blit server_n (B1.sub nonce nonce_hlen nonce_hlen);
  Crypto.box_read_nonce nonce

let sq_magic = "Q6fnvWj8"
let sq_magic_len = String.length sq_magic
let pk_sz = Box.(bytes.public_key)
let sq_hdr_sz = sq_magic_len + pk_sz + nonce_hlen
let encode_streamline_query ?keyring (pk,sk) server_pk dns =
  let client_n = new_half_nonce () in
  let nonce = extend_nonce client_n in
  let key = gen_key keyring sk server_pk in
  let buf = Cstruct.create 4096 in (* TODO: ??? *)
  let { Cstruct.buffer } = Dns.Packet.marshal buf dns in
  let c = Crypto.(box_write_ciphertext (box_afternm key buffer ~nonce)) in
  let txbuf = create_octets ((B1.dim c) + sq_hdr_sz) in
  string_into_octets sq_magic 0 txbuf 0 sq_magic_len;
  B1.blit (Crypto.box_write_key pk) (B1.sub txbuf sq_magic_len pk_sz);
  B1.blit client_n (B1.sub txbuf (sq_magic_len + pk_sz) nonce_hlen);
  B1.blit c (B1.sub txbuf sq_hdr_sz (B1.dim c));
  { client_n; client_pk = pk; key }, txbuf

let decode_streamline_query ?keyring sk buf =
  for i=0 to sq_magic_len do
    if buf.{i} <> sq_magic.[i] then raise (Protocol_error "Bad magic")
  done;
  let client_pk = Crypto.box_read_public_key (B1.sub buf sq_magic_len pk_sz) in
  let key = gen_key keyring sk client_pk in
  let client_n = B1.sub buf (sq_magic_len + pk_sz) nonce_hlen in
  let nonce = extend_nonce client_n in
  let c = Crypto.box_read_ciphertext
    B1.(sub buf sq_hdr_sz (dim buf - sq_hdr_sz)) in
  { client_n; client_pk; key }, Crypto.box_open_afternm key c ~nonce

let sr_magic = "R6fnvWJ8"
let sr_magic_len = String.length sr_magic
let sr_hdr_sz = sr_magic_len + nonce_len
let encode_streamline_response ({ client_n; key }) dns =
  let server_n = new_half_nonce () in
  let nonce = combine_nonce client_n server_n in
  let buf = Cstruct.create 4096 in (* TODO: ??? *)
  let { Cstruct.buffer } = Dns.Packet.marshal buf dns in
  let c = Crypto.(box_write_ciphertext (box_afternm key buffer ~nonce)) in
  let txbuf = create_octets ((B1.dim c) + sr_hdr_sz) in
  string_into_octets sr_magic 0 txbuf 0 sr_magic_len;
  B1.blit (Crypto.box_write_nonce nonce) (B1.sub txbuf sr_magic_len nonce_len);
  B1.blit c (B1.sub txbuf sr_hdr_sz (B1.dim c));
  txbuf

let decode_streamline_response ({ client_n; key }) buf =
  for i=0 to sr_magic_len do
    if buf.{i} <> sr_magic.[i] then raise (Protocol_error "Bad magic")
  done;
  let buf_cn = B1.sub buf sr_magic_len nonce_hlen in
  if buf_cn <> client_n then raise (Protocol_error "Mismatched client nonce");
  let nonce = Crypto.box_read_nonce (B1.sub buf sr_magic_len nonce_len) in
  let c = Crypto.box_read_ciphertext
    B1.(sub buf sr_hdr_sz (dim buf - sr_hdr_sz)) in
  Crypto.box_open_afternm key c ~nonce

let tq_key_magic = "x1a"
let encode_txt_query ?keyring ~id (pk,sk) server_pk zone dns =
  let client_n = new_half_nonce () in
  let nonce = extend_nonce client_n in
  let key = gen_key keyring sk server_pk in
  let buf = Cstruct.create 4096 in (* TODO: ??? *)
  let { Cstruct.buffer } = Dns.Packet.marshal buf dns in
  let c = Crypto.(box_write_ciphertext (box_afternm key buffer ~nonce)) in
  let c32 = Base32.of_octets c in
  let n32 = Base32.of_octets client_n in
  let p32 = n32 ^ c32 in
  let len = String.length p32 in
  let p = ref [] in
  for i=0 to (len / 50) - 1 do
    p := (String.sub p32 (i*50) 50) :: !p
  done;
  let over = len mod 50 in
  if over <> 0 then p := (String.sub p32 (len - over) over) :: !p;
  let k32 = tq_key_magic ^ (Base32.of_octets (Crypto.box_write_key pk)) in
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
    questions = [{ q_name; q_type = Q_TXT; q_class = Q_IN }];
    answers = []; authorities = []; additionals = [];
  })

let decode_txt_query ?keyring sk dns =
  if Dns.Packet.(dns.detail.qr = Response)
  then raise (Protocol_error "TXT query should not have QR bit set");
  match dns.Dns.Packet.questions with
  | [] -> raise (Protocol_error "No questions")
  | _::_::_ -> raise (Protocol_error "Too many questions")
  | [{Dns.Packet.q_name}] ->
    let buf = create_octets 4096 in (* TODO: ??? *)
    let rec decode_name off = function
      | lbl::lbls when String.length lbl = 54 ->
        if (String.sub lbl 0 3) = tq_key_magic
        then off, Base32.to_octets (String.sub lbl 3 51)
        else raise (Protocol_error "TXT query name bad public key magic")
      | lbl::lbls ->
        let written = Base32.into_octets lbl off buf in
        decode_name (off + written) lbls
      | [] -> raise (Protocol_error "TXT query name not encoded for DNSCurve")
    in
    let written, pk_octets = decode_name 0 q_name in
    let client_pk = Crypto.box_read_public_key pk_octets in
    let key = gen_key keyring sk client_pk in
    let client_n = B1.sub buf 0 nonce_hlen in
    let nonce = extend_nonce client_n in
    let c = Crypto.box_read_ciphertext
      (B1.sub buf nonce_hlen (written - nonce_hlen)) in
    { client_n; client_pk; key }, Crypto.box_open_afternm key c ~nonce

let encode_txt_response ({ client_n; key }) query dns =
  let server_n = new_half_nonce () in
  let nonce = combine_nonce client_n server_n in
  let buf = Cstruct.create 4096 in (* TODO: ??? *)
  let { Cstruct.buffer } = Dns.Packet.marshal buf dns in
  let c = Crypto.(box_write_ciphertext (box_afternm key buffer ~nonce)) in
  let clen = B1.dim c in
  let len = nonce_hlen + clen in
  let txt0 = String.create (min len 255) in
  let txts = ref [txt0] in
  octets_into_string server_n 0 txt0 0 nonce_hlen;
  if len < 256
  then octets_into_string c 0 txt0 nonce_hlen clen
  else begin
    let hdsz = 255 - nonce_hlen in
    octets_into_string c 0 txt0 nonce_hlen hdsz;
    let rec mktxts off buf =
      let sz = clen - off in
      let blksz = min sz 255 in
      let s = String.create blksz in
      octets_into_string buf off s 0 blksz;
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
               }];
    authorities = []; additionals = [];
  })

let decode_txt_response ({ client_n; key }) dns =
  (* TODO: check id, check query name? *)
  let open Dns.Packet in
  match dns.answers with
  | [{rdata = TXT (txt0::txts)}] ->
    let server_n = create_octets nonce_hlen in
    string_into_octets txt0 0 server_n 0 nonce_hlen;
    let nonce = combine_nonce client_n server_n in
    let tlsz = List.fold_left (fun acc txt -> acc + String.length txt) 0 txts in
    let hdsz = String.length txt0 - nonce_len in
    let c = create_octets (tlsz + hdsz) in
    string_into_octets txt0 nonce_hlen c 0 hdsz;
    let _clen = List.fold_left (fun off txt ->
      let len = String.length txt in
      string_into_octets txt 0 c off len;
      off + len
    ) hdsz txts in
    Crypto.(box_open_afternm key (box_read_ciphertext c) ~nonce)
  | _ -> raise (Protocol_error "TXT response should only have 1 TXT answer")
