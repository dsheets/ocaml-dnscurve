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

module B = Bigarray

type octets = (char, B.int8_unsigned_elt, B.c_layout) B.Array1.t

exception Decode_error of int * string

let alpha = "0123456789bcdfghjklmnpqrstuvwxyz"

let inject =
  let tbl = Array.make 0xff (-1) in
  String.iteri (fun i c ->
    tbl.(Char.code c) <- i;
    tbl.(Char.(code (uppercase c))) <- i;
  ) alpha;
  fun c -> let v = tbl.(Char.code c) in if v = -1 then raise Not_found else v

(* off is bits not bytes! returns new off *)
let into_octets s off buf =
  let len = String.length s in
  let blen = len * 5 in
  let noff = off + 7 in
  let loff = noff mod 8 in
  let slen = (blen + loff) / 8 in
  B.Array1.(fill (sub buf (noff / 8) slen) '\000');
  let buf = B.Array1.sub buf (off / 8) (slen + 1 - loff / 7) in
  let low = off mod 8 in
  for i=0 to len - 1 do
    let boff = 5 * i + low in
    let bshift = boff mod 8 in
    let off = boff / 8 in
    let btop = 8 - bshift in
    let n = try inject s.[i]
      with Not_found -> raise (Decode_error (i, s)) in
    buf.{off} <- Char.chr ((Char.code buf.{off})
                           lor ((n lsl bshift) land 0xff));
    if btop < 5 then buf.{off + 1} <- Char.chr (n lsr btop)
  done;
  off + blen

let to_octets s =
  let len = ((String.length s) * 5 + 7) / 8 in
  let buf = B.(Array1.create char c_layout) len in
  let _bwritten = into_octets s 0 buf in
  B.Array1.sub buf 0
    (if len > 0 && buf.{len - 1} = '\000' then len - 1 else len)

let of_octets o =
  let len = B.Array1.dim o in
  let blen = (len * 8 + 4) / 5 in
  let buf = Bytes.create blen in
  for i=0 to blen - 1 do
    let boff = 5 * i in
    let bshift = boff mod 8 in
    let off = boff / 8 in
    let bot = ((Char.code o.{off}) lsr bshift) land 0x1f in
    let btop = 8 - bshift in
    if btop < 5 && off < len - 1
    then Bytes.set buf i alpha.[ (((Char.code o.{off + 1}) land (0x1f lsr btop))
                                  lsl btop) + bot ]
    else Bytes.set buf i alpha.[bot];
  done;
  buf
