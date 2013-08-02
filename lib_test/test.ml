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

open OUnit

module TestBase32 = struct
  (* <http://tools.ietf.org/html/draft-dempsky-dnscurve-01#section-3.1> *)
  let rfc_table_3_1 = [
    "","";
    "\x88","84";
    "\x9f\x0b","zw20";
    "\x17\xa3\xd4","rs89f";
    "\x2a\xa9\x13\x7e","b9b71z1";
    "\x7e\x69\xa3\xef\xac","ycu6urmp";
    "\xe5\x3b\x60\xe8\x15\x62","5zg06nr223";
    "\x72\x3c\xef\x3a\x43\x2c\x8f","l3hygxd8dt31";
    "\x17\xf7\x35\x09\x41\xe4\xdc\x01","rsxcm44847r30";
  ]

  let string_of_octets o =
    let len = Bigarray.Array1.dim o in
    let s = String.create len in
    for i=0 to len - 1 do
      s.[i] <- o.{i};
    done;
    s

  let octets_of_string s =
    let len = String.length s in
    let o = Bigarray.(Array1.create char c_layout len) in
    for i=0 to len - 1 do
      o.{i} <- s.[i];
    done;
    o

  let of_octets_rfc () =
    List.iter (fun (o,b) ->
      let o' = octets_of_string o in
      let b_of_o = Base32.of_octets o' in
      let msg = Printf.sprintf "%S => %S vs %S\n" o b_of_o b in
      assert_equal ~msg (Base32.of_octets o') b
    ) rfc_table_3_1

  let to_octets_rfc () =
    List.iter (fun (o,b) ->
      let o_of_b = string_of_octets (Base32.to_octets b) in
      let msg = Printf.sprintf "%S => %S vs %S\n" b o_of_b o in
      assert_equal ~msg (string_of_octets (Base32.to_octets b)) o
    ) rfc_table_3_1

  let suite = [
    "of_octets_rfc" >:: of_octets_rfc;
    "to_octets_rfc" >:: to_octets_rfc;
  ]
end

let suite = "ocaml-dnscurve" >::: [
  "Base32" >::: TestBase32.suite;
]

;;
run_test_tt_main suite
