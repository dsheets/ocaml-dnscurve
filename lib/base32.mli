type octets = (char,
               Bigarray.int8_unsigned_elt,
               Bigarray.c_layout) Bigarray.Array1.t

exception Decode_error of int

val alpha : string

val into_octets : string -> int -> octets -> int
val to_octets : string -> octets
val of_octets : octets -> string
