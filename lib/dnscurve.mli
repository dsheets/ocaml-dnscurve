open Sodium

exception Protocol_error of string

type keyring = (public Box.key, channel Box.key) Hashtbl.t
type channel = {
  client_n : Serialize.Bigarray.t;
  client_pk : public Box.key;
  key : Sodium.channel Box.key;
}

val get_key : string list -> public Box.key option

val encode_streamlined_query :
  ?keyring:keyring ->
  public Box.key * secret Box.key ->
  public Box.key ->
  Dns.Buf.t -> channel * Serialize.Bigarray.t

(** Raises { Protocol_error }, { Sodium.VerificationFailure } *)
val decode_streamlined_query :
  ?keyring:keyring -> secret Box.key ->
  Serialize.Bigarray.t -> channel * Dns.Buf.t

val encode_streamlined_response :
  channel -> Dns.Buf.t -> Serialize.Bigarray.t

(** Raises { Protocol_error }, { Sodium.VerificationFailure } *)
val decode_streamlined_response :
  channel -> Serialize.Bigarray.t -> Dns.Buf.t

val encode_txt_query :
  ?keyring:keyring -> id:int ->
  public Box.key * secret Box.key ->
  public Box.key ->
  string list -> Dns.Buf.t -> channel * Dns.Packet.t

(** Raises { Protocol_error }, { Base32.Decode_error },
    { Sodium.VerificationFailure }
*)
val decode_txt_query :
  ?keyring:keyring -> secret Box.key ->
  Dns.Packet.t -> channel * Dns.Buf.t

val encode_txt_response :
  channel -> Dns.Packet.t -> Dns.Buf.t -> Dns.Packet.t

(** Raises [Protocol_error], { Sodium.VerificationFailure } *)
val decode_txt_response :
  channel -> Dns.Packet.t -> Dns.Buf.t
