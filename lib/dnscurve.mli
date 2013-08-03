exception Protocol_error of string

type keyring =
    (Sodium.public Sodium.Box.key, Sodium.channel Sodium.Box.key) Hashtbl.t
type channel = {
  client_n : Sodium.Serialize.Bigarray.t;
  client_pk : Sodium.public Sodium.Box.key;
  key : Sodium.channel Sodium.Box.key;
}

val get_key : string list -> Sodium.public Sodium.Box.key option

val encode_streamline_query :
  ?keyring:keyring ->
  Sodium.public Sodium.Box.key * Sodium.secret Sodium.Box.key ->
  Sodium.public Sodium.Box.key ->
  Dns.Packet.t -> channel * Sodium.Serialize.Bigarray.t

val decode_streamline_query :
  ?keyring:keyring -> Sodium.secret Sodium.Box.key ->
  Sodium.Serialize.Bigarray.t -> channel * Dns.Packet.t

val encode_streamline_response :
  channel -> Dns.Packet.t -> Sodium.Serialize.Bigarray.t

val decode_streamline_response :
  channel -> Sodium.Serialize.Bigarray.t -> Dns.Packet.t

val encode_txt_query :
  ?keyring:keyring -> id:int ->
  Sodium.public Sodium.Box.key * Sodium.secret Sodium.Box.key ->
  Sodium.public Sodium.Box.key ->
  string list -> Dns.Packet.t -> channel * Dns.Packet.t

val decode_txt_query :
  ?keyring:keyring ->
  Sodium.secret Sodium.Box.key ->
  Dns.Packet.t -> channel * Dns.Packet.t

val encode_txt_response :
  channel -> Dns.Packet.t -> Dns.Packet.t -> Dns.Packet.t

val decode_txt_response :
  channel -> Dns.Packet.t -> Dns.Packet.t
