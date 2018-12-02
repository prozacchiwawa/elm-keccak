module Keccak.Int exposing
    ( fips202_sha3_224
    , fips202_sha3_256
    , fips202_sha3_384
    , fips202_sha3_512
    , ethereum_keccak_256
    )

{-|

Shortcut hash functions using lists of int, as with the original API.

@docs fips202_sha3_224, fips202_sha3_256, fips202_sha3_384, fips202_sha3_512, ethereum_keccak_256
-}

import Keccak as K
import Bytes.Encode as BEnc

keccak : K.Config -> List Int -> List Int
keccak config ints =
    K.init config
    |> K.update (BEnc.encode (BEnc.sequence (List.map BEnc.unsignedInt8 ints)))
    |> K.finish

{-|
  Compute the sha3 224 of a list of byte width integers (0-255) as a list of
  byte width integers.
-}
fips202_sha3_224 = keccak K.fips202_sha3_224
{-|
  Compute the sha3 256 of a list of byte width integers (0-255) as a list of
  byte width integers.
-}
fips202_sha3_256 = keccak K.fips202_sha3_256
{-|
  Compute the sha3 384 of a list of byte width integers (0-255) as a list of
  byte width integers.
-}
fips202_sha3_384 = keccak K.fips202_sha3_384
{-|
  Compute the sha3 512 of a list of byte width integers (0-255) as a list of
  byte width integers.
-}
fips202_sha3_512 = keccak K.fips202_sha3_512
{-|
  Compute the ethereum style 256-bit hash of a list of byte width integers (0-255)
  as a list of byte width integers.
-}
ethereum_keccak_256 = keccak K.ethereum_keccak_256
