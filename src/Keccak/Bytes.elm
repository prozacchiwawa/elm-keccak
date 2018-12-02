module Keccak.Bytes exposing
    ( fips202_sha3_224
    , fips202_sha3_256
    , fips202_sha3_384
    , fips202_sha3_512
    , ethereum_keccak_256
    )

{-|

Shortcut hash functions using elm/bytes.

@docs fips202_sha3_224, fips202_sha3_256, fips202_sha3_384, fips202_sha3_512, ethereum_keccak_256
-}

import Bytes as B
import Keccak as K

keccak : K.Config -> B.Bytes -> List Int
keccak config bytes =
    K.init config
    |> K.update bytes
    |> K.finish

{-|
  Compute the sha3 224 of a Bytes value as a list of byte width integers.
-}
fips202_sha3_224 : B.Bytes -> List Int
fips202_sha3_224 = keccak K.fips202_sha3_224
{-|
  Compute the sha3 256 of a Bytes value as a list of byte width integers.
-}
fips202_sha3_256 : B.Bytes -> List Int
fips202_sha3_256 = keccak K.fips202_sha3_256
{-|
  Compute the sha3 384 of a Bytes value as a list of byte width integers.
-}
fips202_sha3_384 : B.Bytes -> List Int
fips202_sha3_384 = keccak K.fips202_sha3_384
{-|
  Compute the sha3 512 of a Bytes value as a list of byte width integers.
-}
fips202_sha3_512 : B.Bytes -> List Int
fips202_sha3_512 = keccak K.fips202_sha3_512
{-|
  Compute the ethereum 256 bit hash of a Bytes value as a list of byte width integers.
-}
ethereum_keccak_256 : B.Bytes -> List Int
ethereum_keccak_256 = keccak K.ethereum_keccak_256
