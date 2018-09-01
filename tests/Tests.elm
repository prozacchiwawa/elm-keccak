module Tests exposing (..)

import Expect
import Test exposing (..)

import Array
import Char
import Hex

import Keccak

p1 = Array.fromList [0xaa,0xaa,0xaa,0xaa,0x00,0x00,0x00,0x00]

hexify l =
    String.concat (List.map (Hex.toString >> String.padLeft 2 '0') l)

hexifyA a =
    String.concat (List.map (Hex.toString >> String.padLeft 2 '0') (Array.toList a))

foobar = "foobar"
testsig = "baz(uint32,bool)"
sigtext = "f(uint256,uint32[],bytes10,bytes)"

listify sigtext_ =
    String.toList sigtext_ |> List.map Char.toCode

-- 0e130d830bbb4754d860735bf6b4bb1b6e711069f59698862b96679edad9c832
data = """00: 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
14: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
28: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
3c: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
64: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
78: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
8c: 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
b4: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
"""

state = Array.initialize 200 (always 0)

suite : Test
suite =
    describe "keccak"
       [ test "empty sha3-224" <|
           \_ ->
             Expect.equal
                 (hexify (Keccak.fips202_sha3_224 []))
                 "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
       , test "empty sha3-256" <|
           \_ ->
             Expect.equal
                 (hexify (Keccak.fips202_sha3_256 []))
                 "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
       , test "empty sha3-384" <|
           \_ ->
             Expect.equal
                 (hexify (Keccak.fips202_sha3_384 []))
                 "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
       , test "empty sha3-512" <|
           \_ ->
             Expect.equal
                 (hexify (Keccak.fips202_sha3_512 []))
                 "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
       , test "'foobar' sha3-384" <|
           \_ ->
               Expect.equal
                   (hexify (Keccak.fips202_sha3_384 (listify foobar)))
                   "0fa8abfbdaf924ad307b74dd2ed183b9a4a398891a2f6bac8fd2db7041b77f068580f9c6c66f699b496c2da1cbcc7ed8"
       , test (testsig ++ " keccak-256") <|
           \_ ->
               Expect.equal
                   (hexify (Keccak.ethereum_keccak_256 (listify testsig)))
                   "cdcd77c0992ec5bbfc459984220f8c45084cc24d9b6efed1fae540db8de801d2"
       , test (sigtext ++ " keccak-256") <|
           \_ ->
               Expect.equal
                   (hexify (Keccak.ethereum_keccak_256 (listify sigtext)))
                   "8be652465888a0c5d65fc9d0a7e898b9ca98de97185c53a54ec408fd2fd5d45d"
       , test "longer string to verify multiple rounds (sha3-256)" <|
           \_ ->
               Expect.equal
                   (hexify (Keccak.fips202_sha3_256 (listify data)))
                   "0e130d830bbb4754d860735bf6b4bb1b6e711069f59698862b96679edad9c832"
       ]
