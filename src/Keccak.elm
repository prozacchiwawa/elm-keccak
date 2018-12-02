module Keccak exposing
    ( State
    , Config
    , fips202_sha3_224
    , fips202_sha3_256
    , fips202_sha3_384
    , fips202_sha3_512
    , ethereum_keccak_256
    , init
    , update
    , finish
    )
{-|

Implementation by the [Keccak](http://keccak.noekeon.org/), [Keyak](http://keyak.noekeon.org/) and [Ketje](http://ketje.noekeon.org/) Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:




To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

Ported to elm by Art Yerkes.

ethereum_keccak_256 is the hash function used in many places related to the
ethereum cryptocurrency.  It is different from sha3 in the padding used.

Elm 0.19 update by Coury Ditch
https://github.com/cmditch

# Functions
@docs State, Config, fips202_sha3_224, fips202_sha3_256, fips202_sha3_384, fips202_sha3_512, ethereum_keccak_256, init, update, finish

For a replacement for the original version of this library,

    -- Exposes fips_202_sha3_224 etc with int list inputs
    import Keccak.Int as Keccak 

For slightly better versions of the originals using <a href='https://package.elm-lang.org/packages/elm/bytes/latest/Bytes'>elm/bytes</a>,

    -- Exposes fips202_sha3_224 etc with <a href='https://package.elm-lang.org/packages/elm/bytes/latest/Bytes#Bytes'>bytes</a> inputs
    import Keccak.Bytes as Keccak
    import Bytes.Encode as BEnc

    hexify (Keccak.ethereum_keccak_256 (BEnc.string "baz(uint32,bool)")) -- "cdcd77c0992ec5bbfc459984220f8c45084cc24d9b6efed1fae540db8de801d2"

This library exposes configurations named by their respective exports as well as
general hashing functions:

    -- Initialize a hasher state.
    init config
    -- Add bytes to hash.
    update bytes state
    -- Return the hash value.
    finish state

They can be used together like:

    init ethereum_keccak_256 
    |> update (BEnc.encode (BEnc.string "1"))
    |> update (Benc.encode (Benc.string "2"))
    |> finish

-}

import Array exposing (Array)
import Bytes as B
import Bytes.Decode as BDec
import Bytes.Decode exposing (Step(..))
import Bytes.Encode as BEnc
import Bitwise
import List.Extra as ListX

{-
================================================================
The purpose of this source file is to demonstrate a readable and compact
implementation of all the Keccak instances approved in the FIPS 202 standard,
including the hash functions and the extendable-output functions (XOFs).

We focused on clarity and on source-code compactness,
rather than on the performance.

The advantages of this implementation are:
    + The source code is compact, after removing the comments, that is. :-)
    + There are no tables with arbitrary constants.
    + For clarity, the comments link the operations to the specifications using
        the same notation as much as possible.
    + There is no restriction in cryptographic features. In particular,
        the SHAKE128 and SHAKE256 XOFs can produce any output length.
    + The code does not use much RAM, as all operations are done in place.

The drawbacks of this implementation are:
    - There is no message queue. The whole message must be ready in a buffer.
    - It is not optimized for peformance.

The implementation is even simpler on a little endian platform. Just define the
LITTLE_ENDIAN symbol in that case.

For a more complete set of implementations, please refer to
the Keccak Code Package at https://github.com/gvanas/KeccakCodePackage

For more information, please refer to:
    * [Keccak Reference] http://keccak.noekeon.org/Keccak-reference-3.0.pdf
    * [Keccak Specifications Summary] http://keccak.noekeon.org/specs_summary.html

This file uses UTF-8 encoding, as some comments use Greek letters.
================================================================
-}

{-*
  * Function to compute the Keccak[r, c] sponge function over a given input.
  * @param  rate            The value of the rate r.
  * @param  capacity        The value of the capacity c.
  * @param  input           Pointer to the input message.
  * @param  inputByteLen    The number of input bytes provided in the input message.
  * @param  delimitedSuffix Bits that will be automatically appended to the end
  *                         of the input message, as in domain separation.
  *                         This is a byte containing from 0 to 7 bits
  *                         These <i>n</i> bits must be in the least significant bit positions
  *                         and must be delimited with a bit 1 at position <i>n</i>
  *                         (counting from 0=LSB to 7=MSB) and followed by bits 0
  *                         from position <i>n</i>+1 to position 7.
  *                         Some examples:
  *                             - If no bits are to be appended, then @a delimitedSuffix must be 0x01.
  *                             - If the 2-bit sequence 0,1 is to be appended (as for SHA3-*), @a delimitedSuffix must be 0x06.
  *                             - If the 4-bit sequence 1,1,1,1 is to be appended (as for SHAKE*), @a delimitedSuffix must be 0x1F.
  *                             - If the 7-bit sequence 1,1,0,1,0,0,0 is to be absorbed, @a delimitedSuffix must be 0x8B.
  * @param  output          Pointer to the buffer where to store the output.
  * @param  outputByteLen   The number of output bytes desired.
  * @pre    One must have r+c=1600 and the rate a multiple of 8 bits in this implementation.
  -}
-- void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen);

{-
================================================================
Technicalities
================================================================
-}

bitsPerElement = 32
bytesPerElement = bitsPerElement // 8
elementMask = 0xffffffff
twentyFive = List.range 0 25
twentyThree = List.range 0 23

type alias Elt = (Int, Int)

type alias St = (Array Elt)

tupleMap f (a,b) = (f a,f b)
tupleMap2 f (a1,b1) (a2,b2) = (f a1 a2, f b1 b2)

--typedef unsigned char UINT8;
--typedef unsigned long long int UINT64;
--typedef UINT64 tKeccakLane;

--#ifndef LITTLE_ENDIAN
{-* Function to load a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  -}
--static UINT64 load64(const UINT8 *x)
load64 : Int -> St -> Elt
load64 off arr =
--{
    --int i;
    --UINT64 u=0;
    case Array.get off arr of
        Just a -> a
        _ -> (0,0) -- -- Was `Debug.crash "wrong offset"` in 0.18, but had to remove for 0.19. This is considered an impossible state.
--}

{-* Function to store a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  -}
--static void store64(UINT8 *x, UINT64 u)
store64 : Int -> Elt -> St -> St
store64 off v arr =
    Array.set off v arr

storexor64 : Int -> Elt -> St -> St
storexor64 off v arr =
    updateArray off (xor64 v) arr

{-* Function to XOR into a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  -}
--static void xor64(UINT8 *x, UINT64 u)
xor64 : Elt -> Elt -> Elt
xor64 v arr =
    tupleMap2 Bitwise.xor v arr
--#endif

-- Same as Array.Extra.update
updateArray : Int -> (a -> a) -> Array a -> Array a
updateArray n f a =
    let
        element =
            Array.get n a
    in
    case element of
        Nothing ->
            a
        Just element_ ->
            Array.set n (f element_) a
{-
================================================================
A readable and compact implementation of the Keccak-f[1600] permutation.
================================================================
-}

--#define ROL64(a, offset) ((((UINT64)a) << offset) ^ (((UINT64)a) >> (64-offset)))
--#define i(x, y) ((x)+5*(y))

iPerm : Int -> Int -> Int
iPerm x y = (5*y) + x

rolbytes : Int -> Elt -> Elt
rolbytes n (va,vb) =
    if n == 0 then (va,vb) else (vb,va)

rolbits : Int -> Elt -> Elt
rolbits n v =
    if n == 0 then
        v
    else
        let oneRotated = rolbytes 1 v in
        tupleMap2
            (\a b -> Bitwise.and elementMask (Bitwise.or (Bitwise.shiftLeftBy n a) (Bitwise.shiftRightZfBy (bitsPerElement-n) b)))
            v oneRotated

rol64 : Int -> Elt -> Elt
rol64 n v =
    let
        rby = modBy bitsPerElement (n // bitsPerElement)
        rbi = modBy bitsPerElement n
        rotated = rolbytes rby v
    in
    rolbits rbi rotated

and64 : Elt -> Elt -> Elt
and64 a b =
    tupleMap2 Bitwise.and a b

inv64 : Elt -> Elt
inv64 a =
    tupleMap (Bitwise.complement >> Bitwise.and elementMask) a

--#ifdef LITTLE_ENDIAN
--    #define readLane(x, y)          (((tKeccakLane*)state)[i(x, y)])
--    #define writeLane(x, y, lane)   (((tKeccakLane*)state)[i(x, y)]) = (lane)
--    #define XORLane(x, y, lane)     (((tKeccakLane*)state)[i(x, y)]) ^= (lane)
--#else
--    #define readLane(x, y)          load64((UINT8*)state+sizeof(tKeccakLane)*i(x, y))
--    #define writeLane(x, y, lane)   store64((UINT8*)state+sizeof(tKeccakLane)*i(x, y), lane)
--    #define XORLane(x, y, lane)     xor64((UINT8*)state+sizeof(tKeccakLane)*i(x, y), lane)
--#endif

readLane : Int -> Int -> St -> Elt
readLane x y state =
    let off = iPerm x y in
    load64 off state

writeLane : Int -> Int -> Elt -> St -> St
writeLane x y lane state =
    let off = iPerm x y in
    store64 off lane state

xorLane : Int -> Int -> Elt -> St -> St
xorLane x y lane state =
    let off = iPerm x y in
    storexor64 off lane state

{-*
  * Function that computes the linear feedback shift register (LFSR) used to
  * define the round constants (see [Keccak Reference, Section 1.2]).
  -}
--int LFSR86540(UINT8 *LFSR)
lfsr86540 : Int -> (Bool, Int)
lfsr86540 lfsr =
--{
    let result = (Bitwise.and lfsr 1) /= 0 in
    if (Bitwise.and lfsr 0x80) /= 0 then
        -- Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
        (result, Bitwise.xor (Bitwise.shiftLeftBy 1 lfsr) 0x71)
    else
        (result, Bitwise.shiftLeftBy 1 lfsr)
--}

type alias KeccakRound =
    { x : Int
    , y : Int
    , state : St
    , current : Elt
    , lfsrstate : Int
    }

zero : Elt
zero = (0,0)
one : Elt
one = (1,0)

five : List Int
five = List.range 0 4

cInitX x state =
    xor64 (readLane x 0 state)
        (xor64 (readLane x 1 state)
             (xor64 (readLane x 2 state)
                  (xor64 (readLane x 3 state) (readLane x 4 state))
             )
        )

gd n { d0, d1, d2, d3, d4 } =
    case n of
        0 -> d0
        1 -> d1
        2 -> d2
        3 -> d3
        _ -> d4

theta : KeccakRound -> KeccakRound
theta ss =
    let
        d x =
            let
                c4 = cInitX (modBy 5 (x+4)) ss.state
                c1 = cInitX (modBy 5 (x+1)) ss.state
            in
            xor64 c4 (rol64 1 c1)

        dx =
            { d0 = d 0, d1 = d 1, d2 = d 2, d3 = d 3, d4 = d 4}

        sd =
            List.foldl
                (\n state ->
                        let x = modBy 5 n in
                        let y = n // 5 in
                        xorLane x y (gd x dx) state
                )
                ss.state
                twentyFive
    in
    { ss | state = sd }

rhoPi : KeccakRound -> KeccakRound
rhoPi ss =
    -- Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23 */
    List.foldl
        (\t ss_ ->
            let
            -- Compute the rotation constant r = (t+1)(t+2)/2 */
                r = modBy 64 (((t+1)*(t+2))//2)
            -- Compute ((0 1)(2 3)) * (x y) */
                yy = modBy 5 (2*ss_.x+3*ss_.y)
            in
            -- Swap current and state(x,y), and rotate */
            { ss_
            | x = ss_.y
            , y = yy
            , current = readLane ss_.y yy ss_.state
            , state = writeLane ss_.y yy (rol64 r ss_.current) ss_.state
            }
        )
        { ss | x = 1, y = 0, current = readLane 1 0 ss.state }
        twentyThree
    --}

chi : KeccakRound -> KeccakRound
chi ss =
    let
        newState =
            List.foldr
                (\y state ->
                     let
                        temp =
                            { d0 = readLane 0 y ss.state
                            , d1 = readLane 1 y ss.state
                            , d2 = readLane 2 y ss.state
                            , d3 = readLane 3 y ss.state
                            , d4 = readLane 4 y ss.state
                            }

                        yupdate x state_ =
                            writeLane x y
                                (xor64 (gd x temp)
                                (and64 (inv64 (gd (modBy 5 (x+1)) temp))
                                (gd (modBy 5 (x+2)) temp)))
                                state_
                     in
                     state
                        |> yupdate 0
                        |> yupdate 1
                        |> yupdate 2
                        |> yupdate 3
                        |> yupdate 4
                )
                ss.state
                five
    in
    { ss | state = newState }

iota : KeccakRound -> KeccakRound
iota ss =
    List.foldl
        (\j ss_ ->
            let
                bitPosition = (Bitwise.shiftLeftBy j 1) - 1
                (o,lfsr) = lfsr86540 ss_.lfsrstate
            in
            if o then
                { ss_ | state = xorLane 0 0 (rol64 bitPosition one) ss_.state, lfsrstate = lfsr }
            else
                { ss_ | lfsrstate = lfsr }
        )
        ss
        (List.range 0 6)

initRound : St -> KeccakRound
initRound state =
    { x = 1
    , y = 0
    , state = state
    , current = zero
    , lfsrstate = 1
    }

{-*
 * Function that computes the Keccak-f[1600] permutation on the given state.
 -}
--void KeccakF1600_StatePermute(void *state)
keccakF1600_StatePermute : St -> St
keccakF1600_StatePermute state =
--{
    --unsigned int round, x, y, j, t;
    --UINT8 LFSRstate = 0x01;
    let
        res =
            List.foldr
                (\_ -> theta >> rhoPi >> chi >> iota)
                -- Start at coordinates (1 0) */
                (initRound state)
                twentyThree
    in
    res.state
    --for(round=0; round<24; round++) {
        --{   /* === θ step (see [Keccak Reference, Section 2.3.2]) === */

        --tKeccakLane C[5], D;

        -- Compute the parity of the columns */
        --}

        --{   /* === ρ and π steps (see [Keccak Reference, Sections 2.3.3 and 2.3.4]) === */
        --}

        --{   /* === χ step (see [Keccak Reference, Section 2.3.1]) === */
        --}

        --{   /* === ι step (see [Keccak Reference, Section 2.3.5]) === */
        --}
    --}

--}

{-
================================================================
A readable and compact implementation of the Keccak sponge functions
that use the Keccak-f[1600] permutation.
================================================================
-}

-- #include <string.h>
-- #define MIN(a, b) ((a) < (b) ? (a) : (b))

xorFromByte shift sel by =
    if sel == 0 then
        (Bitwise.shiftLeftBy shift by, 0)
    else
        (0, Bitwise.shiftLeftBy shift by)

xorByteIntoState : Int -> Int -> St -> St
xorByteIntoState i v state =
    let
        e = modBy 2 (i//bytesPerElement)
        shift = 8 * (modBy bytesPerElement i)
        newElt = xorFromByte shift e v
    in
    storexor64 (i//8) newElt state

xorIntoState : List Int -> St -> St
xorIntoState block state =
    List.foldl
        (\(i,e) s -> xorByteIntoState i e s)
        state
        (List.indexedMap (\i e -> (i,e)) block)

retrieveOutputByte : Int -> St -> Int
retrieveOutputByte i arr =
    let
        e = modBy 2 (i//bytesPerElement)
        shift = 8*(modBy bytesPerElement i)
        (ea,eb) = Array.get (i//8) arr |> Maybe.withDefault (0,0)
        byi = if e == 0 then ea else eb
    in
    Bitwise.shiftRightBy shift byi |> Bitwise.and 0xff

type alias ConfigAlias =
    { rate : Int
    , capacity : Int
    , delSuffix : Int
    , outputLen : Int
    }
        
{-| A configuration for a keccak hasher. -}
type Config = KC ConfigAlias

{-| The state of the keccak hasher. -}
type State = KS
    { config : ConfigAlias
    , inputLength : Int
    , state : St
    , partial : List B.Bytes
    }

{-| Prepare a keccak instance to do hashing with the given configuration. -}
init : Config -> State
init (KC config) =
    KS
      { config = config
      , inputLength = 0
      , state = Array.initialize 25 (always zero)
      , partial = []
      }

emptyBytes : B.Bytes
emptyBytes = BEnc.encode (BEnc.sequence [])

byteDecoder : BDec.Decoder Int
byteDecoder = BDec.unsignedInt8

-- Thanks, docs
listStep : BDec.Decoder a -> ((Int, List a) -> BDec.Decoder (Step (Int, List a) (List a)))
listStep decoder (n,xs) =
    if n <= 0 then
        BDec.succeed (BDec.Done (List.reverse xs))
    else
        BDec.map (\x -> BDec.Loop (n - 1, x :: xs)) decoder

intListOfBytes : B.Bytes -> List Int
intListOfBytes b =
    BDec.decode (BDec.loop (B.width b, []) (listStep BDec.unsignedInt8)) b
        |> Maybe.withDefault []

restOfBytesDecoder : Int -> Int -> BDec.Decoder B.Bytes
restOfBytesDecoder n m =
    BDec.bytes n
       |> BDec.andThen (\x -> BDec.bytes m)
          
restOfBytes : Int -> B.Bytes -> B.Bytes
restOfBytes n b =
    BDec.decode (restOfBytesDecoder n ((B.width b) - n)) b
        |> Maybe.withDefault emptyBytes

concatBytesList newPartial =
    BEnc.encode
        (BEnc.sequence (List.map BEnc.bytes (List.reverse newPartial)))

{-| Include the given bytes in the hash. -}
update : B.Bytes -> State -> State
update b (KS state) =
    let
        newPartial =
            if B.width b == 0 then
                state.partial
            else
                b :: state.partial
        storedBytes = List.foldl (\bs s -> s + (B.width bs)) 0 newPartial
        rateInBytes = state.config.rate // 8
    in
    if storedBytes >= rateInBytes then
        let
            concat = concatBytesList newPartial

            first =
                BDec.decode (BDec.bytes rateInBytes) concat
                  |> Maybe.withDefault emptyBytes

            rest = restOfBytes rateInBytes concat

            inb = intListOfBytes first
                     
            s1 = xorIntoState inb state.state

            s2 = keccakF1600_StatePermute s1
        in
        update emptyBytes
            (KS
             { state
                 | state = s2
                 , inputLength = (B.width b) + state.inputLength
                 , partial = [rest]
             }
            )
    else
        (KS
         { state
             | inputLength = (B.width b) + state.inputLength
             , partial = newPartial
         }
        )

{-| Consume the given hash state and return a list of ints representing the hash. -}
finish : State -> List Int
finish (KS state) =
    let
        config = state.config

        inputLength = state.inputLength

        concat = concatBytesList state.partial

        inb = intListOfBytes concat

        s1 = xorIntoState inb state.state

        rateInBytes = state.config.rate // 8

        blockSize =
            if inputLength == 0 then
                0
            else if modBy rateInBytes inputLength == 0 then
                rateInBytes
            else
                modBy rateInBytes inputLength
    in
    if ((config.rate + config.capacity) /= 1600) || (modBy 8 config.rate) /= 0 then
        [] -- Was `Debug.crash "wrong capacity or rate"` in 0.18, but had to remove for 0.19. This is considered an impossible state.
    else
        -- === Do the padding and switch to the squeezing phase ===
        -- Absorb the last few bits and add the first bit of padding (which coincides with the delimiter in delimitedSuffix) */
        let
            state1 = xorByteIntoState blockSize config.delSuffix s1

            state2 =
            -- If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
                if (((Bitwise.and config.delSuffix 0x80) /= 0) && (blockSize == (rateInBytes-1))) then
                    keccakF1600_StatePermute state1
                else
                    state1

        -- Add the second bit of padding */
            state3 = xorByteIntoState (rateInBytes - 1) 0x80 state2

        -- Switch to the squeezing phase */
            state4 = keccakF1600_StatePermute state3


        -- === Squeeze out all the output blocks === */
            processRemainingOutput state_ output_ outputByteLen =
                if outputByteLen > 0 then
                    let
                        blockSize_ = min outputByteLen rateInBytes
                        outputBytes =
                            List.range 0 blockSize_
                                |> List.map (\i -> retrieveOutputByte i state4)
                    in
                    processRemainingOutput
                        (keccakF1600_StatePermute state_)
                        (output_ ++ outputBytes)
                        (outputByteLen - blockSize_)
                else
                    output_
       in
       List.take config.outputLen (processRemainingOutput state4 [] config.outputLen)

{-*
  *  Function to compute SHAKE128 on the input message with any output length.
  -}
--void FIPS202_SHAKE128(const unsigned char *input, unsigned int inputByteLen, unsigned char *output, int outputByteLen)
--{
--    Keccak(1344, 256, input, inputByteLen, 0x1F, output, outputByteLen);
--}

{-*
  *  Function to compute SHAKE256 on the input message with any output length.
  -}
--void FIPS202_SHAKE256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output, int outputByteLen)
--{
--    Keccak(1088, 512, input, inputByteLen, 0x1F, output, outputByteLen);
--}

{-*
  *  Function to compute SHA3-224 on the input message. The output length is fixed to 28 bytes.
  -}
--void FIPS202_SHA3_224(const unsigned char *input, unsigned int inputByteLen, unsigned char *output)
--{
--    Keccak(1152, 448, input, inputByteLen, 0x06, output, 28);
--}

{-| Configuration for SHA3-224 -}
fips202_sha3_224 : Config
fips202_sha3_224 =
    KC { rate = 1152, capacity = 448, delSuffix = 6, outputLen = 28 }

{-*
  *  Function to compute SHA3-256 on the input message. The output length is fixed to 32 bytes.
  -}
--void FIPS202_SHA3_256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output)
--{
--    Keccak(1088, 512, input, inputByteLen, 0x06, output, 32);
--}

{-| Configuration for SHA3-256 -}
fips202_sha3_256 : Config
fips202_sha3_256 =
    KC { rate = 1088, capacity = 512, delSuffix = 6, outputLen = 32 }

{-| Configuration for ethereum 256 bit hashes -}
ethereum_keccak_256 : Config
ethereum_keccak_256 =
    KC { rate = 1088, capacity = 512, delSuffix = 1, outputLen = 32 }

{-*
  *  Function to compute SHA3-384 on the input message. The output length is fixed to 48 bytes.
  -}
--void FIPS202_SHA3_384(const unsigned char *input, unsigned int inputByteLen, unsigned char *output)
--{
--    Keccak(832, 768, input, inputByteLen, 0x06, output, 48);
--}

{-| Configuration for SHA3-384 -}
fips202_sha3_384 : Config
fips202_sha3_384 =
    KC { rate = 832, capacity = 768, delSuffix = 6, outputLen = 48 }

{-*
  *  Function to compute SHA3-512 on the input message. The output length is fixed to 64 bytes.
  -}
--void FIPS202_SHA3_512(const unsigned char *input, unsigned int inputByteLen, unsigned char *output)
--{
--    Keccak(576, 1024, input, inputByteLen, 0x06, output, 64);
--}

{-| Configuration for SHA3-512 -}
fips202_sha3_512 : Config
fips202_sha3_512 =
    KC { rate = 576, capacity = 1024, delSuffix = 6, outputLen = 64 }
