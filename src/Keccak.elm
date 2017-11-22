module Keccak exposing
    ( fips202_sha3_224
    , fips202_sha3_256
    , fips202_sha3_384
    , fips202_sha3_512
    , ethereum_keccak_256
    )

{-|

Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

Ported to elm by Art Yerkes.

ethereum_keccak_256 is the hash function used in many places related to the
ethereum cryptocurrency.  It is different from sha3 in the padding used.

# Functions
@docs fips202_sha3_224, fips202_sha3_256, fips202_sha3_384, fips202_sha3_512, ethereum_keccak_256

-}

import Array exposing (Array)
import Array.Extra as ArrayX
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

aslice b s a =
    if b == s then
        Array.empty
    else
        Array.slice b s a

--typedef unsigned char UINT8;
--typedef unsigned long long int UINT64;
--typedef UINT64 tKeccakLane;

--#ifndef LITTLE_ENDIAN
{-* Function to load a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  -}
--static UINT64 load64(const UINT8 *x)
load64 : Int -> Array Int -> Array Int
load64 off arr =
--{
    --int i;
    --UINT64 u=0;
    Array.slice off (off + 4) arr
--}

{-* Function to store a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  -}
--static void store64(UINT8 *x, UINT64 u)
store64 : Int -> Array Int -> Array Int -> Array Int
store64 off v arr =
    Array.foldr
        (\(i,v) a -> Array.set (i+off) v a)
        arr
        (Array.indexedMap (\i e -> (i,e)) v)

storexor64 : Int -> Array Int -> Array Int -> Array Int
storexor64 off v arr =
    Array.foldr
        (\(i,v) a -> (ArrayX.update (i+off) (Bitwise.xor v) a))
        arr
        (Array.indexedMap (\i e -> (i,e)) v)

{-* Function to XOR into a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  -}
--static void xor64(UINT8 *x, UINT64 u)
xor64 : Array Int -> Array Int -> Array Int
xor64 v arr =
    ArrayX.map2 Bitwise.xor v arr
--#endif

{-
================================================================
A readable and compact implementation of the Keccak-f[1600] permutation.
================================================================
-}

--#define ROL64(a, offset) ((((UINT64)a) << offset) ^ (((UINT64)a) >> (64-offset)))
--#define i(x, y) ((x)+5*(y))

i : Int -> Int -> Int
i x y = (5*y) + x

rolbytes : Int -> Array Int -> Array Int
rolbytes n v =
    Array.append (Array.slice ((4-n)%4) (Array.length v) v) (Array.slice 0 ((4-n)%4) v)

rolbits : Int -> Array Int -> Array Int
rolbits n v =
    if n == 0 then
        v
    else
        let oneRotated = rolbytes 1 v in
        ArrayX.map2
            (\a b -> Bitwise.and 0xffff (Bitwise.or (Bitwise.shiftLeftBy n a) (Bitwise.shiftRightZfBy (16-n) b)))
            v oneRotated

rol64 : Int -> Array Int -> Array Int
rol64 n v =
    let rby = (n // 16) % 16 in
    let rbi = n % 16 in
    let rotated = rolbytes rby v in
    rolbits rbi rotated

and64 : Array Int -> Array Int -> Array Int
and64 a b =
    ArrayX.map2 Bitwise.and a b

inv64 : Array Int -> Array Int
inv64 a =
    Array.map (Bitwise.complement >> Bitwise.and 0xffff) a

--#ifdef LITTLE_ENDIAN
--    #define readLane(x, y)          (((tKeccakLane*)state)[i(x, y)])
--    #define writeLane(x, y, lane)   (((tKeccakLane*)state)[i(x, y)]) = (lane)
--    #define XORLane(x, y, lane)     (((tKeccakLane*)state)[i(x, y)]) ^= (lane)
--#else
--    #define readLane(x, y)          load64((UINT8*)state+sizeof(tKeccakLane)*i(x, y))
--    #define writeLane(x, y, lane)   store64((UINT8*)state+sizeof(tKeccakLane)*i(x, y), lane)
--    #define XORLane(x, y, lane)     xor64((UINT8*)state+sizeof(tKeccakLane)*i(x, y), lane)
--#endif

readLane : Int -> Int -> Array Int -> Array Int
readLane x y state =
    let off = 4 * (i x y) in
    load64 off state

writeLane : Int -> Int -> Array Int -> Array Int -> Array Int
writeLane x y lane state =
    let off = 4 * (i x y) in
    store64 off lane state

xorLane : Int -> Int -> Array Int -> Array Int -> Array Int
xorLane x y lane state =
    let off = 4 * (i x y) in
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
    , state : Array Int
    , current : Array Int
    , lfsrstate : Int
    }

zero : Array Int
zero = Array.initialize 4 (always 0)
one : Array Int
one = Array.initialize 4 (\n -> if n == 0 then 1 else 0)

five : List Int
five = List.range 0 4

cInit state =
    Array.initialize 5
        (\x ->
            xor64 (readLane x 0 state)
                (xor64 (readLane x 1 state)
                    (xor64 (readLane x 2 state)
                        (xor64 (readLane x 3 state) (readLane x 4 state))
                    )
                )
        )

theta : KeccakRound -> KeccakRound
theta ss =
    let c = cInit ss.state in
    let d =
        List.map
            (\x ->
                 let
                     dx : Array Int
                     dx =
                         case (Array.get ((x+4)%5) c, Array.get ((x+1)%5) c) of
                             (Just c4, Just c1) -> xor64 c4 (rol64 1 c1)
                             _ -> Debug.crash "wrong indices"
                 in
                 dx
            )
            five
    in
    List.foldr
        (\(x,d) ss ->
            List.foldr
                (\y ss -> { ss | state = xorLane x y d ss.state })
                ss
                five
        )
        ss
        (List.indexedMap (\i d -> (i,d)) d)

rhoPi : KeccakRound -> KeccakRound
rhoPi ss =
    -- Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23 */
    List.foldl
        (\t ss ->
            -- Compute the rotation constant r = (t+1)(t+2)/2 */
            let r = (((t+1)*(t+2))//2)%64 in
            -- Compute ((0 1)(2 3)) * (x y) */
            let yy = (2*ss.x+3*ss.y)%5 in
            -- Swap current and state(x,y), and rotate */
            { ss
            | x = ss.y
            , y = yy
            , current = readLane ss.y yy ss.state
            , state = writeLane ss.y yy (rol64 r ss.current) ss.state
            }
        )
        { ss | x = 1, y = 0, current = readLane 1 0 ss.state }
        (List.range 0 23)
    --}

chi : KeccakRound -> KeccakRound
chi ss =
    List.foldr
        (\y ss ->
            let temp =
                List.map (\x -> readLane x y ss.state) five
                |> Array.fromList
            in
            List.foldr
                (\x ss ->
                    case (Array.get x temp, Array.get ((x+1)%5) temp, Array.get ((x+2)%5) temp) of
                        (Just t0, Just t1, Just t2) ->
                            { ss
                            | state = writeLane x y (xor64 t0 (and64 (inv64 t1) t2)) ss.state
                            }
                        _ -> Debug.crash "Failure in chi"
                )
                ss
                five
        )
        ss
        five

iota : KeccakRound -> KeccakRound
iota ss =
    List.foldl
        (\j ss ->
            let bitPosition = (Bitwise.shiftLeftBy j 1) - 1 in
            let (o,lfsr) = lfsr86540 ss.lfsrstate in
            if o then
                { ss | state = xorLane 0 0 (rol64 bitPosition one) ss.state, lfsrstate = lfsr }
            else
                { ss | lfsrstate = lfsr }
        )
        ss
        (List.range 0 6)

initRound : Array Int -> KeccakRound
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
keccakF1600_StatePermute : Array Int -> Array Int
keccakF1600_StatePermute state =
--{
    --unsigned int round, x, y, j, t;
    --UINT8 LFSRstate = 0x01;
    let res =
        List.foldr
            (\_ -> theta >> rhoPi >> chi >> iota)
            -- Start at coordinates (1 0) */
            (initRound (Debug.log "state" state))
            (List.range 0 23)
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

endian = 0

xorByteIntoState : Int -> Int -> Array Int -> Array Int
xorByteIntoState i v state =
    let e = i//2 in
    let shift = 8*((Bitwise.xor i endian)%2) in
    ArrayX.update e (Bitwise.xor (Bitwise.shiftLeftBy shift v)) state
        
xorIntoState : List Int -> Array Int -> Array Int
xorIntoState block state =
    List.foldl
        (\(i,e) s -> xorByteIntoState i e s)
        state
        (List.indexedMap (\i e -> (i,e)) block)

retrieveOutputByte : Int -> Array Int -> Int
retrieveOutputByte i arr =
    let e = i//2 in
    let shift = 8*((Bitwise.xor i endian)%2) in
    Array.get e arr
    |> Maybe.withDefault 0
    |> Bitwise.shiftRightBy shift
    |> Bitwise.and 0xff

keccak : Int -> Int -> List Int -> Int -> List Int -> Int -> List Int
keccak rate capacity input delSuffix output outputLen =
-- (unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen)
    --UINT8 state[200];
    let rateInBytes = rate // 8 in
    --unsigned int rateInBytes = rate/8;
    --unsigned int blockSize = 0;
    --unsigned int i;

    let inputLength = List.length input in

    let blockSize =
        if inputLength == 0 then
            0
        else if inputLength % rateInBytes == 0 then
            rateInBytes
        else
            inputLength % rateInBytes
    in

    let state =
        ListX.greedyGroupsOf rateInBytes input
        |> List.foldl
           (\inb state ->
                let s1 = xorIntoState inb state in
                if (List.length inb) == rateInBytes then
                    keccakF1600_StatePermute s1
                else
                    s1
           )
           (Array.initialize 100 (always 0))
    in

    if ((rate + capacity) /= 1600) || (rate % 8) /= 0 then
        Debug.crash "wrong capacity or rate"
    else
        -- === Do the padding and switch to the squeezing phase ===
        -- Absorb the last few bits and add the first bit of padding (which coincides with the delimiter in delimitedSuffix) */
        let state1 = xorByteIntoState blockSize delSuffix state in

        let state2 =
            -- If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
            if (((Bitwise.and delSuffix 0x80) /= 0) && (blockSize == (rateInBytes-1))) then
                keccakF1600_StatePermute state1
            else
                state1
        in
        -- Add the second bit of padding */
        let state3 = xorByteIntoState (rateInBytes - 1) 0x80 state2 in
 
        -- Switch to the squeezing phase */
        let state4 = keccakF1600_StatePermute state3 in
 
                   
        -- === Squeeze out all the output blocks === */
        let processRemainingOutput state output outputByteLen =
            if outputByteLen > 0 then
                let blockSize = min outputByteLen rateInBytes in
                let outputBytes =
                    List.range 0 blockSize
                    |> List.map (\i -> retrieveOutputByte i state4)
                in
                processRemainingOutput
                    (keccakF1600_StatePermute state)
                    (output ++ outputBytes)
                    (outputByteLen - blockSize)
            else
                output
       in
       List.take outputLen (processRemainingOutput state4 output outputLen)

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

{-|
  Compute the sha3 224 of a list of byte width integers (0-255) as a list of
  byte width integers.
-}
fips202_sha3_224 : List Int -> List Int
fips202_sha3_224 input =
    keccak 1152 448 input 6 [] 28

{-*
  *  Function to compute SHA3-256 on the input message. The output length is fixed to 32 bytes.
  -}
--void FIPS202_SHA3_256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output)
--{
--    Keccak(1088, 512, input, inputByteLen, 0x06, output, 32);
--}

{-|
  Compute the sha3 256 of a list of byte width integers (0-255) as a list of
  byte width integers.
-}
fips202_sha3_256 : List Int -> List Int
fips202_sha3_256 input =
    keccak 1088 512 input 6 [] 32

{-|
  Compute the ethereum style 256-bit hash of a list of byte width integers (0-255)
  as a list of byte width integers.
-}
ethereum_keccak_256 : List Int -> List Int
ethereum_keccak_256 input =
    keccak 1088 512 input 1 [] 32
        
{-*
  *  Function to compute SHA3-384 on the input message. The output length is fixed to 48 bytes.
  -}
--void FIPS202_SHA3_384(const unsigned char *input, unsigned int inputByteLen, unsigned char *output)
--{
--    Keccak(832, 768, input, inputByteLen, 0x06, output, 48);
--}

{-|
  Compute the sha3 384 of a list of byte width integers (0-255) as a list of
  byte width integers.
-}
fips202_sha3_384 : List Int -> List Int
fips202_sha3_384 input =
    keccak 832 768 input 6 [] 48

{-*
  *  Function to compute SHA3-512 on the input message. The output length is fixed to 64 bytes.
  -}
--void FIPS202_SHA3_512(const unsigned char *input, unsigned int inputByteLen, unsigned char *output)
--{
--    Keccak(576, 1024, input, inputByteLen, 0x06, output, 64);
--}

{-|
  Compute the sha3 512 of a list of byte width integers (0-255) as a list of
  byte width integers.
-}
fips202_sha3_512 : List Int -> List Int
fips202_sha3_512 input =
    keccak 576 1024 input 6 [] 64
