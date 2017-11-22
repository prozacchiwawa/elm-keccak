module Main exposing (..)

import Benchmark.Runner exposing (BenchmarkProgram, program)
import Benchmark exposing (Benchmark, benchmark1, describe)
import Char
import Hex
import Keccak
import SampleText

hexify l =
    String.concat (List.map (Hex.toString >> String.padLeft 2 '0') l)

listify sigtext =
    String.toList sigtext |> List.map Char.toCode

suite : Benchmark
suite =
    let indata = listify SampleText.lorem in
    let crashOnWrongHash =
        if indata |> Keccak.ethereum_keccak_256 |> hexify |> ((/=) SampleText.lorem_hash) then
            Debug.crash "wrong hash"
        else
            ()
    in
    describe "Keccak"
        [ describe "ethereum_keccak_256"
              [ benchmark1 "hash lorem" Keccak.ethereum_keccak_256 indata ]
        ]

main : BenchmarkProgram
main =
    program suite
