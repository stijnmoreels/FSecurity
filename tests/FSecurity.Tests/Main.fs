module Main

open Expecto

#nowarn "0046"

[<EntryPoint>]
let main argv =
  Tests.runTestsInAssembly 
    { defaultConfig with parallel = false } 
    argv