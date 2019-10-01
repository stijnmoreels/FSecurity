namespace FSecurity

open System
open System.Collections.Generic
open System.Runtime.CompilerServices
open System.Net.Http
open System.Text

type internal FuzzType internal () = class end

/// Module that holds the available fuzzing collections.
module Fuzz =
    let private getResourceInput x = 
        use str = typeof<FuzzType>.Assembly.GetManifestResourceStream(sprintf "FSecurity.Resources.%s.txt" x)
        let rdr = new System.IO.StreamReader(str)
        rdr.ReadToEnd().Split([|System.Environment.NewLine|], System.StringSplitOptions.RemoveEmptyEntries)
        |> Seq.filter (fun x -> not <| x.StartsWith "#")

    /// Gets the alhpabethical charaters of a-z and A-Z.
    [<CompiledName("Alphabet")>]
    let alphabet =
        List.map string ['a'..'z'] 
        @ List.map string ['A'..'Z'] 

    /// Gets the alphanumerical series of a-z, A-Z, and 0-9.
    [<CompiledName("Alphanum")>]
    let alphanum =
        alphabet 
        @ List.map string [0..9]
        |> Array.ofList

    /// Gets the alphanumerical series of a-b, A-Z, 0-9, and all special charaters.
    [<CompiledName("AlphanumSpecial")>]
    let alphanum_special =
      alphanum
      |> Array.append [| "!"; "\"";  "#"; "$"; "%"; "&"; "'"; "("; ")"; "*"; "+";  ","; "-"; "."; "/"; ":"; ";"; "<"; "="; ">"; "?"; "@"; "["; "\\"; "]"; "^"; "_"; "`"; "{"; "|"; "}"; "~" |]

    /// Gets HTTP headers that expose information that can be used for fingerprinting.
    [<CompiledName("HttpLeakageHeaders")>]
    let httpLeakageHeaders = [| "Server"; "X-Powered-By"; "X-AspNet-Version"; "X-AspNetMvc-Version" |]

    let httpProtectHeaders = [ "X-XSS-protection"; "X-Frame-Options"; "Strict-Transport-Security" ]

    /// Gets all HTTP methods.
    [<CompiledName("HttpMethods")>]
    let httpMethods = 
        [| HttpMethod.Get; HttpMethod.Post; HttpMethod.Put; HttpMethod.Delete; HttpMethod.Head; HttpMethod.Options; HttpMethod.Trace |]

    /// Gets a series of content-type values.
    [<CompiledName("ContentType")>]
    let contentType = getResourceInput "content-type"

    /// John the Ripper dictionary collection.
    [<CompiledName("JohnTheRipper")>]
    let johnTheRipper = getResourceInput "john"

    /// Gets a series of XSS injection payloads.
    [<CompiledName("Xss")>]
    let xss = getResourceInput "xss.fuzz"

    /// Gets a series of fuzzed XML documents with malicious input.
    [<CompiledName("XmlDocument")>]
    let xmlDoc = getResourceInput "xml.fuzz.doc"

    /// Gets a series of fuzzed XML element and attribute malicious input values.
    [<CompiledName("XmlElemenAttribute")>]
    let xmlElemAttr = getResourceInput "xml.fuzz.elem+attr"

    /// External entity processing XML documents with malicious input.
    [<CompiledName("XmlXxe")>]
    let xmlXxe = getResourceInput "xml.fuzz.xxe"

    /// JSON fuzzed values with malicious input.
    [<CompiledName("Json")>]
    let json = getResourceInput "json.fuzz"

    /// Big list of naughty strings containing reserved strings, strings representing a numeric value, unicode/superscript, unicode font, zaglo text, right-to left strings, emoji, ...
    [<CompiledName("Naughty")>]
    let naughty = getResourceInput "big-list-of-naughty-strings"

    /// Gets a wide sample of malicious input for windows targets
    [<CompiledName("Windows")>]
    let windows = getResourceInput "Windows-Attacks.fuzzdb"

    /// Gets a wide sample of malicious input for unix-like targets
    [<CompiledName("Unix")>]
    let unix = getResourceInput "Unix-Attacks.fuzzdb"

    /// Gets a wide sample of malicious input for SQL targets
    [<CompiledName("Sql")>]
    let sql = getResourceInput "sql"

    /// Gets a directory traversal path for a given file name. (ex. 'file.txt' becomes '../../file.txt')
    /// 847 attack vectors, 8 levels of recursion (Unix-like, Windows)
    [<CompiledName("DirTraversal")>]
    let dirTraversal fileName =
        getResourceInput "dir.traversal.fuzz"
        |> Seq.map (fun r -> r.Replace ("{FILE}", fileName))

    /// Fuzz the case of a given string. (ex. '.php' becomes '.PhP').
    [<CompiledName("Case")>]
    let case (str : string) =
        if isNull str then nullArg "str"
        let lowerOrUpper (fuzz, input) =
            if fuzz = '0' then Char.ToLower input
            else Char.ToUpper input

        let changeCaseByFuzz (fuzz : string, input : string) =
            let inputs = input.ToCharArray()
            let fuzz = fuzz.PadLeft(input.Length, '0').ToCharArray()
            Array.zip fuzz inputs
            |> Array.map lowerOrUpper
            |> fun xs -> String.Join (String.Empty, xs)

        let possibilities = float str.Length ** 2. |> int
        [| 0..possibilities-1 |]
        |> Array.map (fun i -> (Convert.ToString (i, 2), str) |> changeCaseByFuzz)

    /// Fuzz the encoding of the given string and its current encoding.
    [<CompiledName("Encoding")>]
    let encodingFrom (current : Encoding) (str : string) =
        let bytes = current.GetBytes (str)
        let encodings = Encoding.GetEncodings ()
        Encoding.GetEncodings()
        |> Array.map (fun e -> e.GetEncoding ())
        |> Array.zip (Array.replicate encodings.Length current)
        |> Array.map (fun (src, dest) -> dest.GetString(Encoding.Convert(src, dest, bytes)))

    /// Fuzz the encoding of a given string considering the default UTF-8 as current encoding.
    [<CompiledName("Encoding")>]
    let encoding str = encodingFrom Encoding.UTF8 str

/// Extra operations on the sequence type.
module Seq =
    /// Injects a series of inputs into a series of setter functions with a creator function to create the target instance.
    let inject targets creator fuzz =
        seq { for t in targets do
              for x in fuzz do
              yield t x (creator()) }

[<Extension>]
type InjectExtensions =
    /// Injects a series of inputs into a series of setter functions with a creator function to create the target instance.
    [<Extension>]
    static member InjectInto 
        ( fuzz : IEnumerable<'T>, 
          creator : Func<'TResult>, 
          [<ParamArray>] targets : Func<'TResult, 'T, 'TResult> [] ) =
      if isNull fuzz then nullArg "fuzz"
      if isNull creator then nullArg "creator"
      if isNull targets then nullArg "targets"
      if Seq.exists isNull targets then invalidArg "targets" "One or more target functions is 'null'"
      Seq.inject (Seq.map (fun (f : Func<_, _, _>) -> fun t x -> f.Invoke (t, x)) targets) creator.Invoke fuzz
