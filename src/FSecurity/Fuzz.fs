namespace FSecurity

open System
open System.Collections.Generic
open System.Runtime.CompilerServices
open System.Net.Http
open System.Text
open System.IO

type internal FuzzType internal () = class end

/// Representation of a size indication (MB, GB, ...)
type Metric = MB | GB with 
  static member unit metric =
    match metric with MB -> 1048576L | GB -> 1073741824L

/// Module that holds the available fuzzing collections.
module Fuzz =
  let private getResourceInput x = 
    use str = typeof<FuzzType>.Assembly.GetManifestResourceStream(sprintf "FSecurity.Resources.%s.txt" x)
    let rdr = new System.IO.StreamReader(str)
    rdr.ReadToEnd().Split([|System.Environment.NewLine|], System.StringSplitOptions.RemoveEmptyEntries)
    |> Seq.filter (fun x -> not <| x.StartsWith "#")

  /// Gets the all the numbers from a minimum to a maximum value inclusive.
  [<CompiledName("Numbers")>]
  let numbers min max = seq {
    for x in min..max do yield string x }

  /// Gets the alhpabethical charaters of a-z and A-Z.
  [<CompiledName("Alphabet")>]
  let alphabet = seq {
    for x in 'a'..'z' do yield string x
    for y in 'A'..'Z' do yield string y }

  /// Gets the alphanumerical series of a-z, A-Z, and 0-9.
  [<CompiledName("Alphanum")>]
  let alphanum = seq {
    yield! alphabet
    yield! numbers 0 9 }

  /// Gets a series of special charaters (ex. '!', '%', ...)
  [<CompiledName("Specials")>]
  let specials =
    Seq.ofList [ "!"; "\"";  "#"; "$"; "%"; "&"; "'"; "("; ")"; "*"; "+";  ","; "-"; "."; "/"; ":"; ";"; "<"; "="; ">"; "?"; "@"; "["; "\\"; "]"; "^"; "_"; "`"; "{"; "|"; "}"; "~" ]

  /// Gets the alphanumerical series of a-b, A-Z, 0-9, and all special charaters.
  [<CompiledName("AlphanumSpecial")>]
  let alphanum_special =
    Seq.append alphanum specials

  /// Gets HTTP headers that expose information that can be used for fingerprinting.
  [<CompiledName("HttpLeakageHeaders")>]
  let httpLeakageHeaders = [| "Server"; "X-Powered-By"; "X-AspNet-Version"; "X-AspNetMvc-Version" |]

  /// Gets HTTP headers that protect against some browser injection security issues.
  [<CompiledName("HttpProtectHeaders")>]
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

  let private rnd = Random(Guid.NewGuid().GetHashCode())
  let private random xs = Seq.item (rnd.Next (0, Seq.length xs)) xs

  /// Fuzz by making a sized fuzzed input value from a list of possible fuzzed values.
  /// Ex. `Fuzz.sized 3 Metric.MB Fuzz.alphabet`
  [<CompiledName("Sized")>]
  let sized value metric values =
    let size = Metric.unit metric
    use str = new MemoryStream ()
    let des = int64 value * size
    while str.Position < des do
      let x = random values
      let b = Encoding.UTF8.GetBytes (x : string)
      str.Write (b, 0, b.Length)
    str.ToArray () |> Encoding.UTF8.GetString

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
      ( fuzz : IEnumerable<'TInjector>, 
        creator : Func<'T>, 
        [<ParamArray>] targets : Func<'TInjector, 'T, 'TResult> [] ) =
    if isNull fuzz then nullArg "fuzz"
    if isNull creator then nullArg "creator"
    if isNull targets then nullArg "targets"
    if Seq.exists isNull targets then invalidArg "targets" "One or more target functions is 'null'"
    let targets = Seq.map (fun (f : Func<_, _, _>) -> fun t x -> f.Invoke (t, x)) targets
    Seq.inject targets creator.Invoke fuzz
