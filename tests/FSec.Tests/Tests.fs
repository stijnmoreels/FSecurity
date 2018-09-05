module FSec.Tests

open System
open System.IO
open System.Threading
open System.Xml
open System.Xml.Schema
open FsCheck
open FsCheck.Xunit
open Swensen.Unquote
open FSecurity
open ICSharpCode.SharpZipLib.Zip
open System.Text.RegularExpressions
open System.Net

[<Property>]
let ``XPath input injection`` () =
    FSec.xpathInject
    |> Gen.two
    |> Gen.zip (Gen.elements 
        [ Vulnerable, XPath.vulnerable
          Prevented, XPath.prevented ])
    |> Arb.fromGen
    |> Prop.forAll <| fun ((exp, sut), (user, pass)) -> 
        exp =! sut user pass

[<Property>]
let ``XSS input injection`` () =
    FSec.xssInject
    |> Gen.zip (Gen.elements 
        [ true, HTML.vulnerable
          false, HTML.prevented ])
    |> Arb.fromGen
    |> Prop.forAll <| fun ((exp, sut), x) ->
        sut x |> Option.exists (fun y -> y.Contains x)
              |> (=!) exp

[<Property>]
let ``SQL input injection`` () =
    FSec.sqlInject
    |> Gen.zip (Gen.elements
        [ Vulnerable, SQL.vulnerable
          Prevented, SQL.prevented ])
    |> Arb.fromGen
    |> Prop.forAll <| fun ((exp, sut), x) ->
        exp =! sut x

[<Property(MaxTest=1)>]
let ``XML bomb injection timeout`` () = 
    FSec.xmlBomb
    |> Arb.fromGen
    |> Prop.forAll <| fun x ->
        let ss = XmlReaderSettings () in
            ss.DtdProcessing <- DtdProcessing.Parse;
            ss.ValidationFlags <- XmlSchemaValidationFlags.None;
            ss.ValidationType <- ValidationType.None;
            ss.Async <- true
        use r = XmlReader.Create (new StringReader (x), ss)
        use cts = new CancellationTokenSource () in
            cts.CancelAfter 50

        try let a = r.ReadAsync () |> Async.AwaitTask
            while Async.RunSynchronously (a, cancellationToken=cts.Token) do ()
            false
        with | :? OperationCanceledException -> true

[<Property>]
let ``XML malicious generation`` () =
    FSec.xmlMalicious
    |> Arb.fromGen
    |> Prop.forAll <| fun xml ->
        let doc = XmlDocument () in
            doc.LoadXml xml
     
[<Property>]
let ``XML malicious injection`` () =
    let xpath = "/Person/Age"
    let doc = XmlDocument ()
    doc.LoadXml "<Person><Age/></Person>"

    [ xpath, Arb.generate<PositiveInt> |> Gen.map (fun p -> p.Get) ]
    |> Map.ofList
    |> FSec.xmlMaliciousInject doc
    |> Arb.fromGen
    |> Prop.forAll <| fun mal ->
        mal.SelectSingleNode xpath
        |> fun n -> n <> null .&. (int n.InnerText > 0)

let stubQueryParams =
    [ "category", Arb.generate<string>
      "style", Arb.generate<string>
      "size", Arb.generate<string> ]
    |> Map.ofList

[<Property>]
let ``URL tampered generation`` () =
    stubQueryParams
    |> FSec.urlTampered "http://example.com"
    |> Arb.fromGen
    |> Prop.forAll <| fun url ->
        url.Split '&' 
        |> Array.length
        |> (<=!) 3;

module String = let contains x (s : string) = s.Contains x
module Regex = let isMatch p x = Regex.IsMatch (x, p)

[<Property>]
let ``URL bogus query parameter generation`` () =
    stubQueryParams
    |> FSec.urlBogus "http://example.com"
    |> Arb.fromGen
    |> Prop.forAll <| fun url ->
        let qs = url.Split '&'
        [ "category"; "style"; "size" ] 
        |> List.forall (fun x ->
            Array.exists (String.contains x) qs)
        .&. (qs.Length > 3)

[<Property>]
let ``creates file of 1 MB`` () =
    Environment.CurrentDirectory
    |> DirectoryInfo
    |> FSec.fileOfSize 1 MB
    |> fun file ->
        file.Length =! (int64 (1024 * 1024) + 1L)

let regexTraversal = "^[(..|%252e%252e)|(\/|%2f)|(\\|%5c)]+"

[<Property>]
let ``creates path dir traversal`` () =
    FSec.pathDirTraversal
    |> Arb.fromGen
    |> Prop.forAll <| 
        Regex.isMatch regexTraversal
    
let (|Guid|) (g : Guid) = g.ToString()

[<Property>]
let ``creates path fixed file traversal`` (Guid name) =
    FSec.pathFixedFileTraversal [name]
    |> Arb.fromGen
    |> Prop.forAll <| fun x ->
        Regex.isMatch regexTraversal x
        .&. String.contains name x

[<Property>]
let ``create path random file traversal`` () =
    FSec.pathFileTraversal ".txt"
    |> Arb.fromGen
    |> Prop.forAll <|
        Regex.isMatch (regexTraversal + "(.+).txt$")

[<Property(MaxTest=1)>]
let ``can create zip bomb`` () =
    Environment.CurrentDirectory
    |> DirectoryInfo
    |> FSec.fileOfSize 1 MB
    |> FSec.zipBombDepthWidth 1 2
    |> fun path ->
        use zip = new ZipFile (path)
        [ for z in zip -> z :?> ZipEntry ]
        |> List.forall (fun e -> e.Name.EndsWith ".zip") 
        .&. (zip.Count =! 2L)

[<Property>]
let ``week passwords will be found in dictionary attack`` () =
    [ "qwerty"; "password" ]
    |> Gen.elements
    |> Arb.fromGen
    |> Prop.forAll <| fun x -> 
        Seq.contains x FSec.dicAttackSeq
    