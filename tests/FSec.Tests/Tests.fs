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

[<Property>]
let ``URL bogus query parameter generation`` () =
    stubQueryParams
    |> FSec.urlBogus "http://example.com"
    |> Arb.fromGen
    |> Prop.forAll <| fun url ->
        url.Split '&'
        |> (not << Array.isEmpty)

[<Property>]
let ``File creation`` () =
    Environment.CurrentDirectory
    |> DirectoryInfo
    |> FSec.fileOfSize 1 MB
    |> fun file ->
        file.Length =! int64 (1024 * 1024)

[<Property(MaxTest=1)>]
let ``Zip Bomb`` () =
    Environment.CurrentDirectory
    |> DirectoryInfo
    |> FSec.fileOfSize 1 MB
    |> FSec.zipBombDepthWidth 1 2
    |> fun path ->
        use zip = new ZipFile (path)
        [ for z in zip -> z :?> ZipEntry ]
        |> List.forall (fun e -> e.Name.EndsWith ".zip") 
        .&. (zip.Count =! 2L)