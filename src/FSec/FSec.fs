namespace FSecurity

/// Module that holds the security testing functionality
module FSec = 
    open FsCheck
    open System.IO
  
    /// XPath input generator that provides malformed XPath inputs that can be used to discover XPath vulnerabilities.
    /// XPath is a "simple" language to locate information in an XML document. 
    /// Similar to SQL Injection, XPath Injection attacks occur when an application uses user-supplied information 
    /// to construct an XPath query for XML data. By sending intentionally malformed information into the application, 
    /// an attacker can find out how the XML data is structured, or access data that he may not normally have access to.
    /// (more info: https://www.owasp.org/index.php/XPATH_Injection)
    ///
    /// _Severity_: Critical
    /// _Vulnerability Indicators_: incorrect/invalid syntax, syntax error, runtime errors, XPathException, System.Xml.XPath 
    [<CompiledName("XPathInject")>]
    let xpathInject =
        Gen.elements 
            [ "1' or 1=1"
              "a%' or '1' = '1"
              "' or '1' = '1"
              "'a or 1=1 or 'a'='a" ]

    /// XML Bomb input generator: An XML bomb is a message composed and sent with the intent of overloading an XML parser (typically HTTP server). 
    /// It is block of XML that is both well-formed and valid according to the rules of an XML schema. 
    /// It is a type of XML Denial of Service (DoS) attack. (more info: https://en.wikipedia.org/wiki/Billion_laughs)
    ///
    /// _Severity_: Critical
    /// _Vulnerability Indicators_: timeoutv
    [<CompiledName("XmlBomb")>]
    let xmlBomb =
        Gen.elements
            [ """<?xml version="1.0"?>
            <!DOCTYPE lolz [
                <!ENTITY lol "lol">
                <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
                <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
                <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
                <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
                <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
                <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
                <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
                <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
            ]>
            <lolz>&lol9;</lolz>""" ]

    /// XSS (Cross Site Scripting) input generator that provides malformed inputs that can be used to discover XSS vulnerabilities.
    /// Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign 
    /// and trusted web sites. (more info: https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))
    ///
    /// _Severity_: Critical
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
    ///
    /// _Severity_: Critical
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

    type Metric =
        | MB = 1048576
        | GB = 1073741824

    /// Creates a file for a given size stored at a given directory.
    /// ## Parameters
    /// - `dir` - Location of where the file should be stored
    /// - `x` - Value to define the file size (in MB or GB)
    /// - `m` - Metric to define the Unit of the file size
    let fileOfSize (dir : DirectoryInfo) x (m : Metric) =
        let path = Path.Combine (dir.FullName, string (System.Guid.NewGuid()) + ".test")
        use fs = File.Create path
        fs.Seek (x * int64 m, SeekOrigin.Begin) |> ignore
        fs.WriteByte 0uy
        path

    /// Malicious XML generator: generates a XML structure with a specified depth and tag length to detect failures in naive XML parsing implementations.
    /// ## Parameters
    /// - `depth` - Defines the depth of the XML document
    /// - `tagLen` - Defines the length of the tag names
    let xmlMaliciousDepthTagLen depth tagLen =
        let randomAttrOfLength l =
            Gen.elements ['a'..'z']
            |> Gen.map (string)
            |> Gen.zip Arb.generate<int>
            |> Gen.map (fun (x, y) -> sprintf "%s=\"%i\"" y x)
            |> Gen.listOfLength l
            |> Gen.map (List.distinctBy (fun s ->
                let loc = s.IndexOf '='
                s.Substring (0, loc)) 
                >> List.reduce (sprintf "%s %s"))
            |> Gen.listOfLength depth

        let randomTag = 
            Gen.elements [ 'a'..'z' ]
            |> Gen.listOfLength tagLen
            |> Gen.map (List.map string >> List.reduce (+))
        
        randomTag
        |> Gen.listOfLength depth
        |> Gen.zip (Gen.choose (100, 1000) >>= randomAttrOfLength)
        |> Gen.map (fun (attrs, xs) ->
            let os = attrs |> List.map2 (sprintf "<%s %s>") xs
            let cs = xs |> List.rev |> List.map (sprintf "</%s>")
            [ "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" ] 
            @ os @ cs
            |> List.reduce (+))

    /// Malicious XML generator: generates a XML structure with a depth of 1-100, a tag length of 100-1000 and a attribute count of 100-100.
    /// With this generator you can detect failures in naive XML parsers.
    [<CompiledName("XmlMalicious")>]
    let xmlMalicious = 
        Gen.choose (100, 1000) 
        |> Gen.zip (Gen.choose (1, 100))
        >>= fun (tagLen, depth) -> xmlMaliciousDepthTagLen tagLen depth

    /// Generates an url with hidden specified query parameters: admin=true, debug=true.
    /// ## Parameters
    /// - `baseUrl` - The base URL to add the generated query parameters
    let urlHiddenAdmin baseUrl =
        Gen.elements [ "admin=true"; "debug=true" ]
        |> Gen.map (sprintf """%s?%s""" baseUrl)

    /// Generates an url with a specified number of query parameters each with its own generator.
    /// ## Parameters
    /// - `baseUrl` - The base URL to add the generated query parameters
    /// - `args` - Map containing a query parameter names and their generator for its value
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
    let urlInject baseUrl args =
        args
        |> List.map (fun a -> a, xssInject)
        |> Map.ofList
        |> urlTampered baseUrl

    /// Generates an url with an additional "bogus" query parameters added to the specified base url.
    /// ## Parameters
    /// - `baseUrl` - The base URL to add the generated query parsameters
    /// - `args` - Map containing a query parameter names and their generator for its value
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