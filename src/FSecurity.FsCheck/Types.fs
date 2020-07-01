namespace FSecurity

/// Represents a fuzzed XML element or attribute value with malicious input.
type XmlElemAttrFuzz = XmlElemAttrFuzz of string with
    member x.Get = match x with XmlElemAttrFuzz r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (XmlElemAttrFuzz x) = x

/// Represetents a fuzzed XML document with malicious inputs.
type XmlDocFuzz = XmlDocFuzz of string with
    member x.Get = match x with XmlDocFuzz r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (XmlDocFuzz x) = x

/// Represents a fuzzed version of an external entity processing XML injection malicious input.
type XmlXxeFuzz = XmlXxeFuzz of string with
    member x.Get = match x with XmlXxeFuzz r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (XmlXxeFuzz x) = x

/// Represents a JSON value with fuzzed malicious inputs.
type JsonFuzz = JsonFuzz of string with
    member x.Get = match x with JsonFuzz r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (JsonFuzz x) = x

/// Represents a naugthy string containging all sorts of unexpected charaters.
type Naughty = Naughty of string with
    member x.Get = match x with Naughty r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (Naughty x) = x

/// Represents a malicious input of a Windows target.
type WindowsFuzz = WindowsFuzz of string with
    member x.Get = match x with WindowsFuzz r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (WindowsFuzz x) = x

/// Represents a malicious input of an Unix target.
type UnixFuzz = UnixFuzz of string with
    member x.Get = match x with UnixFuzz r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (UnixFuzz x) = x

/// Represents a malicious input for a SQL target.
type SqlFuzz = SqlFuzz of string with
    member x.Get = match x with SqlFuzz r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (SqlFuzz x) = x

/// Represents a content-type.
type ContentType = ContentType of string with
    member x.Get = match x with ContentType r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (ContentType x) = x

/// Represents an string with only charaters in the alphabet.
type Alphabetical = Alphabethical of string with
    member x.Get = match x with Alphabethical r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (Alphabethical x) = x

/// Represents an alphanumerical value.
type Alphanum = Alphanum of string with
    member x.Get = match x with Alphanum r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (Alphanum x) = x

/// Represents an alphanumerical value and special charaters.
type AlphanumExtra = AlphanumExtra of string with
    member x.Get = match x with AlphanumExtra r -> r
    override x.ToString() = x.Get.ToString()
    static member op_Explicit (AlphanumExtra x) = x

open FsCheck

[<AbstractClass; Sealed>]
type Registrations internal () =
    static member XmlElemAttrFuzz () = FSec.xmlElemAttr |> Gen.map XmlElemAttrFuzz |> Arb.fromGen
    static member XmlDocFuzz () = FSec.xmlDoc |> Gen.map XmlDocFuzz |> Arb.fromGen
    static member XmlXxeFuzz () = FSec.xmlXxe |> Gen.map XmlXxeFuzz |> Arb.fromGen
    static member JsonFuzz () = FSec.json |> Gen.map JsonFuzz |> Arb.fromGen
    static member Naughty () = FSec.naugthy |> Gen.map Naughty |> Arb.fromGen
    static member WindowsFuzz () = FSec.windows |> Gen.map WindowsFuzz |> Arb.fromGen
    static member UnixFuzz () = FSec.unix |> Gen.map UnixFuzz |> Arb.fromGen
    static member SqlFuzz () = FSec.sqlInject |> Gen.map SqlFuzz |> Arb.fromGen
    static member ContentType () = FSec.contentType |> Gen.map ContentType |> Arb.fromGen
    static member HttpMethod () = FSec.httpMethod |> Arb.fromGen
    static member Alphabethical () = FSec.alphabet |> Arb.fromGen
    static member Alphanum  () = FSec.alphanum |> Gen.map Alphanum |> Arb.fromGen
    static member AlphanumExtra () = FSec.alphanum_special |> Gen.map AlphanumExtra |> Arb.fromGen

module internal Register =
    do Arb.register<Registrations> () |> ignore