namespace FSecurity

open System
open System.Collections.ObjectModel
open System.Linq
open System.Net.Http
open System.Runtime.ExceptionServices
open System.Security.Cryptography.X509Certificates
open System.Text
open System.Text.RegularExpressions
open System.Threading
open System.Runtime.CompilerServices
open System.Threading.Tasks
open System.Runtime.InteropServices

/// Indicate the severity of a security vulnerability.
type Severity = Info | Medium | High

[<Extension>]
type HttpResponseMessageExtensions () =
  [<Extension>]
  static member readAsStringAsync (content : HttpContent) = content.ReadAsStringAsync() |> Async.AwaitTask
  [<Extension>]
  static member internal FormatAsString (res : HttpResponseMessage) = 
    sprintf "%A %A -> %A" res.RequestMessage.Method res.RequestMessage.RequestUri res.StatusCode 

/// Represents a security vulnerability.
type Vulnerability =
  { /// Gets a short description of the vulnerability.
    Summary : string
    /// Gets a more thorough explination of the vulnerability.
    Description : string
    /// Gets the content of the response for which a vulnerability is signaled.
    ResponseContent : string
    /// Gets the payloads for which the vulnerability was triggered.
    Payloads : string seq
    /// Gets the severity of the vulnerability.
    Severity : Severity } with
  /// Creates a vulnerability with all possible info.
  static member Create (desc, summary, response, severity, payloads) =
    { Description = desc; Summary = summary; ResponseContent = response; Severity = severity; Payloads = payloads }
  /// Creates a vulnerability with only a description.
  static member Create (desc) = Vulnerability.Create (desc, "", "", Medium, [])
  /// Creates a vulnerability but discards the response content.
  /// A summary from the request is created.
  [<CompiledName("CreateWithoutResponseContent")>]
  static member withoutRespContent (res : HttpResponseMessage) desc severity payloads =
    { Description = desc
      Summary = res.FormatAsString ()
      ResponseContent = String.Empty
      Severity = severity
      Payloads = payloads }
  /// Creates a vulnerability by reading the response content.
  /// A summary from the request is created.
  static member fromRespContent (res : HttpResponseMessage) desc severity payloads = async {
    let! content = res.Content.ReadAsStringAsync() |> Async.AwaitTask
    return { Description = desc
             Summary = res.FormatAsString ()
             ResponseContent = content
             Severity = severity
             Payloads = payloads } }
  /// Adds the response content to the vulnerability.
  member this.WithResponseContentAsync (res : HttpResponseMessage) =
    async { let! content = res.Content.ReadAsStringAsync() |> Async.AwaitTask
            return { this with ResponseContent = content } } |> Async.StartAsTask
  /// Creates a vulnerability by reading the response content.
  /// A summary from the request is created.
  static member CreateFromResponseContentAsync response description severity payloads =
    Vulnerability.fromRespContent response description severity payloads |> Async.StartAsTask
  /// Creates a vulnerability with a Info severity.
  static member Info (desc, response, [<Optional>] payloads) =
    let payloads = Option.ofObj payloads |> Option.defaultValue Seq.empty
    Vulnerability.withoutRespContent response desc Info payloads
  /// Creates a vulnerability with a Medium severity.
  static member Medium (desc, response, [<Optional>] payloads) =
    let payloads = Option.ofObj payloads |> Option.defaultValue Seq.empty
    Vulnerability.withoutRespContent response desc Medium payloads
  /// Creates a vulnerability with a High severity.
  static member High (desc, response, [<Optional>] payloads) =
    Vulnerability.withoutRespContent response desc High payloads
  /// Creates a vulnerability (Medium) with a short XSS description.
  static member Xss (response, [<Optional>] payloads) =
    Vulnerability.Medium ("Possible XSS vulnerability", response, payloads)
  /// Creates a vulnerability (High) with a short SQL description.
  static member Sql (response, [<Optional>] payloads) =
    Vulnerability.High ("Possible SQL vulnerability", response, payloads)
  /// Creates a vulnerability (Info) with a short rate-limit description.
  static member Dos (response, [<Optional>] payloads) =
    Vulnerability.Medium ("Possible DOS vulnerability", response, payloads)
  /// Creates a vulnerability (High) with a short privilege escalation description.
  static member PrivilegeEscalation (response, [<Optional>] payloads) =
    Vulnerability.High ("Possible Privilege Escalation vulnerability", response, payloads)
  /// Creates a vulnerability (Medium) with a short insecure direct object reference description.
  static member InsecureDirectObjectReference (response, [<Optional>] payloads) =
    Vulnerability.Medium ("Possible Insecure Direct Object Reference vulnerability", response, payloads)
  /// Creates a vulnerability (Medium) with a short open redirection description.
  static member OpenRedirect (response, [<Optional>] payloads) =
    Vulnerability.Medium ("Possible Open Redirection vulnerability", response, payloads)
  /// Creates a vulnerability (Medium) with a short Cross-site request forgery description.
  static member CrossSiteRequestForgery (response, [<Optional>] payloads) =
    Vulnerability.Medium ("Possible Cross-site request forgery vulnerability", response, payloads)
  /// Creates a vulnerability (Info) with a info leakakge description.
  static member InfoLeakakge (response, [<Optional>] payloads) =
    Vulnerability.Info ("Possible leakage of information", response, payloads)

type Vuln = Vulnerability

/// Operations on the vulnerability type.
module Vuln =
  /// Creates a vulnerability with only a description.
  let create desc = Vuln.Create desc
  /// Sets the summary of the vulnerability.
  let summary txt vuln = { vuln with Summary = txt }
  /// Sets the response content of the vulnerability.
  let response txt vuln = { vuln with ResponseContent = txt }
  /// Sets the payloads that triggered this vulnerability.
  let payloads ps vuln = { vuln with Payloads = ps }
  /// Sets the severity of this vulnerability.
  let severity s vuln = { vuln with Severity = s }
  /// Creates a vulnerability with a Info severity.
  let info desc response payloads = Vuln.Info (desc, response, payloads)
  /// Creates a vulnerability with a Medium severity.
  let medium desc response payloads = Vuln.Medium (desc, response, payloads)
  /// Creates a vulnerability with a High severity.
  let high desc response payloads = Vuln.High (desc, response, payloads)
  /// Creates a vulnerability (Medium) with a short XSS description.
  let xss response payloads = Vuln.Xss (response, payloads)
  /// Creates a vulnerability (High) with a short SQL description.
  let sql response payloads = Vuln.Sql (response, payloads)
  /// Creates a vulnerability (Info) with a short rate-limit description.
  let dos response payloads = Vuln.Dos (response, payloads)
  /// Creates a vulnerability (High) with a short privilege escalation description.
  let privilEscal response payloads = Vuln.PrivilegeEscalation (response, payloads)
  /// Creates a vulnerability (Medium) with a short insecure direct object reference description.
  let idor response payloads = Vuln.InsecureDirectObjectReference (response, payloads)
  /// Creates a vulnerability (Medium) with a short open redirection description.
  let openRedirect response payloads = Vuln.OpenRedirect (response, payloads)
  /// Creates a vulnerability (Medium) with a short Cross-site request forgery description.
  let csrf response payloads = Vuln.CrossSiteRequestForgery (response, payloads)
  /// Creates a vulnerability (Info) with a info leakakge description.
  let leakage response payloads = Vuln.InfoLeakakge (response, payloads)

/// Extensions on the vulnerability type for a dev-friendly C#-context.
[<Extension>]
type VulnerabilityExtensions () =
  /// Sets the summary of the vulnerability.
  [<Extension>]
  static member WithSummary (vuln, txt) = 
    if isNull txt then nullArg "txt"
    Vuln.summary txt vuln
  /// Sets the response content of the vulnerability.
  [<Extension>]
  static member WithResponseContent (vuln, txt) = 
    if isNull txt then nullArg "txt"
    Vuln.response txt vuln
  /// Sets the payloads that triggered this vulnerability.
  [<Extension>]
  static member WithPayloads (vuln, payloads) = 
    if isNull payloads then nullArg "payloads"
    Vuln.payloads payloads vuln
  /// Sets the severity of this vulnerability.
  [<Extension>]
  static member WithSeverity (vuln, severity) = Vuln.severity severity vuln

[<AutoOpen>]
module HttpMethods =
  let GET = HttpMethod.Get
  let POST = HttpMethod.Post
  let PUT = HttpMethod.Put
  let DELETE = HttpMethod.Delete
  let HEAD = HttpMethod.Head
  let OPTIONS = HttpMethod.Options
  let TRACE = HttpMethod.Trace

/// Represents a HTTP request body.
type Body =
  internal 
    { /// Gets the raw content of the request.
      Content : string
      /// Gets the type of the request content.
      ContentType : string
      /// Gets the replacement functions to inject payloads into the request content.
      Replacements : (string -> string) list }

/// Represents a HTTP request.
type Request =
  internal
    { /// Gets the url from which a HTTP request will be created.
      BaseUrl : string
      /// Gets the routes to add after the base URL of the request.
      Routes : string list
      /// Gets the query string parameters to add to the request.
      Params : (string * string) list
      /// Gets the HTTP method of the request.
      Method : HttpMethod
      /// Gets the HTTP headers of the request.
      Headers : (string * string) list
      /// Gets the possible request body.
      Body : Body option
      /// Indicate how many request should be send maximum concurrently.
      MaxConcurrentRequests : int
      /// Gets the possible HTTPS client certificate of the request.
      ClientCertificate : X509Certificate option } with
        /// Creates a HTTP request with a method and base URL.
        static member Endpoint (method, baseUrl) =
          { BaseUrl = baseUrl; Routes = []; Params = []; Headers = []; Method = method; Body = None; ClientCertificate = None; MaxConcurrentRequests = 10 }
        /// Creates a HTTP request message from this request model
        member this.ToHttpRequestMessage () =
          let query = String.Join ("&", List.map (fun (h, v) -> sprintf "%s=%s" h v) this.Params)
          let query = if String.IsNullOrWhiteSpace query then query else "?" + query
          let route = String.Join ("/", this.Routes)
          let url = sprintf "%s/%s%s" (this.BaseUrl.TrimEnd '/') route query
          let req = new HttpRequestMessage(this.Method, url)
          for (headerName, headerValue) in this.Headers do
            req.Headers.Add (headerName, headerValue)

          Option.iter (fun b -> 
            let content = List.fold (fun acc f -> f acc) b.Content b.Replacements
            req.Content <- new StringContent(content, Encoding.UTF8, b.ContentType)) this.Body
          req
        /// Creates a HTTP request message from this request model
        static member op_Implicit (this : Request) = this.ToHttpRequestMessage ()

/// Represents a HTTP response.
type Response = HttpResponseMessage

[<AutoOpen>]
module WebPatterns =
  let (|Request|) (r : Request) = r
  let (|Response|) (r : HttpResponseMessage) = r

/// Type abbrivation for a payload.
type Payload = string

/// Represents a API scan.
type Scan =
  { /// Gets a series of injector functions that together forms the attack surface of the HTTP request.
    AttackSurface : (Payload -> Request -> Request) list
    /// Gets a series of payloads to inject into the request; together with a maximum value indicator of how many payloads to use in a test scan.
    Payloads : Payload seq * int
    /// Gets a series of validation functions to determine wheter a response for a set of payloads is considered vulnerable for a security issue.
    Validation : (Payload list -> Response -> Async<Vulnerability array>) list }

/// Operations for the request type.
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Req =
  /// Creates a HTTP request with a method and base URL.
  let endpoint method baseUrl = Request.Endpoint (method, baseUrl)

  /// Adds routing paths to the request.
  let routes paths req = { req with Routes = req.Routes @ paths }
  
  /// Adds a single route path to the request.
  let route path req = routes [path] req

  /// Adds query string parameters to the request.
  let parameters parameters req = { req with Params = req.Params @ parameters }
  
  /// Adds a single query string parameter to the request.
  let parameter name value req =
    { req with Params = (name, value) :: req.Params }

  /// Adds HTTP headers to the request.
  let headers headers req = { req with Headers = req.Headers @ headers }
  
  /// Adds a single HTTP header to the request.
  let header name value req = headers [name, value] req

  /// Sets the HTTPS client certificate to the request.
  let certificate cert req = { req with ClientCertificate = Some cert }

  /// Sets the HTTP method for the request.
  let method x req = { req with Method = x }

  /// Sets the request body with a content type.
  let body content contentType req = 
    { req with Body = Some { Content = content; ContentType = contentType; Replacements = [] } }
  
  /// Replace all matching occurrences in the request content with a value.
  let body_regex pattern (value : string) req : Request =
    { req with Body = Option.map (fun b -> { b with Replacements = (fun content -> Regex.Replace(content, pattern, value)) :: b.Replacements }) req.Body }
  
  /// Replaces all text between a specified indicator (ex. '#to-be-replaced#') with a value.
  /// Remark that this uses a regular expressions so valid regex charaters should be escaped.
  let body_between varIndicator value req : Request =
    body_regex (sprintf "%s.+%s" varIndicator varIndicator) value req
  
  /// Replaces the content type of the request body.
  let contentType value req : Request =
    { req with Body = Option.map (fun b -> { b with ContentType = value }) req.Body }
    
/// Adds extensions for a C#-friendly context.
[<Extension>]
type RequestExtensions () =
  /// Adds routing paths to the request.
  [<Extension>]
  static member WithRoutes (req, [<ParamArray>] paths : string array) = Req.routes (List.ofArray paths) req
  /// Adds a single route path to the request.
  [<Extension>]
  static member WithRoute (req, path) = Req.route path req
  /// Adds query string parameters to the request.
  [<Extension>]
  static member WithParameters (req, [<ParamArray>] parameters : (string * string) array) = Req.parameters (List.ofArray parameters) req
  /// Adds a single query string parameter to the request.
  [<Extension>]
  static member WithParameter (req, name, value) = Req.parameter name value req
  /// Adds HTTP headers to the request.
  [<Extension>]
  static member WithHeaders (req, [<ParamArray>] headers : (string * string) array) = Req.headers (List.ofArray headers) req
  /// Adds a single HTTP header to the request.
  [<Extension>]
  static member WithHeader (req, name, value) = Req.header name value req
  /// Sets the HTTPS client certificate to the request.
  [<Extension>]
  static member WithClientCertificate (req, certificate) = Req.certificate certificate req
  /// Sets the HTTP method for the request.
  [<Extension>]
  static member WithMethod (req, method) = Req.method method req
  /// Sets the request body with a content type.
  [<Extension>]
  static member WithBody (req, content, contentType) = Req.body content contentType req
  /// Replace all matching occurrences in the request content with a value.
  [<Extension>]
  static member WithBodyReplaceRegex (req, pattern, value) = Req.body_regex pattern value req
  /// Replaces all text between a specified indicator (ex. '#to-be-replaced#') with a value.
  /// Remark that this uses a regular expressions so valid regex charaters should be escaped.
  [<Extension>]
  static member WithBodyReplaceBetween (req, varIndicator, value) = Req.body_between varIndicator value req
  /// Replaces the content type of the request body.
  [<Extension>]
  static member WithContentType (req, contentType) = Req.contentType contentType req

// ----------------------------------------------------------------------------
// F# async extensions
// (c) Tomas Petricek, David Thomas 2012, Available under Apache 2.0 license.
// ----------------------------------------------------------------------------
module Async =
  /// common code for ParallelCatchWithThrottle and ParallelWithThrottle
  let private ParallelWithThrottleCustom tranformResult throttle computations = async {
    use semaphore = new SemaphoreSlim(throttle)
    let throttleAsync a = async {
      do! semaphore.WaitAsync() |> Async.AwaitTask
      let! result = Async.Catch a
      semaphore.Release() |> ignore
      return tranformResult result }
    
    return! computations
            |> Seq.map throttleAsync
            |> Async.Parallel }

  /// Creates an asynchronous computation that executes all the given asynchronous computations, initially queueing each as work items and using a fork/join pattern.
  /// This function doesn't throw exceptions, but instead returns an array of Choices.
  /// The paralelism is throttled, so that at most `throttle` computations run at one time.
  let ParallelCatchWithThrottle throttle computations =
    ParallelWithThrottleCustom id throttle computations

  /// Creates an asynchronous computation that executes all the given asynchronous computations, initially queueing each as work items and using a fork/join pattern.
  /// The paralelism is throttled, so that at most `throttle` computations run at one time.
  let ParallelWithThrottle throttle computations =
    let extractOrThrow = function
       | Choice1Of2 ok -> ok
       | Choice2Of2 ex -> ExceptionDispatchInfo.Capture(ex).Throw(); failwith "unreachable"
    ParallelWithThrottleCustom extractOrThrow throttle computations

/// Operations to scan an API endpoint.
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Api =
  /// Adds an asynchronous validation function that verifies several security issues.
  let shouldAllAsync verifier scan =
    { scan with Validation = verifier:: scan.Validation }
  
  /// Adds a validation function that verifies several security issues.
  let shouldAll verifier scan =
    shouldAllAsync (fun p r -> async { return verifier p r }) scan
  
  /// Adds an asynchronous validation function that verifies a security issue.
  let shouldAsync verifier scan =
    shouldAllAsync (fun p r -> async { 
      let! v = verifier p r
      return Option.toArray v }) scan
  
  /// Adds an asynchronous validation function that verifies for a security issue.
  let shouldAssertAsync verifier scan =
    shouldAsync (fun _ r -> async {
      try do! verifier r
          return None
      with ex -> return Some <| Vuln.create (sprintf "%s: %s" ex.Message ex.StackTrace) }) scan

  /// Adds a validation function that verifies a security issue.
  let should verifier scan =
    shouldAll (fun p r -> verifier p r |> Option.toArray) scan

  /// Adds a validation function that asserts for a security issue.
  let shouldAssert verifier scan =
    should (fun _ r -> try verifier r; None with ex -> Some <| Vuln.create (sprintf "%s: %s" ex.Message ex.StackTrace)) scan

  let private checkHttpLeakageHeaders payloads (Response r) =
    Fuzz.httpLeakageHeaders
    |> Seq.filter r.Headers.Contains
    |> Seq.map (fun h -> Vulnerability.withoutRespContent r (sprintf "Possible leakage of sensitive information from header '%s'" h) Info payloads)
    |> Array.ofSeq

  /// Sets the payloads together with how much payloads should be used for this test scan.
  let injectMax max payloads =
    { AttackSurface = []
      Payloads = payloads, max
      Validation = [] }
    |> shouldAll checkHttpLeakageHeaders

  /// Sets the payloads for this test scan.
  let inject payloads = injectMax 100 payloads

  /// Discards the payloads so the request itself is used to send.
  /// This also means nothing can be injected.
  let passThru = inject []

  /// Adds an injector function to the test scan to inject payloads into a HTTP request.
  let into injector scan =
    { scan with AttackSurface = injector :: scan.AttackSurface }

  let private sendRequest payloads clientCertificate createRequest = async {
    use handler = new System.Net.Http.HttpClientHandler ()
    Option.iter (fun cert -> handler.ClientCertificates.Add cert |> ignore) clientCertificate
    use client = new HttpClient (handler)
    use req = createRequest ()

    try 
      let! response = client.SendAsync (req) |> Async.AwaitTask
      return payloads, response
    with ex ->
      let res = new HttpResponseMessage(Net.HttpStatusCode.InternalServerError)
      res.Content <- new StringContent (ex.Message)
      res.RequestMessage <- req
      return payloads, res }
  
  let private disposeAll disposables =
    let exns = Collection<exn> ()
    for (x : #IDisposable) in disposables do
      try x.Dispose ()
      with ex -> exns.Add ex
    if exns.Count <> 0 
    then raise (AggregateException (exns.ToArray ()))

  let private rnd = Random(Guid.NewGuid().GetHashCode())
  module internal Seq = let internal rnd xs = Seq.item (rnd.Next (0, Seq.length xs)) xs

  let private injectRndPayloadsInReq scan req =
    let payloads, max = scan.Payloads
    let injectors = scan.AttackSurface
    Seq.init max <| fun _ ->
      Seq.fold (fun (ps, req) injector -> 
        let p = Seq.rnd payloads
        p::ps, injector p req) ([], req) injectors

  let private single clientCertificate createRequest scan = async {
    let! _, response = sendRequest [] clientCertificate createRequest
    try
      let! vulnerabilities =
        Seq.map (fun v -> v [] response) scan.Validation
        |> Async.Parallel
      return Array.concat vulnerabilities 
             |> Seq.distinctBy (fun v -> v.Description)
    finally disposeAll [response] }

  let private genMultiple (options : Request) createRequest scan = async {
    let! responsesForPayloads = 
       injectRndPayloadsInReq scan options
       |> fun xs -> Seq.map (fun (ps, r) -> sendRequest ps r.ClientCertificate createRequest) xs
       |> Async.ParallelWithThrottle options.MaxConcurrentRequests
    try
      let! vulnerabilities =
        responsesForPayloads
        |> Seq.collect (fun (ps, r) -> Seq.map (fun v -> v ps r) scan.Validation)
        |> Async.Parallel
        
      return Array.concat vulnerabilities 
             |> Seq.distinctBy (fun v -> v.Description)
    finally Array.map snd responsesForPayloads |> disposeAll }

  /// Runs a test scan for a given HTTP request, aggregates all found vulnerabilities for the test scan by validating the HTTP responses with the previously provided validation functions.
  let scanRequest request clientCertificate scan =
    single clientCertificate (fun () -> request) scan
  
  /// Runs a test scan for a given HTTP request by injecting a maximum amount of payloads into a series of HTTP requests
  /// using the previously specified injector functions for the request, 
  /// and aggregates all found vulnerabilities for the test scan by validating the HTTP responses with the previously provided validation functions.
  let scan (req : Request) scan =
    let createRequest () = req.ToHttpRequestMessage ()
    if Seq.isEmpty (fst scan.Payloads)
    then single req.ClientCertificate createRequest scan
    else genMultiple req createRequest scan

/// Adds extensions to the API scan type for a C#-friendly context.
[<Extension>]
type Api () =
  /// Sets the payloads together with how much payloads should be used for this test scan.
  static member InjectMax (max, payloads) = Api.injectMax max payloads
  /// Sets the payloads for this test scan.
  static member Inject payloads = Api.inject payloads
  /// Discards the payloads so the request itself is used to send.
  /// This also means nothing can be injected.
  static member PassThru = Api.passThru
  /// Adds an injector function to the test scan to inject payloads into a HTTP request.
  [<Extension>]
  static member Into (scan, injector : Func<_, _, _>) =
    if isNull injector then nullArg "injector"
    Api.into (fun p r -> injector.Invoke (p, r)) scan
  /// Adds an asynchronous validation function that verifies several security issues.
  [<Extension>]
  static member ShouldAllAsync (scan, verifier : Func<_, _, _>) =
    if isNull verifier then nullArg "verifier"
    Api.shouldAllAsync (fun ps (Response res) -> Async.AwaitTask <| verifier.Invoke (Array.ofList ps, res)) scan
  /// Adds a validation function that verifies several security issues.
  [<Extension>]
  static member ShouldAll (scan, verifier : Func<_, _, _>) =
    if isNull verifier then nullArg "verifier"
    Api.shouldAll (fun ps r -> verifier.Invoke (Array.ofList ps, r)) scan
  /// Adds an asynchronous validation function that verifies a security issue.
  [<Extension>]
  static member ShouldAsync (scan, verifier : Func<_, _, Task<ValueTuple<_, _>>>) =
    if isNull verifier then nullArg "verifier"
    Api.shouldAsync (fun ps (Response res) -> async {
      let! tuple = Async.AwaitTask <| verifier.Invoke (Array.ofList ps, res)
      let hasValue, value = tuple.ToTuple()
      return if hasValue then Some value else None }) scan
  /// Adds an asynchronous validation function that verifies a security issue.
  [<Extension>]
  static member ShouldAsnc (scan, verifier : Func<_, Task>) =
    if isNull verifier then nullArg "verifier"
    Api.shouldAssertAsync (fun (Response res) -> async {
      do! verifier.Invoke res |> Async.AwaitTask }) scan
  /// Adds an asynchronous validation function that verifies a security issue.
  [<Extension>]
  static member ShouldAsync (scan, verifier : Func<_, _, Task<_>>, vulnerability) =
    if isNull verifier then nullArg "verifier"
    Api.shouldAsync (fun ps (Response res) -> async {
      let! isVulnerable = Async.AwaitTask <| verifier.Invoke (Array.ofList ps, res)
      return if isVulnerable then Some vulnerability else None }) scan
  /// Adds a validation function that verifies a security issue.
  [<Extension>]
  static member Should (scan, verifier : Func<_, _, ValueTuple<_, _>>) =
    if isNull verifier then nullArg "verifier"
    Api.should (fun ps (Response res) ->
     let hasValue, value = (verifier.Invoke (Array.ofList ps, res)).ToTuple()
     if hasValue then Some value else None) scan
  /// Adds a validation function that verifies a security issue.
  [<Extension>]
  static member Should (scan, verifier : Func<_, _, _>, vulnerability) =
    if isNull verifier then nullArg "verifier"
    Api.should (fun ps (Response res) ->
     let isVulnerable = (verifier.Invoke (Array.ofList ps, res))
     if isVulnerable then Some vulnerability else None) scan
   /// Adds a validation function that verifies a security issue.
  [<Extension>]
  static member Should (scan, verifier : Func<_, ValueTuple<_, _>>) =
    if isNull verifier then nullArg "verifier"
    Api.should (fun _ (Response res) ->
     let hasValue, value = (verifier.Invoke res).ToTuple()
     if hasValue then Some value else None) scan
  /// Adds a validation function that verifies a security issue.
  [<Extension>]
  static member Should (scan, verifier : Func<_, _>, vulnerability) =
    if isNull verifier then nullArg "verifier"
    Api.should (fun _ (Response res) ->
     let isVulnerable = (verifier.Invoke res)
     if isVulnerable then Some vulnerability else None) scan
  /// Adds a validation function that asserts for a security issue.
  [<Extension>]
  static member Should (scan, verifier : Action<_>) =
    if isNull verifier then nullArg "verifier"
    Api.shouldAssert (fun (Response res) -> verifier.Invoke res) scan
  /// Runs a test scan for a given HTTP request by injecting a maximum amount of payloads into a series of HTTP requests
  /// using the previously specified injector functions for the request, 
  /// and aggregates all found vulnerabilities for the test scan by validating the HTTP responses with the previously provided validation functions.
  [<Extension>]
  static member ScanAsync (scan, req) = Api.scan req scan |> Async.StartAsTask
  /// Runs a test scan for a given HTTP request, aggregates all found vulnerabilities for the test scan by validating the HTTP responses with the previously provided validation functions.
  [<Extension>]
  static member ScanRequestAsync (scan, req, [<Optional>] clientCertificate) = 
    let clientCertificate = Option.ofObj clientCertificate
    Api.scanRequest req clientCertificate scan |> Async.StartAsTask

/// Operations on the response type.
module Res =
  /// Determines if a response content contains an expected string,
  /// and creates a vulnerability for it when it does.
  let contain expected (response : HttpResponseMessage) = async {
    let! content = response.Content.readAsStringAsync()
    return content.Contains (expected) }
  /// Determines if a response has one of the allowed status codes.
  let allow statusCodes (response : HttpResponseMessage) = Seq.contains response.StatusCode statusCodes
  /// Determines if a response header exists in the response.
  let hasHeader headerName (response : HttpResponseMessage) = response.Headers.Contains(headerName)
  /// Determines if a response header exists in the response.
  let hasHeaderValues headerName headerValues (response : HttpResponseMessage) =
    response.Headers.Contains(headerName)
    && response.Headers.GetValues(headerName).SequenceEqual(headerValues : seq<_>)
  /// Determines if a response header exists in the response.
  let hasHeaderValue headerName headerValue response =
    hasHeaderValues headerName (seq { yield headerValue }) response
  /// Gets the response headers in a Map<_, _> type.
  let headers (response : HttpResponseMessage) : Map<string, string seq> = 
    Seq.map (|KeyValue|) response.Headers |> Map.ofSeq

/// Extensions on the response type for a dev-friendly C#-context.
[<Extension>]
type ResponseExtensions () =
  /// Determines if a response content contains an expected string,
  /// and creates a vulnerability for it when it does.
  [<Extension>]
  static member ContainInBody (response, expected) =
    if isNull expected then nullArg "expected"
    Res.contain expected response |> Async.StartAsTask
  /// Determines if a response has one of the allowed status codes.
  [<Extension>]
  static member AllowStatusCodes (response, [<ParamArray>] statusCodes : _ array) =
    if isNull statusCodes then nullArg "statusCodes"
    Res.allow statusCodes response
  /// Determines if a response headers exists in the response.
  [<Extension>]
  static member HasHeader (response, headerName) =
    if isNull headerName then nullArg "headerName"
    Res.hasHeader headerName response
  /// Determines if a response headers exists in the response.
  [<Extension>]
  static member HasHeaderValue (response, headerName, headerValue) =
    if isNull headerName then nullArg "headerName"
    Res.hasHeaderValue headerName headerValue response
  /// Determines if a response headers exists in the response.
  [<Extension>]
  static member HasHeaderValues (response, headerName, headerValues) =
    if isNull headerName then nullArg "headerName"
    Res.hasHeaderValues headerName headerValues response

/// Adds extensions for the request model to work smootly with the .NET HttpClient.
[<Extension>]
type HttpClientExtensions () =
  /// Sends a HTTP request as a asynchronous operation.
  [<Extension>]
  static member SendAsync (this : HttpClient, req : Request) =
    use req = req.ToHttpRequestMessage ()
    this.SendAsync req
