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
    
  /// Sets the maximum amount of request that can be send concurrently to the target API endpoint.
  let maxConcurrent amount req =
    { req with MaxConcurrentRequests = amount }

/// Represents a builder for creating a HTTP request template.
type RequestBuilder internal (verb, url) =
  member __.Yield (_) = Req.endpoint verb url
  /// Adds a single query string parameter to the request.
  [<CustomOperation("parameter")>]
  member __.Parameter (state, name, value) = Req.parameter name value state
  /// Adds query string parameters to the request.
  [<CustomOperation("parameters")>]
  member __.Parameters (state, parameters) = Req.parameters parameters state
  /// Adds a single HTTP header to the request.
  [<CustomOperation("header")>]
  member __.Header (state, name, value) = Req.header name value state
  /// Adds HTTP headers to the request.
  [<CustomOperation("headers")>]
  member __.Headers (state, headers) = Req.headers headers state
  /// Adds a single route path to the request.
  [<CustomOperation("route")>]
  member __.Route (state, path) = Req.route path state
  /// Adds routing paths to the request.
  [<CustomOperation("routes")>]
  member __.Routes (state, paths) = Req.routes paths state
  /// Sets the HTTPS client certificate to the request.
  [<CustomOperation("certificate")>]
  member __.Certificate (state, certificate) = Req.certificate certificate state
  /// Sets the request body with a content type.
  [<CustomOperation("body")>]
  member __.Body (state, content, contentType) = Req.body content contentType state
  /// Replace all matching occurrences in the request content with a value.
  [<CustomOperation("body_regex")>]
  member __.BodyRegex (state, pattern, value) = Req.body_regex pattern value state
  /// Replaces all text between a specified indicator (ex. '#to-be-replaced#') with a value.
  /// Remark that this uses a regular expressions so valid regex charaters should be escaped.
  [<CustomOperation("body_between")>]
  member __.BodyBetween (state, varIndicator, value) = Req.body_between varIndicator value state
  /// Replaces the content type of the request body.
  [<CustomOperation("contentType")>]
  member __.ContentType (value, state) = Req.contentType value state
  /// Sets the maximum amount of request that can be send concurrently to the target API endpoint.
  [<CustomOperation("maxConcurrent")>]
  member __.MaxConcurrent (state, amount) = Req.maxConcurrent amount state

[<AutoOpen>]
module RequestBuilderValues =
  /// Starter value for the request template builder.
  let req verb url = RequestBuilder (verb, url)

/// Adds extensions for a C#-friendly context.
[<Extension>]
type RequestExtensions () =
  /// Adds routing paths to the request.
  [<Extension>]
  static member WithRoutes (req, [<ParamArray>] paths : string array) = 
    if isNull paths then nullArg "paths"
    Req.routes (List.ofArray paths) req
  /// Adds a single route path to the request.
  [<Extension>]
  static member WithRoute (req, path) = 
    Req.route path req
  /// Adds query string parameters to the request.
  [<Extension>]
  static member WithParameters (req, [<ParamArray>] parameters : (string * string) array) = 
    if isNull parameters then nullArg "parameters"
    Req.parameters (List.ofArray parameters) req
  /// Adds a single query string parameter to the request.
  [<Extension>]
  static member WithParameter (req, name, value) = 
    Req.parameter name value req
  /// Adds HTTP headers to the request.
  [<Extension>]
  static member WithHeaders (req, [<ParamArray>] headers : (string * string) array) = 
    if isNull headers then nullArg "headers"
    Req.headers (List.ofArray headers) req
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
  /// Sets the maximum amount of request that can be send concurrently to the target API endpoint.
  [<Extension>]
  static member WithMaximumConcurrent (req, amount) = Req.maxConcurrent amount req

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

/// Extensions on the HTTP response message.
[<Extension>]
type HttpResponseMessageExtensions () =
  /// Format the HTTP response message to a user-friendly string.
  [<Extension>]
  static member internal FormatAsString (res : HttpResponseMessage) = 
    sprintf "%A %A -> %A" res.RequestMessage.Method res.RequestMessage.RequestUri res.StatusCode 

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
    let summary = r.FormatAsString()
    Fuzz.httpLeakageHeaders
    |> Seq.filter r.Headers.Contains
    |> Seq.map (fun h -> Vulnerability.withoutRespContent summary (sprintf "Possible leakage of sensitive information from header '%s'" h) Info payloads)
    |> Array.ofSeq

  /// Sets the payloads together with how much payloads should be used for this test scan.
  let injectMax max payloads =
    { AttackSurface = []
      Payloads = payloads, max
      Validation = [] }
    |> shouldAll checkHttpLeakageHeaders

  /// Sets the payloads for this test scan.
  let inject payloads = injectMax 100 payloads

  /// Sets the payload for this test scan.
  let injectOne payload = inject [ payload ]

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

/// Builder to create a API test scan; running the scan when the builder runs.
type ApiBuilder internal (scan, req : Request) =
  member __.Yield (_) = Api.passThru
  member __.Run (state) = scan req state
  /// Sets the payloads for this this test scan.
  [<CustomOperation("inject")>]
  member __.Inject (state, payloads) : Scan = { state with Payloads = payloads, snd state.Payloads  }
  /// Sets the payload for this test scan.
  [<CustomOperation("injectOne")>]
  member __.InjectOne (state, payload) : Scan = { state with Payloads = seq { yield payload }, snd state.Payloads }
  /// Sets the payloads together with how much payloads should be used for this test scan.
  [<CustomOperation("injectMax")>]
  member __.InjectMax (state, payloads, max) : Scan = { state with Payloads = payloads, max }
  /// Adds an injector function to the test scan to inject payloads into a HTTP request.
  [<CustomOperation("into")>]
  member __.Into (state, injector) = Api.into injector state
  /// Adds a validation function that verifies a security issue.
  [<CustomOperation("should")>]
  member __.Should (state, verifier) = Api.should verifier state
  /// Adds a validation function that asserts for a security issue.
  [<CustomOperation("shouldAssert")>]
  member __.ShouldAssert (state, verifier) = Api.shouldAssert verifier state
  /// Adds a validation function that verifies several security issues.
  [<CustomOperation("shouldAll")>]
  member __.ShouldAll (state, verifier) = Api.shouldAll verifier state
  /// Adds an asynchronous validation function that verifies a security issue.
  [<CustomOperation("shouldAsync")>]
  member __.ShouldAsync (state, verifier) = Api.shouldAsync verifier state
  /// Adds an asynchronous validation function that verifies for a security issue.
  [<CustomOperation("shouldAssertAsync")>]
  member __.ShouldAssertAsync (state, verifier) = Api.shouldAssertAsync verifier state
  /// Adds an asynchronous validation function that verifies several security issues.
  [<CustomOperation("shouldAllAsync")>]
  member __.ShouldAllAsync (state, verifier) = Api.shouldAllAsync verifier state

/// Builder starter values.
[<AutoOpen>]
module ApiBuilderValues =
  /// Runs a test scan for a given HTTP request by injecting a maximum amount of payloads into a series of HTTP requests
  /// using the previously specified injector functions for the request, 
  /// and aggregates all found vulnerabilities for the test scan by validating the HTTP responses with the previously provided validation functions.
  let scan req = ApiBuilder (Api.scan, req)
  /// Runs a test scan for a given HTTP request, aggregates all found vulnerabilities for the test scan by validating the HTTP responses with the previously provided validation functions.
  let scanRequest req clientCertificate = ApiBuilder ((fun r s -> Api.scanRequest (r.ToHttpRequestMessage()) clientCertificate s), req)

/// Adds extensions to the API scan type for a C#-friendly context.
[<Extension>]
type Api () =
  /// Sets the payloads together with how much payloads should be used for this test scan.
  static member InjectMax (max, payloads) = Api.injectMax max payloads
  /// Sets the payloads for this test scan.
  static member Inject payloads = Api.inject payloads
  /// Sets the payload for this test scan.
  static member Inject payload = Api.injectOne payload
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
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Res =
  /// Determines if a response content contains an expected string,
  /// and creates a vulnerability for it when it does.
  let contain expected (response : HttpResponseMessage) = async {
    let! content = response.Content.ReadAsStringAsync() |> Async.AwaitTask
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
  let private isStatusMSB code (Response r) =
    let actual = int r.StatusCode
    actual / 100 = code
  /// Determines if the response's status code is expected.
  let isStatus code (Response r) = r.StatusCode = code
  /// Determines if the response is in the range of 4XX status codes.
  let isStatus4XX r = isStatusMSB 4 r
  /// Determines if the response is in the range of 5XX status codes.
  let isStatus5XX r = isStatusMSB 5 r
  let private statusMSB code payloads (Response r) =
    if isStatusMSB code r then None
    else Some <| Vuln.medium (sprintf "should respond with %iXX status code but was %i" code (int r.StatusCode)) (r.FormatAsString()) payloads
  /// Determines if the response is in the range of 4XX status codes.
  let status4XX payloads r = statusMSB 4 payloads r
  /// Determines if the response is in the range of 5XX status codes.
  let status5XX payloads r = statusMSB 5 payloads r
  /// Determines if the response status code is expected.
  let statuscode code ps (Response r) =
    let actual = int r.StatusCode
    if actual = code then None
    else Some <| Vuln.medium (sprintf "should respond with %i but was %i" code actual) (r.FormatAsString()) ps
  /// Determines if the respose status code is expected.
  let status (code : Net.HttpStatusCode) ps r = statuscode (int code) ps r
  /// Determines if the response has response header.
  let header name value ps (Response r) =
    match r.Headers.TryGetValues name with
    | true, vs -> String.Join (String.Empty, vs) = value
    | false, _ -> false
    |> fun check ->
      if check then None 
      else Some <| Vuln.medium (sprintf "should have header %s = %s" name value) (r.FormatAsString()) ps

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
  /// Determines if the response is in the range of 4XX status codes.
  [<Extension>]
  static member IsStatus4XX (response) = Res.isStatus4XX response
  /// Determines if the response is in the range of 5XX status codes.
  [<Extension>]
  static member IsStatus5XX (response) = Res.isStatus5XX response
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

/// Functionality on the vulnerability type which is directly available.
[<AutoOpen>]
module VulnerabilityAutoOpen =
  /// Additional extensions on the vulnerability type.
  type Vulnerability with
    /// Creates a vulnerability by reading the response content.
    /// A summary from the request is created.
    static member fromRespContent (res : HttpResponseMessage) desc severity payloads = async {
      let! content = res.Content.ReadAsStringAsync() |> Async.AwaitTask
      return { Description = desc
               Summary = res.FormatAsString ()
               ResponseContent = content
               Severity = severity
               Payloads = payloads } }
  
/// Provides additional extensions on the vulnerability type.
[<Extension>]
type VulnerabilityExtensions () =
  /// Adds the response content to the vulnerability.
  [<Extension>]
  static member WithResponseContentAsync (vulnerability : Vulnerability) (res : HttpResponseMessage) =
    async { let! content = res.Content.ReadAsStringAsync() |> Async.AwaitTask
            return { vulnerability with ResponseContent = content } } |> Async.StartAsTask
  
/// Model to create vulnerability types.
type VulnerabilityFactory =
  /// Creates a vulnerability by reading the response content.
  /// A summary from the request is created.
  static member CreateFromResponseContentAsync response description severity payloads =
    Vulnerability.fromRespContent response description severity payloads |> Async.StartAsTask
