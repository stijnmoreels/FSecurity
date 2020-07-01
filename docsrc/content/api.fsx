(*** hide ***)
// This block of code is omitted in the generated HTML documentation. Use 
// it to define helpers that you do not want to show in the documentation.
#r "../../src/FSecurity.Api/bin/Release/netstandard2.0/FSecurity.dll"
#r "../../src/FSecurity.Api/bin/Release/netstandard2.0/FSecurity.Api.dll"

open FSecurity

(**
Application security testing API's
==================================

**FSecurity** provides several components so testing an API on application security issues becomes an easier process.

Everything starts and ends with the `Api` type that allows you to pass allong a HTTP request 'template' on how the requests should be made and injection points on where the security payload should be injected.
Both combined allows you to scan an API for security issues which will be bundled into a list of `Vulnerability` types.

Create HTTP request template
----------------------------

First things first, we have to create a HTTP request template on what the minimum requirements are to interact with the API.
For example: API keys, headers, ...

This example shows how such a template can be created:
*)

let request =
  Req.endpoint GET "http://localhost:8080"
  |> Req.parameter "X-API-Key" "super-secret-key"

(** 
And the C# alternative: 
*)

Request.Endpoint("http://localhost:8080")
       .WithParameter("X-API-Key", "super-secret-key");

(**
Determine injection points
--------------------------

The parts you want to test/verify, are the 'injection points'. It can be for example that you want to verify if a certain input only allows certain values.
This part is were the fuzzing comes into play. 

The base library already defines several lists that contain possible fuzzing inputs for you test:
*)

let (xs : string seq) = Fuzz.xss
let (xs : string seq) = Fuzz.json
let (xs : string seq) = Fuxx.alphanum

(**
And many more...
*)

(**
Scanning for vulnerabilities
----------------------------

Combining the HTTP request template with the injection points; we can now create our security scan test that will by default run 100 tests with random takes from the fuzzed inputs and inject them into the predefined injection parts of the HTTP request.
*)

let request =
  Req.endpoint GET "http://localhost:8080"
  |> Req.parameter "X-API-Key" "super-secret-key"

let (vulnerabilities : Vulnerability seq) =
  Api.inject Fuzz.json
  |> Api.into (Req.parameter "personName")
  |> Api.should Res.status4XX
  |> Api.scan request

(**
And the C# alternative:
*)

var request =
  Request.Endpoint("http://localhost:8080")
         .WithParameter("X-API-Key", "super-secret-key");

var vulnerabilities =
  Api.Inject(Fuzz.Json)
     .Into((req, value) => req.WithParameter(value))
     .Should((payloads, res) => res.IsStatus4XX(), Vulnerability.Info(""))