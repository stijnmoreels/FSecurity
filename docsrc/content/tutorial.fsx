(*** hide ***)
// This block of code is omitted in the generated HTML documentation. Use 
// it to define helpers that you do not want to show in the documentation.
#I "../../bin/FSec"
#r "FsCheck.dll"
#r "FSec.dll"
open FSecurity
open FsCheck
module Html = let login u p : string = p
module String = let contains x (s : string) = s.Contains x

(**
Introducing to FSec
========================

Security Testing is sometimes a "forgotten" topic when writing tests. Unit, Component, Integration, Performance, Stress and even Functional Tests are somewhat common during testing, but Security is often forgotten.
When looking at available packages for this, there's not very much arround. That's why this package can help you finding the missing spots in your application.

Security Testing
----------------

The closest approach Security Testing can be related to, is propably Stress Testing. What we want to do, is manipulating the input of the test in such a way that the application reacts falsely on this; meaning that the application is likely vulnerable to this kind of input.
In Stress Testing you most likly are testing the application in adnormal conditions to test the robustness of the application, in an even further approach we would test the application with a DOS attack.

When designing the application itself, the security mantra AAA comes into mind: "Authentication", "Authorization", and "Availability". The previous example would test the "Availability" of the system. But what Stress Testing doesn't verify, are the two other elements of the mantra.

Writing your first Security Test
--------------------------------

What people sometimes think, is that writing Security Tests is hard to do. A Security Test doesn't look very different from a Unit or Integration Test, meaning: you can write in the same language or framework you always write your tests which makes the learning curve rather low.

The package `FSec` consists most of all of input generators. These inputs can be used to send to any kind of system you want to test. Whether it's a function, or a file, web call...because it only consists of these generators, its applicable in many domains.

For this example, lets think of a many occuring problem: XSS. If an input field is vulnerable to XSS, it allows you to input not ony text but whole HTML code, and therefore, JavaScript. When this input is shown on any page, the JavaScript would run meaning it's vulnerable to XSS.
The `FSec` package has a generator for this: `FSec.xssInject` which generates different kinds of XSS inputs that you can use in your test.

*)

FSec.xssInject
|> Arb.fromGen
|> Prop.forAll <| fun x -> 
    Html.login "admin" x
    |> String.contains x
