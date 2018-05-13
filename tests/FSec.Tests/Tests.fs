module FSec.Tests

open System.Xml
open FSec
open FsCheck
open FsCheck.Xunit


let vulnerableXPath user pass =
    let doc = XmlDocument ()
    @"<?xml version=""1.0"" encoding=""utf-8""?>    
          <Employees>
            <Employee ID=""1"">
                <FirstName>Arnold</FirstName>
                <LastName>Baker</LastName>
                <UserName>ABaker</UserName>
                <Password>SoSecret</Password>
                <Type>Admin</Type>
            </Employee>
            <Employee ID=""2"">
                <FirstName>Peter</FirstName>
                <LastName>Pan</LastName>
                <UserName>PPan</UserName>
                <Password>NotTelling</Password>
                <Type>User</Type>
                </Employee>
           </Employees>"
    |> doc.LoadXml
    sprintf "//Employee[UserName/text()='%s' and Password/text()='%s']" user pass
    |> fun x -> 
        try 
            if doc.SelectSingleNode x = null then false
            else true
        with | ex -> true

[<Property>]
let ``XPath input injection`` () =
    FSec.xpathInput
    |> Gen.two
    |> Arb.fromGen
    |> Prop.forAll <| fun (u, p) -> 
        vulnerableXPath u p