module XPath

open System.Xml
open System
open System.Xml.Xsl
open System.Xml.XPath

let xml = @"<?xml version=""1.0"" encoding=""utf-8""?>    
          <Employees>
            <Employee ID=""1"">
                <FirstName>Arnold</FirstName>
                <LastName>Baker</LastName>
                <UserName>ABaker</UserName>
                <Password>SoSecret</Password>
                <Type>Admin</Type>
            </Employee>s
            <Employee ID=""2"">
                <FirstName>Peter</FirstName>
                <LastName>Pan</LastName>
                <UserName>PPan</UserName>
                <Password>NotTelling</Password>
                <Type>User</Type>
                </Employee>
           </Employees>"

let notImpl = raise (NotImplementedException ())

type XPathVar (x) =
    interface IXsltContextVariable with
        member __.Evaluate _ = x
        member __.IsLocal: bool = notImpl
        member __.IsParam: bool = notImpl
        member __.VariableType: XPathResultType = raise (NotImplementedException ())
        
type XPathVars (values : Map<string, obj>) =
    inherit XsltContext ()
    override __.ResolveVariable (_, n) = XPathVar values.[n] :> IXsltContextVariable
    override __.ResolveFunction (_, _, _) = raise (NotImplementedException ())
    override __.CompareDocument (_, _) = raise (NotImplementedException ())
    override __.PreserveWhitespace _ = raise (NotImplementedException ())
    override __.Whitespace = raise (NotImplementedException ())

let vulnerable user pass =
    let doc = XmlDocument () in
        doc.LoadXml xml
    let xpath = sprintf "//Employee[UserName/text()='%s' and Password/text()='%s']" user pass
    testVuln <| fun () ->
        if doc.SelectSingleNode xpath = null 
        then Prevented
        else Vulnerable

let prevented user pass =
    let doc = XmlDocument () in
        doc.LoadXml xml

    let ctx = 
        Map.empty 
        |> Map.add "user" user 
        |> Map.add "pass" pass 
        |> XPathVars
    
    let xpath = "//Employee[UserName/text()='$user' and Password/text()='$pass']"
    testVuln <| fun () ->
        if doc.SelectSingleNode (xpath, ctx) = null
        then Prevented 
        else Vulnerable