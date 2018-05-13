namespace FSec

/// Module that holds the security testing functionality
///
module FSec = 
    open FsCheck
  
    /// **Description**
    /// XPath input generator that provides malformed information that can be used to discover vulnerabilities in XPath functionality.
    /// XPath is a "simple" language to locate information in an XML document. 
    /// Similar to SQL Injection, XPath Injection attacks occur when an application uses user-supplied information 
    /// to construct an XPath query for XML data. By sending intentionally malformed information into the application, 
    /// an attacker can find out how the XML data is structured, or access data that he may not normally have access to.
    /// **Severity**
    /// Critical
    /// **Vulnerability Indicators**
    /// - Incorrect syntax
    /// - Invalid syntax
    /// - Syntax error
    /// - Runtime Errors
    /// - XPathException
    /// - System.Xml.XPath
    let xpathInput =
        Gen.elements [ 
            "1' or 1=1"
            "a%' or '1' = '1"
            "' or '1' = '1"
            "'a or 1=1 or 'a'='a" ]