[<AutoOpen>]
module VulnResult

/// Represents a type that acts as response of a SUT to indicate wheter or not the given payload results in a vulnerable system.
type VulnResult = 
    | Prevented 
    | Vulnerable

let testVuln f = try f () with | _ -> Vulnerable