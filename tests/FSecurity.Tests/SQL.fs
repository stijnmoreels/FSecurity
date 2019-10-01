module SQL

open System.Text.RegularExpressions

let private matches x =
    Regex.IsMatch (x, "^[a-zA-Z]+$")

let private testVuln (conn : string) =
    conn.ToCharArray ()
    |> Array.exists (not << (string >> matches))
    |> function
        | true -> Vulnerable
        | false -> Prevented

let vulnerable =
    sprintf "SELECT * FROM Users WHERE Id = %s;" 
    >> testVuln

let prevented x =
    match x with
    | x when matches x -> vulnerable x
    | _ -> Prevented