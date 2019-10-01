module HTML

open System.Text.RegularExpressions

let vulnerable x =
    Some <| sprintf "<span>Hello%s!</span>" x

let prevented x =
    if Regex.IsMatch (x, "^[A-Za-z]$")
    then vulnerable x
    else None