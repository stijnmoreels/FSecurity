#r "paket: groupref Build //"
open Fake.DotNet.Testing

#load "./.fake/build.fsx/intellisense.fsx"
#if !FAKE
    #r "netstandard"
#endif

open Fake
open Fake.DotNet
open Fake.DotNet.Testing.XUnit2 
open Fake.Core
open Fake.BuildServer
open Fake.Core.TargetOperators
open Fake.IO
open Fake.IO.Globbing.Operators
open Fake.IO.FileSystemOperators

let projects = [ "src/FSec/FSec.fsproj" ]
let project = "FSec"
let summary = "FSec is a tool for automatically running security tests for .NET programs"
let description = "FSec is a tool for automatically running security tests for .NET programs. The tool provides some basic security testing functionality to discover vulnerabilities."
let authors = [ "Stijn Moreels" ]
let tags = "fsharp security testing tool automation tests ci owasp"
let solutionFile  = "FSec.sln"
let configuration = "Release"
let testAssemblies = "tests/**/bin" </> configuration </> "*Tests*.dll"
let nuget = "https://www.nuget.org/packages/FSec"
let gitOwner = "stijnmoreels"
let gitHome = "https://github.com/stijnmoreels/FSec"
let gitName = "FSec"
let buildDir = System.IO.Path.GetFullPath "bin"
let testDir = System.IO.Path.GetFullPath "tests"
let docsDir = System.IO.Path.GetFullPath "docs"
let docsrcDir = System.IO.Path.GetFullPath "docsrc"
let website = "/" + gitName
let gitRaw = Environment.environVarOrDefault "gitRaw" "https://raw.githubusercontent.com/stijnmoreels/FSec/stijnmoreels"
let release = ReleaseNotes.load  "RELEASE_NOTES.md"
let isAppVeyorBuild = Environment.environVar "APPVEYOR" |> isNull |> not
let isTaggedBuild = Environment.environVarAsBoolOrDefault "APPVEYOR_REPO_TAG" false
let versionSuffix =
    let buildVersion = BuildServer.buildVersion
    if isTaggedBuild then ""
    elif buildVersion = "LocalBuild" then "-LocalBuild"
    else "-beta" + buildVersion
let nugetVersion = release.NugetVersion + versionSuffix

BuildServer.install [ AppVeyor.Installer ]

Target.create "BuildVersion" <| fun _ ->
    Shell.Exec("appveyor", sprintf "UpdateBuild -Version \"%s\"" nugetVersion) |> ignore

Target.create "Clean" <| fun _ ->
    !! "src/**/bin"
    ++ "src/**/obj"
    ++ "bin"
    ++ "temp"
    |> Shell.cleanDirs

Target.create "CleanDocs" <| fun _ -> 
    Shell.cleanDir "docs/output"

Target.create "Build" <| fun _ ->
    !! solutionFile
    |> MSBuild.runReleaseExt id "" [] "Rebuild"
    |> ignore

Target.create "CopyLicense" <| fun _ ->
    [ "LICENSE.txt" ] |> Shell.copyTo "bin"

Target.create "RunTests" <| fun _ ->
    !! (testDir @@ "**/bin/Release/FSec.Tests.dll")
    |> XUnit2.run (fun p ->
        { p with
            ShadowCopy = false
            TimeOut = System.TimeSpan.FromMinutes 20.
            XmlOutputPath = Some "TestResults.xml" })

Target.create "Pack" <| fun _ ->
    Environment.setEnvironVar "PackageVersion" nugetVersion
    Environment.setEnvironVar "Version" nugetVersion
    Environment.setEnvironVar "PackageReleaseNotes" (release.Notes |> String.toLines)
    projects
    |> List.iter (
        DotNet.pack (fun p -> 
            { p with
                OutputPath = Some buildDir
                NoBuild = true
            }
        )
       )

Target.create "Push" <| fun _ ->
    DotNet.Paket.push(fun p ->
        { p with
            PublishUrl = "https://www.nuget.org"
            WorkingDir = "bin" })

Target.create "GenerateDocs" <| fun _ ->
    let githubLink = "https://github.com/stijnmoreels/FSec"
    let root = "/FSec"

    let content = docsDir @@ "content"
    let output = docsDir @@ "output"
    let outputContent = output @@ "content"
    let outputReference = output @@ "reference"
    let files = docsDir @@ "files"
    let templates = docsrcDir @@ "tools/templates"
    let formatting = System.IO.Path.GetFullPath "packages/build/FSharp.Formatting.CommandTool"
    let docTemplate = formatting @@ "templates/docpage.cshtml"

    let layoutRoots = 
        [ templates
          formatting @@ "templates"
          formatting @@ "templates/reference" ]

    let info =
        [ "root", root
          "project-name", project
          "project-author", String.concat ", " authors
          "project-summary", summary
          "project-github", githubLink
          "project-nuget", nuget ]

    Directory.ensure files
    Shell.copyDir output files FileFilter.allFiles
    Directory.ensure outputContent
    Shell.copyDir outputContent (formatting @@ "styles") FileFilter.allFiles
    FSFormatting.createDocs (fun s ->
        { s with 
            Source = content
            OutputDirectory = output
            Template = docTemplate
            ProjectParameters = info
            LayoutRoots = layoutRoots })

    Directory.ensure outputReference
    let dlls =
        !! "src/FSec/bin/Release/**/FSec.dll"
        |> Seq.distinctBy System.IO.Path.GetFileName
        |> List.ofSeq
    let libDirs =
        dlls
        |> Seq.map System.IO.Path.GetDirectoryName
        |> Seq.distinct
        |> List.ofSeq

    dlls
    |> FSFormatting.createDocsForDlls (fun s ->
        { s with
            OutputDirectory = outputReference
            LayoutRoots = layoutRoots
            LibDirs = libDirs
            ProjectParameters = info
            SourceRepository = githubLink @@ "tree/master" })

open Fake.Tools

Target.create "ReleaseDocs" <| fun _ ->
    let tempDocsDir = "temp/gh-pages"
    Shell.cleanDir tempDocsDir

    let workingDir = ""
    Git.Repository.cloneSingleBranch
        workingDir ("https://github.com/stijnmoreels/FSec.git") "gh-pages" tempDocsDir

    let overwrite = true
    Shell.copyRecursive "docs/output" tempDocsDir overwrite 
    |> Trace.tracefn "%A"

    Git.Staging.stageAll tempDocsDir
    Git.Commit.exec tempDocsDir (sprintf "Update generated documentation for version %s" release.NugetVersion)
    Git.Branches.push tempDocsDir

Target.create "Release" <| fun _ ->
    Git.Staging.stageAll ""
    Git.Commit.exec "" (sprintf "Bump version to %s" release.NugetVersion)
    Git.Branches.push ""

    Git.Branches.tag "" release.NugetVersion
    Git.Branches.pushTag "" "origin" release.NugetVersion

Target.create "All" ignore

"Clean"
=?> ("BuildVersion", isAppVeyorBuild)
==> "CopyLicense"
==> "Build"
==> "RunTests"
==> "All"
=?> ("GenerateDocs", BuildServer.isLocalBuild && not Environment.isMono)

"All"
==> "Pack"
==> "Push"

"CleanDocs"
==> "GenerateDocs"
==> "ReleaseDocs"

"Push"
==> "Release"

Core.Target.runOrDefault "All"
