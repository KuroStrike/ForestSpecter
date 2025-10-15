<# 
.SYNOPSIS
  ForestSpecter — AD Forest Trust Path Visualizer and Risk Auditor.

.USAGE
  # Full forest audit + diagrams
  .\ForestSpecter.ps1 -ExportPath C:\Reports

  # Trust-path between two domains (shortest path)
  .\ForestSpecter.ps1 -ExportPath C:\Reports -StartDomain corp.contoso.com -TargetDomain eu.fabrikam.com

.REQUIREMENTS
  Windows PowerShell 5.1+ with RSAT ActiveDirectory, or PS7 + WindowsCompatibility.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ExportPath,
  [string]$StartDomain,
  [string]$TargetDomain
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Test-Module([string]$Name){
  if(-not (Get-Module -ListAvailable -Name $Name)){ throw "Module $Name not found. Install RSAT-AD-PowerShell." }
}
Test-Module ActiveDirectory
Import-Module ActiveDirectory

# ---------- Setup ----------
$null = New-Item -ItemType Directory -Path $ExportPath -Force
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$pathTrusts  = Join-Path $ExportPath "ForestSpecter_Trusts_$ts.csv"
$pathDomains = Join-Path $ExportPath "ForestSpecter_Domains_$ts.csv"
$pathRisks   = Join-Path $ExportPath "ForestSpecter_Risks_$ts.csv"
$pathMermaid = Join-Path $ExportPath "ForestSpecter_Graph_$ts.mmd"
$pathDOT     = Join-Path $ExportPath "ForestSpecter_Graph_$ts.dot"
$pathPathCSV = Join-Path $ExportPath "ForestSpecter_ShortestPath_$ts.csv"

# ---------- Collect domains and trusts ----------
$forest = Get-ADForest
$domains = @()
$trusts  = New-Object System.Collections.Generic.List[object]

foreach($d in $forest.Domains){
  $domains += [pscustomobject]@{ Domain=$d; Forest=$forest.Name }

  # Enumerate outbound view from each domain controller of domain
  try{
    $t = Get-ADTrust -Filter * -Server $d -ErrorAction Stop
    foreach($row in $t){
      $trusts.Add([pscustomobject]@{
        SourceDomain              = $d
        TargetDomain              = $row.Target
        TrustType                 = $row.TrustType                      # Forest, External, Kerberos, MIT
        Direction                 = $row.Direction                      # Inbound/Outbound/Bidirectional
        ForestTransitive          = [bool]$row.ForestTransitive
        SelectiveAuthentication   = [bool]$row.SelectiveAuthentication
        TGTDelegation             = [bool]$row.TGTDelegation
        SIDFilteringQuarantined   = [bool]$row.SIDFilteringQuarantined
        SIDFilteringForestAware   = [bool]$row.SIDFilteringForestAware
        UsesAESKeys               = [bool]$row.UsesAESKeys
        UsesRC4EncryptionOnly     = [bool]$row.UsesRC4EncryptionOnly
        IntraForest               = [bool]$row.IntraForest
        IsTreeParent              = [bool]$row.IsTreeParent
        IsTreeRoot                = [bool]$row.IsTreeRoot
      })
    }
  } catch {
    Write-Warning "Failed to query trusts from $d : $($_.Exception.Message)"
  }
}

# ---------- Normalize to undirected edges for visualization ----------
# Key = Source->Target unique
$edges = @{}
foreach($t in $trusts){
  $key = "$($t.SourceDomain)|$($t.TargetDomain)"
  if(-not $edges.ContainsKey($key)){ $edges[$key] = $t }
}

# ---------- Risk rules ----------
$risks = New-Object System.Collections.Generic.List[object]
foreach($e in $edges.Values){
  $flags = @()

  if(-not $e.SIDFilteringQuarantined -and -not $e.IntraForest){
    $flags += 'SID filtering disabled on external/forest trust'
  }
  if(-not $e.SelectiveAuthentication -and -not $e.IntraForest){
    $flags += 'Selective Authentication disabled'
  }
  if($e.TGTDelegation){
    $flags += 'TGTDelegation enabled across trust'
  }
  if($e.UsesRC4EncryptionOnly -and -not $e.UsesAESKeys){
    $flags += 'RC4 only'
  }
  if($e.TrustType -eq 'External' -and $e.ForestTransitive){
    $flags += 'External marked forest-transitive (check)'
  }

  if($flags.Count -gt 0){
    $risks.Add([pscustomobject]@{
      SourceDomain = $e.SourceDomain
      TargetDomain = $e.TargetDomain
      TrustType    = $e.TrustType
      Findings     = ($flags -join '; ')
    })
  }
}

# ---------- Exports ----------
$domains | Sort-Object Domain | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $pathDomains
$trusts  | Sort-Object SourceDomain,TargetDomain | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $pathTrusts
$risks   | Sort-Object SourceDomain,TargetDomain | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $pathRisks

# ---------- Mermaid graph ----------
$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine('graph LR')
$null = $sb.AppendLine('%% ForestSpecter — Trust topology')

# Node set
$allNodes = ($domains | Select-Object -Expand Domain) + ($trusts | Select-Object -Expand TargetDomain)
$allNodes = $allNodes | Sort-Object -Unique
foreach($n in $allNodes){
  $label = $n.ToUpper()
  $null = $sb.AppendLine(("  ""{0}""([[""{1}"" ]])" -f $n,$label))
}

# Edges
function EdgeLabel($e){
  $parts = @()
  $parts += $e.TrustType
  if($e.ForestTransitive){ $parts += 'Transitive' } else { $parts += 'NonTransitive' }
  if($e.SelectiveAuthentication){ $parts += 'SA' } else { $parts += 'NoSA' }
  if($e.SIDFilteringQuarantined){ $parts += 'SIDFilter' } else { $parts += 'NoSIDFilter' }
  if($e.TGTDelegation){ $parts += 'TGTDel' }
  if($e.UsesRC4EncryptionOnly -and -not $e.UsesAESKeys){ $parts += 'RC4' }
  return ($parts -join ',')
}

foreach($e in $edges.Values){
  $lbl = EdgeLabel $e
  $null = $sb.AppendLine(("  ""{0}"" ---|""{2}""| ""{1}""" -f $e.SourceDomain,$e.TargetDomain,$lbl))
}

$sb.ToString() | Set-Content -Path $pathMermaid -Encoding UTF8

# ---------- Graphviz DOT (optional for large graphs) ----------
$dot = New-Object System.Text.StringBuilder
$null = $dot.AppendLine('graph ForestSpecter {')
$null = $dot.AppendLine('  rankdir=LR; node [shape=box];')
foreach($n in $allNodes){ $null = $dot.AppendLine(('  "{0}";' -f $n)) }
foreach($e in $edges.Values){
  $null = $dot.AppendLine(('  "{0}" -- "{1}" [label="{2}"];' -f $e.SourceDomain,$e.TargetDomain,(EdgeLabel $e)))
}
$null = $dot.AppendLine('}')
$dot.ToString() | Set-Content -Path $pathDOT -Encoding UTF8

# ---------- Shortest trust path (optional) ----------
if($StartDomain -and $TargetDomain){
  $adj = @{}
  foreach($n in $allNodes){ $adj[$n] = New-Object System.Collections.Generic.HashSet[string] }
  foreach($e in $edges.Values){
    $adj[$e.SourceDomain].Add($e.TargetDomain) | Out-Null
    $adj[$e.TargetDomain].Add($e.SourceDomain) | Out-Null
  }

  if(-not $adj.ContainsKey($StartDomain)){ throw "StartDomain $StartDomain not found." }
  if(-not $adj.ContainsKey($TargetDomain)){ throw "TargetDomain $TargetDomain not found." }

  $queue = New-Object System.Collections.Generic.Queue[object]
  $queue.Enqueue($StartDomain)
  $prev = @{}
  $seen = New-Object System.Collections.Generic.HashSet[string]
  $seen.Add($StartDomain) | Out-Null

  while($queue.Count -gt 0){
    $u = $queue.Dequeue()
    if($u -eq $TargetDomain){ break }
    foreach($v in $adj[$u]){
      if(-not $seen.Contains($v)){
        $seen.Add($v) | Out-Null
        $prev[$v] = $u
        $queue.Enqueue($v)
      }
    }
  }

  $path = @()
  $at = $TargetDomain
  while($prev.ContainsKey($at)){ $path += $at; $at = $prev[$at] }
  if($at -eq $StartDomain){ $path += $StartDomain; $path = $path[::-1] }
  else { throw "No path between $StartDomain and $TargetDomain." }

  $out = for($i=0;$i -lt ($path.Count-1);$i++){
    $a=$path[$i]; $b=$path[$i+1]
    $edge = $edges["$a|$b"]; if(-not $edge){ $edge = $edges["$b|$a"] }
    [pscustomobject]@{
      Hop = $i+1
      From = $a
      To   = $b
      TrustType = $edge.TrustType
      Transitive = $edge.ForestTransitive
      SelectiveAuth = $edge.SelectiveAuthentication
      SIDFiltering = $edge.SIDFilteringQuarantined
      TGTDelegation = $edge.TGTDelegation
    }
  }
  $out | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $pathPathCSV
}

Write-Host "Saved:" -ForegroundColor Cyan
Write-Host " - $pathDomains"
Write-Host " - $pathTrusts"
Write-Host " - $pathRisks"
Write-Host " - $pathMermaid"
Write-Host " - $pathDOT"
if(Test-Path $pathPathCSV){ Write-Host " - $pathPathCSV" }
Write-Host "Done." -ForegroundColor Green
