<#
.Synopsis
   Parse Nessus XML report and import to ElasticSearch using _bulk API
.DESCRIPTION
   Parse Nessus XML report and convert to expected json format (x-ndjson)
   for ElasticSearch _bulk API
.EXAMPLE
   .\ImportTo-ElasticSearchBulk.ps1 -InputXML "C:\folder\file.nessus" -Server es.contoso.com -Index "nessus" -type "vuln"
#>

[CmdletBinding()]
[Alias()]
Param
(
    # XML file input
    [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
    $InputXML,
    # ElasticSearch index mapping
    [Parameter(Mandatory=$false,
                ValueFromPipelineByPropertyName=$true,
                Position=1)]
    $Index,
    # ElasticSearch type mapping
    [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=2)]
    $Type,
    # ElasticSearch server
    [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=3)]
    $Server
)

Begin{

    $ErrorActionPreference = 'Stop'
    [xml]$nessus = [System.IO.File]::OpenText("$InputXML").readtoend()

}
Process{

    $hash = foreach ($n in $nessus.NessusClientData_v2.Report.ReportHost){
    
        foreach($r in $n.ReportItem){
            if($r.pluginID -match "19506|20094"){
                # ignore useless plugins
            }            
            $obj=[PSCustomObject]@{
                "ip" = ($n.HostProperties.tag | ? {$_.name -eq "host-ip"})."#text"
                "fqdn" = ($n.HostProperties.tag | ? {$_.name -eq "host-fqdn"})."#text"
                "svc" = ($r.svc_name)
                "protocol" = $r.severity
                "pluginID" = $r.pluginID
                "pluginName" = $r.pluginName
                "pluginFamily" = $r.pluginFamily
                #"description" = $r.description
                "plugin_publication_date" = $r.plugin_publication_date
                "plugn_type" = $r.plugin_type
                "risk_factor" = $r.risk_factor
                "solution" = $r.solution
                "synopsis" = $r.synopsis
                "plugin_output" = $r.plugin_output
                "cvss_base_score"= $r.cvss_base_score
                "cvss_temporal_score" = $r.cvss_temporal_score
                "cvss_vector" = $r.cvss_vector
                "operating-system-unsupported" = ($n.HostProperties.tag | ? {$_.name -eq "operating-system-unsupported"})."#text"
                "system-type" = ($n.HostProperties.tag | ? {$_.name -eq "system-type"})."#text"
                "os" = ($n.HostProperties.tag | ? {$_.name -eq "os"})."#text"
                "operating-system" = ($n.HostProperties.tag | ? {$_.name -eq "operating-system"})."#text"
                "Credentialed_Scan" = ($n.HostProperties.tag | ? {$_.name -eq "Credentialed_Scan"})."#text"
                "policy-used" = ($n.HostProperties.tag | ? {$_.name -eq "policy-used"})."#text"
                "exploit_available" = $r.exploit_available
                "in_the_news" = $r.in_the_news
                "edb-id" = $r."edb-id"
                "see_also" = $r.see_also
                "unsupported_by_vendor" = $r.unsupported_by_vendor
                #"msft" = $(if(($r.msft).count -gt 1) {([string]$r.msft.GetEnumerator() -replace " ","`n")})
                #"xref" = $(if(($r.msft).count -gt 1) {([string]$r.xref.GetEnumerator() -replace " ","`n")})
                #"bid" = $(if(($r.msft).count -gt 1) {([string]$r.bid.GetEnumerator() -replace " ","`n")})
                #"mskb" = $(if(($r.msft).count -gt 1) {([string]$r.mskb.GetEnumerator() -replace " ","`n")})
                #"cve" = $(if(($r.msft).count -gt 1) {([string]$r.cve.GetEnumerator() -replace " ","`n")})
                "time" = $(Get-Date -f "yyyy/MM/dd hh:mm:ss" $((((($n.HostProperties.tag | ? {$_.name -eq "HOST_END"})."#text") | sls "^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{2}) (.+) ([0-9]{4})").Matches.Groups[2,3,5,4].Value)-join " "))
            } | ConvertTo-Json -Compress
            
            "{`"index`":{`"_index`":`"$index`",`"_type`":`"$type`"}}`r`n$obj`r`n"
        }
    }
}
End{

        
    try{
        Invoke-Webrequest -Uri "http://$($server):9200/$index/$type/_bulk" -Method POST -ContentType "application/json " -body $hash
    } catch {
        $_.Exception.Message
    }
    

}