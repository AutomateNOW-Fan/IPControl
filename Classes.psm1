Add-Type -AssemblyName Microsoft.PowerShell.Commands.Utility

#Region Enums

#Region - Enum [ResourceRecord]

Enum ResourceRecord_resourceRecType {
    A; A6; AAAA; AFSDB; APL; AVC; CAA; CDS; CDNSKEY; CERT; CNAME; CSYNC; DNAME; DS; EUI48; EUI64; GPOS; HINFO; ISDN; KEY; KX; LOC; MB; MG; MINFO; MR; MX; NAPTR; NINFO; NULL; NS; NSAP; NSAPPTR; OPENPGPKEY; PTR; RKEY; NXT; PX; RP; RT; SA; SSHFP; SIG; SINK; SMIMEA; SOA; SRV; TALINK; TKEY; TLSA; TSIG; TXT; URI; WKS; X25; ZONERR;
}

#endregion

#EndRegion

#Region Classes

#region Class - [IPControl] (Base Class)

# This is the base class that exists at the top of the hierarchy. All other classes will inherit the properties/methods defined in this object.

Class IPControl {
    [int64]$id
}

#endregion

#region Class - [Container]

Class Container : IPControl {
    [string[]]$allowedAllocFromParentBlocktypes
    [string[]]$allowedBlockTypes
    [string[]]$allowedDeviceTypes
    [string[]]$allowedDomains
    [boolean]$applyDHCPToMultiparentDevContainer
    [int64]$blockAllocation
    [string[]]$blockTypeInfoTemplates
    [string]$cloudObjectId
    [string]$containerName
    [string]$containerType
    [string]$description
    [string]$discoveryAgent
    [int64]$domainConstraintEnabled
    [boolean]$ignoreBlocktypeInUse
    [boolean]$inheritvlan
    [boolean]$maintainHistoryRecs
    [boolean]$msSite
    [string]$parentName

    Container() {
        $this.Init(@{})
    }
    [void] Init([hashtable]$Properties) {
        ForEach ($Property in $Properties.Keys) {
            $this.$Property = $Properties.$Property
        }
    }
}

#endregion

#region Class - [Device]

Class Device : IPControl {
    [string]$addressType
    [PSCustomObject[]]$aliases #= [PSCustomObject]@{}
    [string]$container
    [string]$description
    [string]$deviceType
    [string]$duid
    [string]$domainName
    [string]$domainType
    [string]$hostname
    [PSCustomObject[]]$interfaces
    [string]$ipAddress
    [string]$resourceRecordFlag

    Container() {
        $this.Init(@{})
    }
    [void] Init([hashtable]$Properties) {
        ForEach ($Property in $Properties.Keys) {
            $this.$Property = $Properties.$Property
        }
    }
}

Class initExportDevice : IPControl {
    [string]$contextId
    [string]$contextType
    [string]$filter
    [int64]$firstResultPos
    [int64]$internalResultCount
    [int64]$maxResults
    [array]$options = @($null)
    [string]$query
    [int64]$resultCount

    initExportDevice() {
        $this.Init(@{})
    }
    [void] Init([hashtable]$Properties) {
        ForEach ($Property in $Properties.Keys) {
            $this.$Property = $Properties.$Property
        }
    }
}

#region Class - [ResourceRecord]

#endregion

#endregion

#region Class - [ResourceRecord]

Class ResourceRecord : IPControl {
    [string]$comment
    [string]$container
    [string]$data
    [string]$domain
    [string]$domainType
    [string]$effectiveStart
    [string]$hostname
    [string]$ipAddress
    [string]$owner
    [boolean]$pendingDeployment
    [string]$resourceRecClass
    [ResourceRecord_resourceRecType]$resourceRecType
    [string]$TTL

    ResourceRecord() {
        $this.Init(@{})
    }
    [void] Init([hashtable]$Properties) {
        ForEach ($Property in $Properties.Keys) {
            $this.$Property = $Properties.$Property
        }
    }
}

#endregion

#endregion

#endregion