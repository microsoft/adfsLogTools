# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# ----------------------------------------------------
#
# Global Constants
#
# ----------------------------------------------------

$global:CONST_ADFS_ADMIN = "AD FS"
$global:CONST_ADFS_AUDIT = "AD FS Auditing"
$global:CONST_ADFS_DEBUG = "AD FS Tracing"

$global:CONST_SECURITY_LOG = "security"
$global:CONST_ADMIN_LOG = "AD FS/Admin"
$global:CONST_DEBUG_LOG = "AD FS Tracing/Debug"

$global:CONST_LOG_PARAM_SECURITY = "security"
$global:CONST_LOG_PARAM_ADMIN = "admin"
$global:CONST_LOG_PARAM_DEBUG = "debug"

$global:CONST_AUDITS_TO_AGGREGATE = @( "299", "324", "403", "404", "411", "412")
$global:CONST_AUDITS_LINKED = @(500, 501, 502, 503, 510)
$global:CONST_TIMELINE_AUDITS = @(299, 324, 403, 411, 412)

# TODO: PowerShell is not good with JSON objects. Headers should be {}. 

$global:REQUEST_OBJ_TEMPLATE = '{"num": 0,"time": "1/1/0001 12:00:00 AM","protocol": "","host": "","method": "","url": "","query": "","useragent": "","server": "","clientip": "","contlen": 0,"headers": [],"tokens": [],"ver": "1.0"}'
$global:RESPONSE_OBJ_TEMPLATE = '{"num": 0,"time": "1/1/0001 12:00:00 AM","result": "","headers": {},"tokens": [],"ver": "1.0"}'
$global:ANALYSIS_OBJ_TEMPLATE = '{"requests": [],"responses": [],"errors": [],"timeline": [],"ver": "1.0"}'
$global:ERROR_OBJ_TEMPLATE = '{"time": "1/1/0001 12:00:00 AM","eventid": 0,"level": "", "message": [],"ver": "1.0"}'
$global:TIMELINE_OBJ_TEMPLATE = '{"time": "","type": "", "tokentype": "", "rp": "","result": "","stage": 0,"ver": "1.0"}'
$global:TOKEN_OBJ_TEMPLATE = '{"num": 0,"type": "","rp": "","user": "","direction": "","claims": [],"oboclaims": [],"actasclaims": [],"ver": "1.0"}'

$global:TIMELINE_INCOMING = "incoming"
$global:TIMELINE_AUTHENTICATION = "authn"
$global:TIMELINE_AUTHORIZATION = "authz"
$global:TIMELINE_ISSUANCE = "issuance"
$global:TIMELINE_SUCCESS = "success"
$global:TIMELINE_FAILURE = "fail"

$global:TOKEN_TYPE_ACCESS = "access_token"

$global:CONST_ADFS_HTTP_PORT = 0
$global:CONST_ADFS_HTTPS_PORT = 0

$global:DidLoadPorts = $false
$global:DidLoadJson = $true






# ----------------------------------------------------
#
# Helper Functions - Querying 
#
# ----------------------------------------------------

function MakeQuery
{

    <#

    .DESCRIPTION
    Performs a log search query to a remote machine, using remote PowerShell, and Get-WinEvent

    #>

    param(
    [parameter(Mandatory=$True)]
    [string]$Query,

    [Parameter(Mandatory=$True)]
    [string]$Log,

    [Parameter(Mandatory=$True)]
    [System.Management.Automation.Runspaces.PSSession]$Session,

    [parameter(Mandatory=$false)]
    [string]$FilePath,

    [parameter(Mandatory=$false)]
    [bool]$ByTime,
    
    [parameter(Mandatory=$false)]
    [DateTime]$Start = (Get-Date),
    
    [parameter(Mandatory=$false)]
    [DateTime]$End = (Get-Date),

    [parameter(Mandatory=$false)]
    [bool]$IncludeLinkedInstances

    )

    # Get-WinEvent is performed through a remote powershell session to avoid firewall issues that arise from simply passing a computer name to Get-WinEvent  
    Invoke-Command -Session $Session -ArgumentList $Query, $Log, $global:CONST_ADFS_AUDIT, $global:CONST_AUDITS_TO_AGGREGATE, $global:CONST_AUDITS_LINKED, $ByTime, $Start, $End, $FilePath -ScriptBlock {
        param(
        [string]$Query, 
        [string]$Log,
        [string]$providername,
        [object]$auditsToAggregate,
        [object]$auditsWithInstanceIds,
        [bool]$ByTime,
        [DateTime]$Start,
        [DateTime]$End,
        [string]$FilePath)


        # TODO: Perform adjustment for time skew. Check the difference between the current UTC time on this machine,
        #  and the current UTC time on the target machine

        # TODO: Consider checking audits on each machine to determine the behavior level, and then 
        #  keep track of that for event parsing schema 

        #
        # Perform Get-WinEvent call to collect logs 
        #
        if ( $FilePath.Length -gt 0 )
        {   
            $Result = Get-WinEvent -Path $FilePath -FilterXPath $Query -ErrorAction SilentlyContinue -Oldest
        }
        elseif ( $ByTime )
        {
            # Adjust times for zone on specific server
            $TimeZone = [System.TimeZoneInfo]::Local
            $AdjustedStart = [System.TimeZoneInfo]::ConvertTimeFromUtc($Start, $TimeZone)
            $AdjustedEnd = [System.TimeZoneInfo]::ConvertTimeFromUtc($End, $TimeZone)

            # Filtering based on time is more robust when using hashtable filters
            if ( $Log -eq "security" )
            {
                $Result = Get-WinEvent -FilterHashtable @{logname = $Log; providername = $providername; starttime = $AdjustedStart; endtime = $AdjustedEnd} -ErrorAction SilentlyContinue
            }
            else
            {
                $Result = Get-WinEvent -FilterHashtable @{logname = $Log; starttime = $AdjustedStart; endtime = $AdjustedEnd} -ErrorAction SilentlyContinue -Oldest
            }
        }
        else
        {
            $Result = Get-WinEvent -LogName $Log -FilterXPath $Query -ErrorAction SilentlyContinue -Oldest
        }

        #
        # Process results from Get-WinEvent query 
        #
        $instanceIdsToQuery = @()

        foreach ( $Event in $Result )
        {
            # Copy over all properties so they remain accessible when remote session terminates

            $Properties = @()
            foreach ( $Property in $Event.Properties )
            {
                # TODO: BUGBUG - do we need to call .value? Don't we want the full object?
                $Properties += $Property.value
            }
            $Event | Add-Member RemoteProperties $Properties
            
            # Contains activity ID
            if ( $Event.Properties.count -gt 0 )
            {
                $guidRef = [ref] [System.Guid]::NewGuid()
                if ( [System.Guid]::TryParse( $Event.Properties[1].Value, $guidRef ) ) 
                {
                    $Event | Add-Member CorrelationID $Event.Properties[1].Value 
                }
                else
                {
                    # Ensure correlation id is not lost through the serialization process
                    $Event | Add-Member CorrelationID $Event.Properties[0].Value 

                    # TODO: BUGBUG: This will always be the instance ID. Instance ID and Correlation ID are not the same
                }
            }
            else
            {
                # Redundant property. Allows for consistency among all events
                $Event | Add-Member CorrelationID $Event.ActivityID 
            }

            # If we want to include events that are linked by the instance ID, we need to 
            #  generate a list of instance IDs to query on for the current server 
            if ( $IncludeLinkedInstances -or $true )
            {
                if ( $Event.CorrelationID.length -ne 0 )
                {
                    # We only want to collect linked instance data when the correlation ID was provided, 
                    #  otherwise the results could become too large 

                     if ( $auditsToAggregate -contains $Event.Id )
                    {
                        # The instance ID in this event should be used to get more data
                        $instanceID = $Event.Properties[0].Value 
                        $instanceIdsToQuery += $instanceID
                    }
                }
            }
        }

        #
        # If we have instance IDs to collect accross, do that collection now
        #
        if ( $instanceIdsToQuery.Count -gt 0 )
        {
            $eventIdString = ""
            foreach ( $eventID in $auditsWithInstanceIds )
            {
                if ( $eventIdString.Length -gt 0)
                {
                    $eventIdString += " or "
                }

                $eventIdString += "EventID={0}" -f $eventID
            }

            $queryString = ""
            if ( $ByTime ){
                $queryString = "*[System[Provider[@Name='{0}'] and ({1}) and TimeCreated[@SystemTime>='{2}' and @SystemTime<='{3}']]]" -f $providername, $eventIdString, $Start, $End
            }
            else
            {
                $queryString = "*[System[Provider[@Name='{0}'] and ({1})]]" -f $providername, $eventIdString
            }

            # Note: we can do this query for just the local server, because an instance ID will never be written cross-server

            Write-Host $queryString

            $instanceIdResultsRaw = $null
            if ( $FilePath )
            {
                $instanceIdResultsRaw = Get-WinEvent -FilterXPath $queryString -ErrorAction SilentlyContinue -Path $FilePath
            }
            else
            {
                $instanceIdResultsRaw = Get-WinEvent -FilterXPath $queryString -ErrorAction SilentlyContinue
            }

            Write-Host $instanceIdResultsRaw.Count
            
            foreach ( $instanceID in $instanceIdsToQuery )
            {
                foreach ( $instanceEvent in $instanceIdResultsRaw)
                {
                    if ( $instanceID -eq $instanceEvent.Properties[0].Value )
                    {
                        # We have an event that we want 

                        # Copy data of remote params
                        $Properties = @()
                        foreach ( $Property in $instanceEvent.Properties )
                        {
                            # TODO: BUGBUG - do we need to call .value? Don't we want the full object?
                            $Properties += $Property.value
                        }

                        $instanceEvent | Add-Member RemoteProperties $Properties
                        $instanceEvent | Add-Member AdfsInstanceId $instanceEvent.Properties[0].Value

                        $Result += $instanceEvent
                    }                    
                }
            }
        }

        return $Result  
    } 
}

function GetSecurityEvents
{

    <#

    .DESCRIPTION
    Perform a query to get the ADFS Security Events 

    #>

    param(
    [parameter(Mandatory=$False)]
    [string]$CorrID,

    [parameter(Mandatory=$True)]
    [System.Management.Automation.Runspaces.PSSession]$Session,

    [parameter(Mandatory=$false)]
    [bool]$ByTime,
    
    [parameter(Mandatory=$false)]
    [DateTime]$Start,
    
    [parameter(Mandatory=$false)]
    [DateTime]$End,

    [parameter(Mandatory=$false)]
    [bool]$IncludeLinkedInstances,

    [parameter(Mandatory=$false)]
    [string]$FilePath

    )

    if ( $CorrID.length -eq 0 )
    {
        $Query = "*[System[Provider[@Name='{0}' or @Name='{1}' or @Name='{2}']]]" -f $global:CONST_ADFS_ADMIN, $global:CONST_ADFS_AUDIT, $global:CONST_ADFS_DEBUG
    }
    else
    {
        $Query = "*[System[Provider[@Name='{0}' or @Name='{1}' or @Name='{2}']]] and *[EventData[Data and (Data='{3}')]]" -f $global:CONST_ADFS_ADMIN, $global:CONST_ADFS_AUDIT, $global:CONST_ADFS_DEBUG, $CorrID
    }

    # Perform the log query 
    return MakeQuery -Query $Query -Log $global:CONST_SECURITY_LOG -Session $Session -ByTime $ByTime -Start $Start -End $End -IncludeLinkedInstances $IncludeLinkedInstances -FilePath $FilePath
}

function GetAdminEvents
{

    <#

    .DESCRIPTION
    Perform a query to get the ADFS Admin events

    #>

    param(
    [parameter(Mandatory=$False)]
    [string]$CorrID,

    [parameter(Mandatory=$True)]
    [System.Management.Automation.Runspaces.PSSession]$Session,
    
    [parameter(Mandatory=$false)]
    [bool]$ByTime,
    
    [parameter(Mandatory=$false)]
    [DateTime]$Start,

    [parameter(Mandatory=$false)]
    [DateTime]$End, 

    [parameter(Mandatory=$false)]
    [string]$FilePath

    ) 

    # Default to query all 
    $Query = "*"

    if ( $CorrID.length -gt 0 )
    {
        $Query =  "*[System[Correlation[@ActivityID='{$CorrID}']]]"
    }

    return MakeQuery -Query $Query -Log $global:CONST_ADMIN_LOG -Session $Session -ByTime $ByTime -Start $Start -End $End -FilePath $FilePath
}

function GetDebugEvents
{

    <#

    .DESCRIPTION
    Perform a query to get the ADFS Debug logs  

    #>

    param(
    [parameter(Mandatory=$False)]
    [string]$CorrID,

    [parameter(Mandatory=$True)]
    [System.Management.Automation.Runspaces.PSSession]$Session,

    [parameter(Mandatory=$false)]
    [bool]$ByTime,
    
    [parameter(Mandatory=$false)]
    [DateTime]$Start,

    [parameter(Mandatory=$false)]
    [DateTime]$End,

    [parameter(Mandatory=$false)]
    [string]$FilePath

    )

    # Default to query all
    $Query = "*"

    if ( $CorrID.length -gt 0 )
    {
        $Query =  "*[System[Correlation[@ActivityID='{$CorrID}']]]"
    }

    return MakeQuery -Query $Query -Log $global:CONST_DEBUG_LOG -Session $Session -ByTime $ByTime -Start $Start -End $End -FilePath $FilePath
}

function QueryDesiredLogs
{   

    <#

    .DESCRIPTION
    Query for all logs that were requested from the user input 

    #>

    param(
        [parameter(Mandatory=$False)]
        [string]$CorrID,

        [parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [parameter(Mandatory=$false)]
        [bool]$ByTime,
    
        [parameter(Mandatory=$false)]
        [DateTime]$Start,

        [parameter(Mandatory=$false)]
        [DateTime]$End,

        [parameter(Mandatory=$false)]
        [bool]$IncludeLinkedInstances,

        [parameter(Mandatory=$false)]
        [string]$FilePath
    )


    $Events = @()

    if ($Logs -contains $global:CONST_LOG_PARAM_SECURITY)
    {
        $Events += GetSecurityEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End -IncludeLinkedInstances $IncludeLinkedInstances -FilePath $FilePath
    }

    if ($Logs -contains $global:CONST_LOG_PARAM_DEBUG)
    {
        $Events += GetDebugEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End -FilePath $FilePath
    }

    if ($Logs -contains $global:CONST_LOG_PARAM_ADMIN)
    {
        $Events += GetAdminEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End -FilePath $FilePath
    }

    return $Events
}






# ----------------------------------------------------
#
# Helper Functions - JSON Management 
#
# ----------------------------------------------------

function NewObjectFromTemplate
{
    param(
        [parameter(Mandatory=$true)]
        [string]$Template
    )

    return $Template | ConvertFrom-Json
}






# ----------------------------------------------------
#
# Helper Functions - Event Processing 
#
# ----------------------------------------------------

function Process-HeadersFromEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$events
    )

    $longText = ""
    foreach ( $event in $events )
    {
        if ( $event.Id -eq 510 )
        {
            # 510 events are generic "LongText" events. When the LongText that's being 
            #  written is header data (from a 403 or 404), then the schema is: 
            #      instanceID : $event.RemoteProperties[0]
            #      headers_json : $event.RemoteProperties[1...N] (ex. {"Content-Length":"89","Content-Type":"application/x-www-form-urlencoded", etc. } )

            for ( $i=1; $i -le $event.RemoteProperties.Count - 1; $i++ )
            {
                $propValue = $event.RemoteProperties[$i]

                if ( $propValue -ne "-")
                {
                    $longText += $propValue
                }                
            }
        }
    }

    return $longText | ConvertFrom-Json
}

function Get-ClaimsFromEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$event
    )

    $keyValuePair = @()
    for ($i = 1; $i -lt $event.RemoteProperties.Count - 1; $i += 2)
    {
        if ($event.RemoteProperties[$i] -ne "-" -and $event.RemoteProperties[$i + 1] -ne "-" )
        {
            $keyValuePair += @($event.RemoteProperties[$i], $event.RemoteProperties[$i + 1])
        }
    }

    return $keyValuePair
}

function Process-TokensFromEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$event,

        [parameter(Mandatory=$false)]
        [object]$LinkedEvents
    )

    $allTokens = @()

    if ( $event.Id -eq 412)
    {
        $tokenObj = NewObjectFromTemplate -Template $global:TOKEN_OBJ_TEMPLATE
        $claims = @()
        foreach ( $linkedEvent in $LinkedEvents[$event.RemoteProperties[0]] ) #InstanceID
        {
            # Get claims out of event
            $claims += Get-ClaimsFromEvent -event $linkedEvent
        }

        $tokenObj.type = $event.RemoteProperties[2]
        $tokenObj.rp = $event.RemoteProperties[3]
        $tokenObj.direction = "incoming"
        $tokenObj.claims = $claims

        $allTokens += $tokenObj
    }

    if ( $event.Id -eq 324 )
    {
        $tokenObj = NewObjectFromTemplate -Template $global:TOKEN_OBJ_TEMPLATE
        $claims = @()
        foreach ( $linkedEvent in $LinkedEvents[$event.RemoteProperties[0]] ) #InstanceID
        {
            # Get claims out of token 
            $claims += Get-ClaimsFromEvent -event $linkedEvent
        }

        $tokenObj.user = $event.RemoteProperties[2]
        $tokenObj.rp = $event.RemoteProperties[3]
        $tokenObj.direction = "incoming"
        $tokenObj.claims = $claims

        $allTokens += $tokenObj
    }

    if ( $event.Id -eq 299 )
    {
        $tokenObjIn = NewObjectFromTemplate -Template $global:TOKEN_OBJ_TEMPLATE
        $tokenObjOut = NewObjectFromTemplate -Template $global:TOKEN_OBJ_TEMPLATE

        $claimsIn = @()
        $claimsOut = @()

        foreach ( $linkedEvent in $LinkedEvents[$event.RemoteProperties[0]] ) #InstanceID
        {
            if ( $linkedEvent.Id -eq 500 )
            {
                # Issued claims
                $claimsOut += Get-ClaimsFromEvent -event $linkedEvent
            }

            if ( $linkedEvent.Id -eq 501 )
            {
                # Caller claims
                $claimsIn += Get-ClaimsFromEvent -event $linkedEvent
            }

            # Get claims out of token 
        }

        $tokenObjOut.rp = $event.RemoteProperties[2]
        $tokenObjOut.direction = "outgoing"

        $tokenObjIn.claims = $claimsIn
        $tokenObjOut.claims = $claimsOut

        $allTokens += $tokenObjIn
        $allTokens += $tokenObjOut
    }

    return $allTokens
}


function Generate-ErrorEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$event
    )

    $errorObj = NewObjectFromTemplate -Template $global:ERROR_OBJ_TEMPLATE
    $errorObj.time = $event.TimeCreated
    $errorObj.eventid = $event.Id
    $errorObj.message = $event.Message
    $errorObj.level = $event.LevelDisplayName

    return $errorObj
}

function Generate-ResponseEvent
{
    param(
        [parameter(Mandatory=$false)]
        [object]$event,

        [parameter(Mandatory=$true)]
        [int]$requestCount,

        [parameter(Mandatory=$false)]
        [object]$LinkedEvents
    )

    $response = NewObjectFromTemplate -Template $global:RESPONSE_OBJ_TEMPLATE
    $response.num = $requestCount

    # Return an empty response object if we don't have data to use 
    if ( $event.length -eq 0 )
    {
        return $response
    }

    $response.time = $event.RemoteProperties[2] #Datetime
    # "{Status code} {status_description}""
    $response.result = "{0} {1}" -f $event.RemoteProperties[3], $event.RemoteProperties[4] 

    $headerEvent = $LinkedEvents[$event.RemoteProperties[0]] #InstanceID
    $headersObj = Process-HeadersFromEvent -events $headerEvent
    $response.headers = $headersObj

    return $response
}


function Generate-RequestEvent
{
    param(
        [parameter(Mandatory=$false)]
        [object]$event,

        [parameter(Mandatory=$true)]
        [int]$requestCount,

        [parameter(Mandatory=$false)]
        [object]$LinkedEvents
    )

    # TODO: This is the schema for ADFS 2016
    # Need to adjust for 2012R2 

    $currentRequest = NewObjectFromTemplate -Template $global:REQUEST_OBJ_TEMPLATE
    $currentRequest.num = $requestCount

    # Return an empty request object if we don't have data to use 
    if ( -not $event )
    {
        return $currentRequest
    }

    $currentRequest.time = $event.RemoteProperties[2]  #Date
    $currentRequest.clientip = $event.RemoteProperties[3]  #ClientIP
    $currentRequest.method = $event.RemoteProperties[4]  #HTTP_Method
    $currentRequest.url = $event.RemoteProperties[5]  #URL
    $currentRequest.query = $event.RemoteProperties[6]  #QueryString
    $currentRequest.useragent = $event.RemoteProperties[9]  #UserAgent
    $currentRequest.contlen = $event.RemoteProperties[10]  #ContentLength
    $currentRequest.server = $event.MachineName

    $headerEvent = $LinkedEvents[$event.RemoteProperties[0]] #InstanceID
    $headersObj = Process-HeadersFromEvent -events $headerEvent
    $currentRequest.headers = $headersObj

    # Load the HTTP and HTTPS ports, if we haven't already 
    # We need these to convert the 'LocalPort' field in the 403 audit
    if (-not $global:DidLoadPorts)
    {
        $global:CONST_ADFS_HTTP_PORT = (Get-AdfsProperties).HttpPort
        $global:CONST_ADFS_HTTPS_PORT = (Get-AdfsProperties).HttpsPort
        $global:DidLoadPorts = $true 
    }
             
    if ( $event.RemoteProperties[7] -eq $global:CONST_ADFS_HTTP_PORT)
    {
        $currentRequest.protocol = "HTTP"
    }

    if ( $event.RemoteProperties[7] -eq $global:CONST_ADFS_HTTPS_PORT)
    {
        $currentRequest.protocol = "HTTPS"
    }

    return $currentRequest 
}

function Update-ResponseEvent
{
    param(
        [parameter(Mandatory=$false)]
        [object]$event,

        [parameter(Mandatory=$true)]
        [object]$responseEvent,

        [parameter(Mandatory=$false)]
        [object]$LinkedEvents
    )

    if ( $event.Id -eq 404 )
    {
        $responseEvent.time = $event.RemoteProperties[2] #Datetime
        # "{Status code} {status_description}""
        $responseEvent.result = "{0} {1}" -f $event.RemoteProperties[3], $event.RemoteProperties[4] 

        $headerEvent = $LinkedEvents[$event.RemoteProperties[0]] #InstanceID
        $headersObj = Process-HeadersFromEvent -events $headerEvent
        $responseEvent.headers = $headersObj

        return $responseEvent
    }

    if ( $event.Id -eq 299 )
    {

    }
}

function Generate-TimelineEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$event
    )

    $timelineEvent = NewObjectFromTemplate -Template $global:TIMELINE_OBJ_TEMPLATE
    $timelineEvent.time = $event.TimeCreated
    
    # 403 - request received
    if ( $event.Id -eq 403 )
    {
        $timelineEvent.type = $global:TIMELINE_INCOMING
        $timelineEvent.result = $global:TIMELINE_SUCCESS
        return $timelineEvent
    }       
    
    # 411 - token validation failure 
    if ( $event.Id -eq 411 )
    {    
        $timelineEvent.type = $global:TIMELINE_AUTHENTICATION
        $timelineEvent.result = $global:TIMELINE_FAILURE
        $timelineEvent.tokentype = $event.RemoteProperties[1] #Token Type
        return $timelineEvent
    }

    # 412 - authentication success 
    if ( $event.Id -eq 412 )
    {
        $timelineEvent.type = $global:TIMELINE_AUTHENTICATION
        $timelineEvent.result = $global:TIMELINE_SUCCESS
        $timelineEvent.tokentype = $event.RemoteProperties[2] #Token Type
        $timelineEvent.rp = $event.RemoteProperties[3] #RP
        return $timelineEvent
    }

    # 324 - authorization failure 
    if ( $event.Id -eq 324 )
    {
        $timelineEvent.type = $global:TIMELINE_AUTHORIZATION
        $timelineEvent.result = $global:TIMELINE_FAILURE
        $timelineEvent.rp = $event.RemoteProperties[3] #RP
        return $timelineEvent
    }

    # 299 - token issuance success
    if ( $event.Id -eq 299 )
    {
        $timelineEvent.type = $global:TIMELINE_ISSUANCE
        $timelineEvent.result = $global:TIMELINE_SUCCESS
        $timelineEvent.rp = $event.RemoteProperties[2] #RP
        $timelineEvent.tokentype = $global:TOKEN_TYPE_ACCESS
        return $timelineEvent
    }

    return $timelineEvent
}

function Process-EventsForAnalysis
{
    param(
        [parameter(Mandatory=$true)]
        [object]$events
    )

    # TODO: Validate that all events have the same correlation ID, or no correlation ID 

    # Validate that the events are sorted by time 
    $events = $events | Sort-Object TimeCreated 

    $requestCount = 0
    $mapRequestNumToObjects = @{} 
    $allErrors = @()
    $allTimeline = @()
    $timelineIncomingMarked = $false
    $LinkedEvents = @{}

    # Do a pre-pass through the events set to generate 
    #  a hashtable of instance IDs to their events 
    foreach ( $event in $events )
    {
        if ( $event.AdfsInstanceId )
        {
            if ( $LinkedEvents.Contains( $event.AdfsInstanceId ) ) 
            {
                # Add event to exisiting list
                $LinkedEvents[$event.AdfsInstanceId] += $event
            }
            else
            {
                # Add instance ID and fist event to hashtable
                $LinkedEvents[$event.AdfsInstanceId] = @() + $event 
            }   
        }
    }

    #
    # Do a second pass through the events to collect all the data we need for analysis 
    #
    foreach ( $event in $events )
    {
        # Error or warning. We use 'Level' int to avoid localization issues  
        if ( ($event.Level -eq 2 ) -or ($event.Level -eq 3 )  -or ($event.Level -eq 16 ))
        {
            # TODO: BUGBUG - will 411's show up as error events? Will any failure audit? Level is 16 for 411
            $allErrors += Generate-ErrorEvent -event $event 
        }

        # If this event signals a timeline event, generate it 
        if ( $event.Id -in $global:CONST_TIMELINE_AUDITS)
        {
            if( $event.Id -ne 403 -or -not $timelineIncomingMarked )
            {
                # We only want to include one 403 timeline event
                $allTimeline += Generate-TimelineEvent -event $event 
            }
        }

        # 411 - token validation failure 
        if ( $event.Id -eq 411 )
        {
            # TODO: Use for error 
        }

        # 412 - authentication success or 324 - authorization failure 
        if ( $event.Id -eq 412 -or $event.Id -eq 324 )
        {
            # Use this for caller identity on request object            
            $tokenObj = Process-TokensFromEvent -event $event -LinkedEvents $LinkedEvents
            $tokenObj[0].num = $requestCount  

            $currentRequest = $mapRequestNumToObjects[$requestCount][0] 
            $currentRequest.tokens += $tokenObj[0]
        }

        # 299 - token issuance success
        if ( $event.Id -eq 299 )
        {
            $tokenObj = Process-TokensFromEvent -event $event -LinkedEvents $LinkedEvents
            $tokenObj[0].num = $requestCount  
            $tokenObj[1].num = $requestCount

            $currentRequest = $mapRequestNumToObjects[$requestCount][0] 
            $currentRequest.tokens += $tokenObj[0]

            $currentResponse = $mapRequestNumToObjects[$requestCount][1] 
            $currentResponse.tokens += $tokenObj[1]
        }

        # 403 - request received
        if ( $event.Id -eq 403 )
        {
            # We have a new request, so generate a request/response pair, and store it 

            if ( $mapRequestNumToObjects[$requestCount] -ne $null -and $mapRequestNumToObjects[$requestCount].Count -gt 0 )
            {
                # We have a previous request in the pipeline. Finalize that request
                $requestCount += 1
            }
            
            $currentRequest = Generate-RequestEvent -event $event -requestCount $requestCount -LinkedEvents $LinkedEvents
            $currentResponse = Generate-ResponseEvent -requestCount $requestCount
            $mapRequestNumToObjects[$requestCount] = @($currentRequest, $currentResponse)
        }
        
        # 404 - response sent 
        if ( $event.Id -eq 404 )
        {
            if ( $mapRequestNumToObjects[$requestCount] -eq $null -or $mapRequestNumToObjects[$requestCount].Count -eq 0 )
            {
                # We have a response, but no request yet. Create the request/response pair 
                $currentRequest = Generate-RequestEvent -requestCount $requestCount
                $currentResponse = Generate-ResponseEvent -event $event -requestCount $requestCount -LinkedEvents $LinkedEvents 
                $mapRequestNumToObjects[$requestCount] = @($currentRequest, $currentResponse)
                #$requestCount += 1
            }
            else
            {
                $currentResponse = $mapRequestNumToObjects[$requestCount][1]
                $updatedResponse = Update-ResponseEvent -event $event -responseEvent $currentResponse -LinkedEvents $LinkedEvents 
                $mapRequestNumToObjects[$requestCount][1] = $updatedResponse
            }

            # We do not mark a request/response pair as complete until we have a new request come in, 
            #  since we sometimes see events after the 404 (token issuance, etc.) 
        }
    }

    #
    # Generate the complete analysis JSON object 
    #    
    $analysisObj = NewObjectFromTemplate -Template $global:ANALYSIS_OBJ_TEMPLATE

    $allRequests = @()
    $allResponses = @()
    foreach ( $requestKey in $mapRequestNumToObjects.keys )
    {
        $allRequests += $mapRequestNumToObjects[$requestKey][0]
        $allResponses += $mapRequestNumToObjects[$requestKey][1]
    } 

    $analysisObj.requests = $allRequests
    $analysisObj.responses = $allResponses
    $analysisObj.errors = $allErrors
    $analysisObj.timeline = $allTimeline

    return $analysisObj
}

function AggregateOutputObject
{
    param(
    [parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$CorrID,

    [parameter(Mandatory=$true,Position=1)]
    [AllowEmptyCollection()]
    [PSObject[]]$Events,

    [parameter(Mandatory=$true,Position=2)]
    [AllowEmptyCollection()]
    [PSObject]$Data)

     $Output = New-Object PSObject -Property @{
        "CorrelationID" = $CorrID
        "Events" = $Events
        "AnalysisData" = $Data
    }

    Write-Output $Output
    return $Output
}






# ----------------------------------------------------
#
# Exported Functions 
# 
# ----------------------------------------------------

function Write-ADFSEventsSummary
{
    <#

    .DESCRIPTION
    This cmdlet consumes a piped-in list of Event objects, and produces a summary table
    of the relevant data from the request. 

    Note: this function should only be used on a list of Event objects that all contain 
    the same correlation ID (i.e. all of the events are from the same user request) 

    #>

    # Create Table object
    $table = New-Object system.Data.DataTable "SummaryTable"

    # Define Columns
    $col1 = New-Object system.Data.DataColumn Time,([string])
    $col2 = New-Object System.Data.DataColumn Level,([string])
    $col3 = New-Object system.Data.DataColumn EventID,([string])
    $col4 = New-Object system.Data.DataColumn Details,([string])
    $col5 = New-Object system.Data.DataColumn CorrelationID,([string])
    $col6 = New-Object system.Data.DataColumn Machine,([string])
    $col7 = New-Object system.Data.DataColumn Log,([string])
    $table.columns.add( $col1 )
    $table.columns.add( $col2 )
    $table.columns.add( $col3 )
    $table.columns.add( $col4 )
    $table.columns.add( $col5 )
    $table.columns.add( $col6 )
    $table.columns.add( $col7 )

    foreach($Event in $input.Events)
    {
        #Create a row
        $row = $table.NewRow()

        $row.Time = $Event.TimeCreated
        $row.EventID = $Event.Id
        $row.Details = $Event.Message
        $row.CorrelationID = $Event.CorrelationID
        $row.Machine = $Event.MachineName
        $row.Log = $Event.LogName
	    $row.Level = $Event.LevelDisplayName

        #Add the row to the table
        $table.Rows.Add($row)    

    }

    return $table
}


function Get-ADFSEvents
{

    <#

    .SYNOPSIS
    This script gathers ADFS related events from the security, admin, and debug logs into a single file, 
    and allows the user to reconstruct the HTTP request/response headers from the logs.

    .DESCRIPTION
    Given a correlation id, the script will gather all events with the same identifier and reconstruct the request
    and response headers if they exist. Using the 'All' option (either with or without headers enabled) will first collect
    all correlation ids and proceed to gather the events for each. If start and end times are provided, all events 
    that fall into that span will be returned. The start and end times will be assumed to be base times. That is, all
    time conversions will be based on the UTC of these values.

    .EXAMPLE
    Get-ADFSEvents -Logs Security, Admin, Debug -CorrelationID 669bced6-d6ae-4e69-889b-09ceb8db78c9 -Server LocalHost, MyServer
    .Example
    Get-ADFSEvents -CorrelationID 669bced6-d6ae-4e69-889b-09ceb8db78c9 -Headers
    .EXAMPLE
    Get-ADFSEvents -Logs Admin -All 
    .EXAMPLE
    Get-ADFSEvents -Logs Debug, Security -All -Headers -Server LocalHost, Server1, Server2
    .Example
    Get-ADFSEvents -Logs Debug -StartTime (Get-Date -Date ("2017-09-14T18:37:26.910168700Z"))  -EndTime (Get-Date) -Headers

    #>

    # Provide either correlation id, 'All' parameter, or time range along with logs to be queried and list of remote servers
    [CmdletBinding(DefaultParameterSetName='CorrelationIDParameterSet')]
    param(
    [parameter(Mandatory=$false, Position=0)]
    [ValidateSet("Admin", "Debug", "Security")]
    [string[]]$Logs = @("Security","Admin"),

    [parameter(Mandatory=$true, Position=1, ParameterSetName="CorrelationIDParameterSet")]
    [ValidateNotNullOrEmpty()]
    [string]$CorrelationID,

    [parameter(Mandatory=$true, Position=1, ParameterSetName="AllEventsSet")]
    [switch]$All,

    [parameter(Mandatory=$true, Position=1, ParameterSetName="AllEventsByTimeSet")]
    [DateTime]$StartTime,

    [parameter(Mandatory=$true, Position=2, ParameterSetName="AllEventsByTimeSet")]
    [DateTime]$EndTime,

    [parameter(Mandatory=$false)]
    [switch]$CreateAnalysisData,

    [parameter(Mandatory=$false, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
    [string[]]$Server="LocalHost",

    [parameter(Mandatory=$false, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
    [string]$FilePath
    )

    # TODO: Add warning if environment is not Win2016
    if ($Server -eq "*")
    {
        $Server = @()
        $nodes = (Get-AdfsFarmInformation).FarmNodes
        foreach( $server in $nodes)
        {
            $Server += $server
        }
    }
    
    $ServerList = @()
    
    # Validate Correlation ID is a valid GUID
    $guidRef = [ref] [System.Guid]::NewGuid()
    if ( $CorrelationID.length -eq 0 -or ![System.Guid]::TryParse( $CorrelationID, $guidRef ) ){ 
        Write-Error "Invalid Correlation ID. Please provide a valid GUID."
        Break
    }

    # Validate timing parameters 
    if ( $StartTime -ne $null -and $EndTime -ne $null )
    {
        if ( $EndTime -lt $StartTime )
        {
            $temp = $StartTime
            $StartTime = $EndTime
            $EndTime = $temp
            Write-Warning "The EndTime provided is earlier than the StartTime. Swapping time parameters and continuing."
        }

        $ByTime = $true
    }
    else
    {
        $ByTime = $false
        
        # Set values to prevent binding issues when passing parameters
        $StartTime = Get-Date
        $EndTime = Get-Date
    }

    if ( $CreateAnalysisData )
    {
        if ($global:DidLoadJson -eq $false)
        {
            LoadJson

            if ($global:DidLoadJson -eq $false)
            {
                Write-Error "Failed to load data templates. Creating JSON objects will likely fail."
            }
        } 
    }
    
    # Iterate through each server, and collect the required logs
    foreach ( $Machine in $Server )
    {
        $Events = @()
        $includeLinks = $false
        if ( $CreateAnalysisData )
        {
            $includeLinks = $true
        }

        Try
        {
            $Session = New-PSSession -ComputerName $Machine
            $Events += QueryDesiredLogs -CorrID $CorrelationID -Session $Session -ByTime $ByTime -Start $StartTime.ToUniversalTime() -End $EndTime.ToUniversalTime() -IncludeLinkedInstances $includeLinks -FilePath $FilePath
        }
        Catch
        {
            Write-Warning "Error collecting events from $Machine. Error: $_"
        }
        Finally
        {
            if ( $Session )
            {
                Remove-PSSession $Session
            }
        }
    }

    $EventsByCorrId = @{}
    # Collect events by correlation ID, and store in a hashtable      
    foreach ( $Event in $Events )
    {
        $ID = [string] $Event.CorrelationID

        # TODO: BUGBUG - Why are we doing this?
        if($CorrelationID -ne "" -and $CorrelationID -ne $ID)
        {
            continue #Unrelated event mentioned correlation id in data blob
        }
                
        if(![string]::IsNullOrEmpty($ID) -and $EventsByCorrId.Contains($ID)) 
        {
            # Add event to exisiting list
            $EventsByCorrId.$ID =  $EventsByCorrId.$ID + $Event
        }
        elseif(![string]::IsNullOrEmpty($ID))
        {
            # Add correlation ID and fist event to hashtable
            $EventsByCorrId.$ID = @() + $Event 
        }
    }

    $dataObj = $null
    if ( $CreateAnalysisData )
    {
        $dataObj = Process-EventsForAnalysis -events $Events
    }

    return AggregateOutputObject -Data $dataObj -Events $EventsByCorrId[$CorrelationID] -CorrID $CorrelationID
}

#
# Export the appropriate modules 
#
Export-ModuleMember -Function Get-ADFSEvents
Export-ModuleMember -Function Write-ADFSEventsSummary