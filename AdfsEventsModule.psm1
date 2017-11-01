# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# ----------------------------------------------------
#
# Global Constants
#
# ----------------------------------------------------

$CONST_ADFS_ADMIN = "AD FS"
$CONST_ADFS_AUDIT = "AD FS Auditing"
$CONST_ADFS_DEBUG = "AD FS Tracing"

$CONST_SECURITY_LOG = "security"
$CONST_ADMIN_LOG = "AD FS/Admin"
$CONST_DEBUG_LOG = "AD FS Tracing/Debug"

$CONST_LOG_PARAM_SECURITY = "security"
$CONST_LOG_PARAM_ADMIN = "admin"
$CONST_LOG_PARAM_DEBUG = "debug"

$CONST_QUERY_EVENTID = "System/EventID"
$CONST_QUERY_OR_JOIN = " or " 

$CONST_AUDITS_TO_AGGREGATE = @(299, 324, 403, 404, 411, 412)
$CONST_AUDITS_LINKED = @(500, 501, 502, 503, 510)
$CONST_TIMELINE_AUDITS = @(299, 324, 403, 411, 412)

$REQUEST_OBJ_TEMPLATE = ""
$RESPONSE_OBJ_TEMPLATE = ""
$ANALYSIS_OBJ_TEMPLATE = ""
$ERROR_OBJ_TEMPLATE = ""
$TIMELINE_OBJ_TEMPLATE = ""
$TOKEN_OBJ_TEMPLATE = ""

$TIMELINE_INCOMING = "incoming"
$TIMELINE_AUTHENTICATION = "authn"
$TIMELINE_AUTHORIZATION = "authz"
$TIMELINE_ISSUANCE = "issuance"
$TIMELINE_SUCCESS = "success"
$TIMELINE_FAILURE = "fail"

$TOKEN_TYPE_ACCESS = "access_token"

$CONST_ADFS_HTTP_PORT = 0
$CONST_ADFS_HTTPS_PORT = 0

$DidLoadPorts = $false
$DidLoadJson = $false


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
    [switch]$CopyAllProperties,

    [parameter(Mandatory=$false)]
    [bool]$ByTime,
    
    [parameter(Mandatory=$false)]
    [DateTime]$Start = (Get-Date),
    
    [parameter(Mandatory=$false)]
    [DateTime]$End = (Get-Date))

    # Get-WinEvent is performed through a remote powershell session to avoid firewall issues that arise from simply passing a computer name to Get-WinEvent  
    Invoke-Command -Session $Session -ArgumentList $Query, $Log, $CopyAllProperties, $ByTime, $Start, $End -ScriptBlock {
        param(
        [string]$Query, 
        [string]$Log,
        [bool]$CopyAllProperties,
        [bool]$ByTime,
        [DateTime]$Start,
        [DateTime]$End)


        # TODO: Perform adjustment for time skew. Check the difference between the current UTC time on this machine,
        #  and the current UTC time on the target machine


        #
        # Perform Get-WinEvent call to collect logs 
        #
        if ( $ByTime )
        {
            # Adjust times for zone on specific server
            $TimeZone = [System.TimeZoneInfo]::Local
            $AdjustedStart = [System.TimeZoneInfo]::ConvertTimeFromUtc($Start, $TimeZone)
            $AdjustedEnd = [System.TimeZoneInfo]::ConvertTimeFromUtc($End, $TimeZone)

            # Filtering based on time is more robust when using hashtable filters
            if ( $Log -eq "security" )
            {
                $Result = Get-WinEvent -FilterHashtable @{logname = $Log; providername = $CONST_ADFS_AUDIT; starttime = $AdjustedStart; endtime = $AdjustedEnd} -ErrorAction SilentlyContinue
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
            if ( $CopyAllProperties ) 
            {
                $Properties = @()
                foreach ( $Property in $Event.Properties )
                {
                    # TODO: BUGBUG - do we need to call .value? Don't we want the full object?
                    $Properties += $Property.value
                }
                $Event | Add-Member RemoteProperties $Properties
            }
            elseif ( $Log -eq $CONST_SECURITY_LOG ) # TODO: BUGBUG - why is this an elseif?
            {
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
            }
            else
            {
                # Redundant property. Allows for consistency among all events
                $Event | Add-Member CorrelationID $Event.ActivityID 
            }

            # If we want to include events that are linked by the instance ID, we need to 
            #  generate a list of instance IDs to query on for the current server 
            if ( $IncludeLinkedInstances )
            {
                if ( $Event.CorrelationID.length -ne 0 )
                {
                    # We only want to collect linked instance data when the correlation ID was provided, 
                    #  otherwise the results could become too large 

                    if ( $CONST_AUDITS_TO_AGGREGATE -contains $Event.Id )
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
        if ( $instanceIdsToQuery.count -gt 0 )
        {
            foreach ( $eventID in $CONST_AUDITS_LINKED )
            {
                # Note: we can do this query for just the local server, because an instance ID will never be written cross-server

                # TODO: BUGBUG: Adjust this to use (System/EventID=403 or System/EventID = 404) 

                $instanceIdResultsRaw = Get-WinEvent -FilterHashtable @{logname = $Log; providername = $CONST_ADFS_AUDIT; Id = $eventID } -ErrorAction SilentlyContinue

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
    [bool]$IncludeLinkedInstances)

    if ( $CorrID.length -eq 0 )
    {
        $Query = "*[System[Provider[@Name='{0}' or @Name='{1}' or @Name='{2}']]]" -f $CONST_ADFS_ADMIN, $CONST_ADFS_AUDIT, $CONST_ADFS_DEBUG
    }
    else
    {
        $Query = "*[System[Provider[@Name='{0}' or @Name='{1}' or @Name='{2}']]] and *[EventData[Data and (Data='{3}')]]" -f $CONST_ADFS_ADMIN, $CONST_ADFS_AUDIT, $CONST_ADFS_DEBUG, $CorrID
    }

    # Perform the log query 
    $result = MakeQuery -Query $Query -Log $CONST_SECURITY_LOG -Session $Session -ByTime $ByTime -Start $Start -End $End -IncludeLinkedInstances
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
    [DateTime]$End) 

    # Default to query all 
    $Query = "*"

    if ( $CorrID.length -gt 0 )
    {
        $Query =  "*[System[Correlation[@ActivityID='{$CorrID}']]]"
    }

    MakeQuery -Query $Query -Log $CONST_ADMIN_LOG -Session $Session -ByTime $ByTime -Start $Start -End $End
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
    [DateTime]$End)

    # Default to query all
    $Query = "*"

    if ( $CorrID.length -gt 0 )
    {
        $Query =  "*[System[Correlation[@ActivityID='{$CorrID}']]]"
    }

    MakeQuery -Query $Query -Log $CONST_DEBUG_LOG -Session $Session -ByTime $ByTime -Start $Start -End $End
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
        [bool]$IncludeLinkedInstances
    )


    $Events = @()

    if ($Logs -contains $CONST_LOG_PARAM_SECURITY)
    {
        $Events += GetSecurityEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End -IncludeLinkedInstances $IncludeLinkedInstances
    }

    if ($Logs -contains $CONST_LOG_PARAM_DEBUG)
    {
        $Events += GetDebugEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End
    }

    if ($Logs -contains $CONST_LOG_PARAM_ADMIN)
    {
        $Events += GetAdminEvents -CorrID $CorrID -Session $Session -ByTime $ByTime -Start $Start -End $End
    }

    return $Events
}













# ----------------------------------------------------
#
# Helper Functions - JSON Management 
#
# ----------------------------------------------------

function LoadJson
{
    $REQUEST_OBJ_TEMPLATE = Get-Content -Raw -Path "data_templates/requestObjTemplate.json"
    $RESPONSE_OBJ_TEMPLATE = Get-Content -Raw -Path "data_templates/responseObjTemplate.json"
    $ANALYSIS_OBJ_TEMPLATE = Get-Content -Raw -Path "data_templates/analysisObjTemplate.json"
    $ERROR_OBJ_TEMPLATE = Get-Content -Raw -Path "data_templates/errorObjTemplate.json"
    $TIMELINE_OBJ_TEMPLATE = Get-Content -Raw -Path "data_templates/timelineObjTemplate.json"
    $TOKEN_OBJ_TEMPLATE = Get-Content -Raw -Path "data_templates/tokenObjTemplate.json"
    $DidLoadJson = $true
}

function NewObjectFromTemplate
{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Template
    )

    if ($DidLoadJson -eq $false)
    {
        LoadJson

        if ($DidLoadJson -eq $false)
        {
            Write-Error "Failed to load data templates. Could not create a new JSON object."
            return
        }
    }

    return $template | ConvertFrom-Json
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

    foreach ( $event in $events )
    {
        if ( $event.Id -eq 510 )
        {
            # 510 events are generic "LongText" events. When the LongText that's being 
            #  written is header data (from a 403 or 404), then the schema is: 
            #      instanceID : $event.Properties[0]
            #      headers_json : $event.Properties[1] (ex. {"Content-Length":"89","Content-Type":"application/x-www-form-urlencoded", etc. } )
            #      empty : all other fields 

            # Note: we return on the first find, because there should only ever be one 510 headers event per 403 request and 
            #  one 510 headers event per 404 response
            return $event.Properties[1] | ConverFrom-Json
        }
    }
}

function Generate-ErrorEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$event
    )

    $errorObj = NewObjectFromTemplate -Template $ERROR_OBJ_TEMPLATE
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

    $response = NewObjectFromTemplate -Template $RESPONSE_OBJ_TEMPLATE
    $response.num = $requestCount

    # Return an empty response object if we don't have data to use 
    if ( $event.length -eq 0 )
    {
        return $response
    }

    $response.time = $event.Properties[2] #Datetime
    # "{Status code} {status_description}""
    $response.result = "{0} {1}" -f $event.Properties[3], $event.Properties[4] 
            
    $headerEvent = $LinkedEvents[$event.Properties[0]] #InstanceID
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

    # Un-used data from event 
    #$event.Properties[7]  #LocalPort
    #$event.Properties[8]  #LocalIP
    #$event.Properties[11]  #Caller Identity
    #$event.Properties[12]  #Cert identity
    #$event.Properties[13]  #RP
    #$event.Properties[14]  #ThroughProxy
    #$event.Properties[15]  #Proxy DNS

    $currentRequest = NewObjectFromTemplate -Template $REQUEST_OBJ_TEMPLATE
    $currentRequest.num = $requestCount

    # Return an empty request object if we don't have data to use 
    if ( $event.length -eq 0 )
    {
        return $currentRequest
    }

    $currentRequest.time = $event.Properties[2]  #Date
    $currentRequest.clientip = $event.Properties[3]  #ClientIP
    $currentRequest.method = $event.Properties[4]  #HTTP_Method
    $currentRequest.url = $event.Properties[5]  #URL
    $currentRequest.query = $event.Properties[6]  #QueryString
    $currentRequest.useragent = $event.Properties[9]  #UserAgent
    $currentRequest.contlen = $event.Properties[10]  #ContentLength
    $currentRequest.server = $event.MachineName

    $headerEvent = $LinkedEvents[$event.Properties[0]] #InstanceID
    $headersObj = Process-HeadersFromEvent -events $headerEvent
    $currentRequest.headers = $headersObj

    # Load the HTTP and HTTPS ports, if we haven't already 
    # We need these to convert the 'LocalPort' field in the 403 audit
    if (-not $DidLoadPorts)
    {
        $CONST_ADFS_HTTP_PORT = (Get-AdfsProperties).HttpPort
        $CONST_ADFS_HTTPS_PORT = (Get-AdfsProperties).HttpsPort
        $DidLoadPorts = $true 
    }
             
    if ( $event.Properties[7] -eq $CONST_ADFS_HTTP_PORT)
    {
        $currentRequest.protocol = "HTTP"
    }

    if ( $event.Properties[7] -eq $CONST_ADFS_HTTPS_PORT)
    {
        $currentRequest.protocol = "HTTPS"
    }

    return $request 
}

function Generate-TimelineEvent
{
    param(
        [parameter(Mandatory=$true)]
        [object]$event
    )

    $timelineEvent = NewObjectFromTemplate -Template $TIMELINE_OBJ_TEMPLATE
    $timelineEvent.time = $event.TimeCreated
    
    # 403 - request received
    if ( $event.Id -eq 403 )
    {
        $timelineEvent.type = $TIMELINE_INCOMING
        $timelineEvent.result = $TIMELINE_SUCCESS
        return $timelineEvent
    }       
    
    # 411 - token validation failure 
    if ( $event.Id -eq 411 )
    {    
        $timelineEvent.type = $TIMELINE_AUTHENTICATION
        $timelineEvent.result = $TIMELINE_FAILURE
        $timelineEvent.tokentype = $event.Properties[1] #Token Type
        return $timelineEvent
    }

    # 412 - authentication success 
    if ( $event.Id -eq 412 )
    {
        $timelineEvent.type = $TIMELINE_AUTHENTICATION
        $timelineEvent.result = $TIMELINE_SUCCESS
        $timelineEvent.tokentype = $event.Properties[2] #Token Type
        $timelineEvent.rp = $event.Properties[3] #RP
        return $timelineEvent
    }

    # 324 - authorization failure 
    if ( $event.Id -eq 324 )
    {
        $timelineEvent.type = $TIMELINE_AUTHORIZATION
        $timelineEvent.result = $TIMELINE_FAILURE
        $timelineEvent.rp = $event.Properties[3] #RP
        return $timelineEvent
    }

    # 299 - token issuance success
    if ( $event.Id -eq 299 )
    {
        $timelineEvent.type = $TIMELINE_ISSUANCE
        $timelineEvent.result = $TIMELINE_SUCCESS
        $timelineEvent.rp = $event.Properties[2] #RP
        $timelineEvent.tokentype = $TOKEN_TYPE_ACCESS
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

    # TODO: Validate that the events are sorted by time 

    $currentRequest = $null
    $requestCount = -1

    $allRequests = @()
    $allResponses = @()
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
        if ( $event.Id -in $CONST_TIMELINE_AUDITS)
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
            #$event.Properties[2] #Client IP
            #$event.Properties[3] #Error message
            #$event.Properties[4] #Error details
        }

        # 412 - authentication success 
        if ( $event.Id -eq 412 )
        {
            # Use this for caller identity on request object 

            $event.Properties[0] #InstanceID
        }

        # 324 - authorization failure 
        if ( $event.Id -eq 324 )
        {
            $event.Properties[0] #InstanceID
        }

        # 299 - token issuance success
        if ( $event.Id -eq 299 )
        {
            $event.Properties[0] #InstanceID
        }

        # 403 - request received
        if ( $event.Id -eq 403 )
        {

            # We should generate a request/response pair every time we get a 403
            #  and then proceed to fill both as we come accross more audits 

            if ( $currentRequest -ne $null )
            {
                # We already have a request in progress when a new request came in. 
                #  This is due to an ADFS logging bug, which doesn't always return a 404
                #  We will just generate a response and add it 

                $response = NewObjectFromTemplate -Template $RESPONSE_OBJ_TEMPLATE
                $response.num = $requestCount 

                # TODO: Decide how to handle this, since we might still be able to get headers, tokens

                $allRequests += $currentRequest
                $allResponses += $response
                $currentRequest = $null
            }

            $requestCount += 1
            $currentRequest = Generate-RequestEvent -event $event -requestCount $requestCount -LinkedEvents $LinkedEvents 
            

            # TODO: BUGBUG - figure out how to get incoming tokens to add to the request object 
            #$currentRequest.tokens
        }
        
        # 404 - response sent 
        if ( $event.Id -eq 404 )
        {
            if ( $currentRequest -eq $null ){
                # We do not have a request in progress, but we are responding 
                #  This should never happen, but if it does, we will just generate
                #  a request and add it

                $request = NewObjectFromTemplate -Template $REQUEST_OBJ_TEMPLATE
                $requestCount += 1
                $request.num = $requestCount 

                $allRequests += $currentRequest
                $currentRequest = $null
            }

            $response = Generate-ResponseEvent -event $event -requestCount $requestCount -LinkedEvents $LinkedEvents 
            $event.Properties[0] #InstanceID

            #$response.tokens
        }
    }

    #
    # Generate the complete analysis JSON object 
    #
    $analysisObj = NewObjectFromTemplate -Template $ANALYSIS_OBJ_TEMPLATE
    $analysisObj.requests = $allRequests
    $analysisObj.responses = $allResponses
    $analysisObj.errors = $allErrors
    $analysisObj.timeline = $allTimeline

    return $analysisObj
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
    [string[]]$Server="LocalHost"
    )

    # TODO: Add support for querying * for Servers, if environment is Win2016
  
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
    
    # Iterate through each server, and collect the required logs
    foreach ( $Machine in $Server )
    {
        $Events = @()
        Try
        {
            $Session = New-PSSession -ComputerName $Machine
            $Events += QueryDesiredLogs -CorrID $CorrelationID -Session $Session -ByTime $ByTime -Start $StartTime.ToUniversalTime() -End $EndTime.ToUniversalTime() -IncludeLinkedInstances
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

    if ( $CreateAnalysisData )
    {
        $dataObj = Process-EventsForAnalysis -events $Events
    }
}

#
# Export the appropriate modules 
#
Export-ModuleMember -Function Get-ADFSEvents
Export-ModuleMember -Function Write-ADFSEventsSummary
