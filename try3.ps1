<#
This script will 
    1. Get all Permanent role assignments (User/Group & App)
    2. Get all Eligible assignments  (User/Group)
    3. Export all group members thast have a role assigned either Permanent or Eligible
    4. Export all admin users - searches on displayname contains admin 
Requires a cdv called tenants.csv in hte script root
Rows 
    1. Name	= name you wish to give this tenant, just used in cav
    2. TenantName	- name of tenant for connecting to 
    3. AppID	- app registration id
    4. AppSecret - app secret
#>

# Initialise the arrays
$AzurerAdminGroup = @()
$AzurerAdmin  = @()
$AzureuserAdminArray  = @()

# Import the cav
$Tenants = import-csv  "$($PSScriptRoot)\tenants.csv"

# Format date and foormatoutput files
$date = get-date -Format dd-MM-yyyy--HH-mm
$UseOut= "$($PSScriptRoot)\Azure-Admin-Reports-$($date).csv"
$GroupOut = "$($PSScriptRoot)\Azure-Admin-Group-Reports-$($date).csv"
$AzureuserAdminArrayOut = "$($PSScriptRoot)\Azure-Admin-Users-Reports-$($date).csv"
$UriRoot = "https://graph.microsoft.com/v1.0"

# start the loop through the csv
ForEach($Tenant in $Tenants)
    {
    write-host -ForegroundColor green "Starting to process $($Tenant.TenantName) ...."
    # setup the variables to use in this run
    $clientID = $Tenant.AppID
    $tenantName = $Tenant.TenantName
    $ClientSecret = $Tenant.AppSecret
    
    # Create a hash table for the token request
    $ReqTokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        client_Id     = $clientID
        Client_Secret = $clientSecret
    } 
    # Go get the token
    $TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody

    # Create the headers
    $headers = @{
    Authorization = "Bearer $($Tokenresponse.access_token)"
    ConsistencyLevel="eventual"
    }

    # format the uri we will use to get teh directory roles
    $uri = ("/{0}/directoryRoles" -f $UriRoot)

    # If the result is more than 999, we need to read the @odata.nextLink to show more than one side of users
    $Data = while (-not [string]::IsNullOrEmpty($uri)) {
        # API Call
        $apiCall = try {
            # request the data
            Invoke-RestMethod -Headers $headers -Uri $uri -Method Get
        }
        catch {
            $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
            write-host $errorMessage 
        }
        $uri = $null
        if ($apiCall) {
            # Check if any data is left
            $uri = $apiCall.'@odata.nextLink'
            $apiCall
        }
    }
    # Put the data into a variable so we can use it
    $directoryRoles = ($Data | select-object Value).Value #| select -first 10
    # Loop through the data
    ForEach ($directoryRole in $directoryRoles)
        {
        # format the uri again - we are going to look for users first
        #$uri = "https://graph.microsoft.com/v1.0/directoryRoles/$($directoryRole.ID)/members/microsoft.graph.user"
        $uri = ("{0}/directoryRoles/{1}/members/microsoft.graph.user" -f $UriRoot,$directoryRole.ID)
        $MemberUsers = Invoke-RestMethod -Headers $headers -Uri $uri -Method Get
        # If there are any we will put them in an array
        $MemberUserLoop = ($MemberUsers | select-object Value).Value
        # We will loop thought them
        ForEach($MemberUser in $MemberUserLoop )
            {
            # Now lets bang them into an array
            $AzurerAdminObj    | Add-Member -type NoteProperty -name DisplayName -Value $MemberUser.displayName
            $AzurerAdminObj      | Add-Member -type NoteProperty -name UPN -Value $MemberUser.UserPrincipalName
            $AzurerAdminObj     | Add-Member -type NoteProperty -name GroupName  -Value "NA"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Role  -Value $directoryRole.Displayname
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Type  -Value "Permament"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Assignment  -Value "Direct"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name ADType -Value "User"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Tenant  -Value $TenantName
            $AzurerAdmin += $AzurerAdminObj  
            }
        # format the uri again - we are going to look for groups now
        #$uri = "https://graph.microsoft.com/v1.0/directoryRoles/$($directoryRole.ID)/members/microsoft.graph.group"
        $uri = ("{0}/directoryRoles/{1}/members/microsoft.graph.group" -f $UriRoot,$directoryRole.ID)
        $MemberGroups = Invoke-RestMethod -Headers $headers -Uri $uri -Method Get
        $MemberGroupLoop = ($MemberGroups | select-object Value).Value
        ForEach($MemberGroup in $MemberGroupLoop )
        {
        ## Now lets bang them into an array
        # format the uri again as we are going to get the group members
        #$uri = "https://graph.microsoft.com/v1.0/groups/$($MemberGroup.id)/members"
        $uri = ("{0}/groups/{1}/members" -f $UriRoot,$MemberGroup.id)
        $AzureMemberGroups = Invoke-RestMethod -Headers $headers -Uri $uri -Method Get
        # Add the members into a variable
        $AzureGroupLoop = ($AzureMemberGroups | select-object Value).Value
        ForEach($AzureMemberGroup in $AzureGroupLoop  )
            {
            #write-host -ForegroundColor yellow "Group name is $($MemberGroup.displayName)"
            $AzurerAdminObj     = New-Object System.Object
            $AzurerAdminObj     | Add-Member -type NoteProperty -name DisplayName -Value $AzureMemberGroup.displayName
            $AzurerAdminObj     | Add-Member -type NoteProperty -name UPN -Value $AzureMemberGroup.UserPrincipalName
            $AzurerAdminObj     | Add-Member -type NoteProperty -name GroupName  -Value $MemberGroup.Displayname
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Role  -Value $directoryRole.Displayname
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Type  -Value "Permament"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Assignment  -Value "Indirect"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name ADType -Value "Group"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Tenant  -Value $TenantName
            $AzurerAdmin += $AzurerAdminObj
            }
        }

        #$uri = "https://graph.microsoft.com/v1.0/directoryRoles/$($directoryRole.ID)/members/microsoft.graph.servicePrincipal"
        $uri = ("{0}/directoryRoles/{1}/members/microsoft.graph.servicePrincipal" -f $UriRoot,$directoryRole.ID)
        $MemberApps = Invoke-RestMethod -Headers $headers -Uri $uri -Method Get
        $MemberAppsLoop = ($MemberApps | select-object Value).Value
        ForEach($AppGroup in $MemberAppsLoop )
        {
            #write-host -ForegroundColor yellow "Group name is $($MemberGroup.displayName)"
            $AzurerAdminObj     = New-Object System.Object
            $AzurerAdminObj    | Add-Member -type NoteProperty -name DisplayName -Value $AppGroup.displayName
            $AzurerAdminObj      | Add-Member -type NoteProperty -name UPN -Value "NA"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name GroupName  -Value "NA"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Role  -Value $directoryRole.Displayname
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Type  -Value "Permament"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Assignment  -Value "Direct"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name ADType -Value "App"
            $AzurerAdminObj     | Add-Member -type NoteProperty -name Tenant  -Value $TenantName
            $AzurerAdmin += $AzurerAdminObj
        }


        }
    
    #$uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
    # This took an absolute age to get to - it is for eligiable assignments, teh documentation around it is shocking
    #$uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
    $uri = ("{0}/roleManagement/directory/roleEligibilityScheduleInstances" -f $UriRoot)
    # If the result is more than 999, we need to read the @odata.nextLink to show more than one side of users
    $Data = while (-not [string]::IsNullOrEmpty($uri)) {
        # API Call
        $apiCall = try {
            Invoke-RestMethod -Headers $headers -Uri $uri -Method Get
        }
        catch {
            $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
            write-host $errorMessage 
        }
        $uri = $null
        if ($apiCall) {
            # Check if any data is left
            $uri = $apiCall.'@odata.nextLink'
            $apiCall
        }
    }
    # Put the data in a variable
    $directoryEligiableRoles = ($Data | select-object Value).Value #| select -first 10
    # Loop through the entries
    FOrEach($directoryEligiableRole in $directoryEligiableRoles)
        {
            # null the variables
            $UserEligiable = $null
            $GroupEligiable = $null
            # format the uri so that we look for the principal the role is assigned to, seeign as t can be a group or user we will start of with users first
            #$uri = "https://graph.microsoft.com/v1.0/users/$($directoryEligiableRole.principalId)"
            # get the user role
            $uri = ("{0}/roleManagement/directory/roleDefinitions/{1}" -f $UriRoot,$directoryEligiableRole.roleDefinitionId)
            $UserEligiableRole = Invoke-RestMethod -Headers $headers -Uri $uri -Method Get
            $uri = ("{0}/users/{1}" -f $UriRoot,$directoryEligiableRole.principalId)
            # try it
            Try {$UserEligiable = Invoke-RestMethod -Headers $headers -Uri $uri -Method Get}
                Catch
                    {
                    write-host "$($directoryEligiableRole.principalId) is not a user so we will see if it is a group"
                    
                    }
            # if it fails it shoud be a group
            if(!($UserEligiable ))
                {
                    # format the uri for a group query
                    #$uri = "https://graph.microsoft.com/v1.0/groups/$($directoryEligiableRole.principalId)"
                    $uri = ("{0}/groups/{1}" -f $UriRoot,$directoryEligiableRole.principalId)
                    Try {$GroupEligiable = Invoke-RestMethod -Headers $headers -Uri $uri -Method Get}
                    Catch
                        {
                        # god knows why we would get here 
                        write-host -ForegroundColor red  "$($directoryEligiableRole.principalId) is not a group or a user"
                        }
                    # get the role that has been assigned byt formating the uri and quering it
                    #$uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$($directoryEligiableRole.roleDefinitionId)"
                    #$uri = ("{0}/roleManagement/directory/roleDefinitions/{1}" -f $UriRoot,$directoryEligiableRole.roleDefinitionId)
                    #$UserEligiableRole = Invoke-RestMethod -Headers $headers -Uri $uri -Method Get
                    write-host -ForegroundColor red "here $($GroupEligiable.displayName)"
                    $uri = "https://graph.microsoft.com/v1.0/groups/$($GroupEligiable.id)/members"
                    $AzureMemberGroups = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)"} -Uri $uri -Method Get
                    # Add the members into a variable
                    $AzureGroupLoop = ($AzureMemberGroups | select-object Value).Value
                    ForEach($AzureMemberGroup in $AzureGroupLoop  )
                        {
                        # Bang it in an array
                        $AzurerAdminObj     = New-Object System.Object
                        $AzurerAdminObj    | Add-Member -type NoteProperty -name DisplayName -Value $AzureMemberGroup.displayName
                        $AzurerAdminObj      | Add-Member -type NoteProperty -name UPN -Value $AzureMemberGroup.UserPrincipalName
                        $AzurerAdminObj     | Add-Member -type NoteProperty -name GroupName  -Value $GroupEligiable.displayName
                        $AzurerAdminObj     | Add-Member -type NoteProperty -name Role  -Value $UserEligiableRole.Displayname
                        $AzurerAdminObj     | Add-Member -type NoteProperty -name Type  -Value "Eligiable"
                        $AzurerAdminObj     | Add-Member -type NoteProperty -name Assignment  -Value "Indirect"
                        $AzurerAdminObj     | Add-Member -type NoteProperty -name ADType -Value "Group"
                        $AzurerAdminObj     | Add-Member -type NoteProperty -name Tenant  -Value $TenantName
                        $AzurerAdmin += $AzurerAdminObj  
                        }
                }
            Else{
                # it is a user so format the uri and get the role - dupliation of something above so will clean up at some point
                write-host -ForegroundColor green "here - name is $($UserEligiable.displayName)"
                #$uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$($directoryEligiableRole.roleDefinitionId)"
                #$uri = ("{0}/roleManagement/directory/roleDefinitions/{1}" -f $UriRoot,$directoryEligiableRole.roleDefinitionId)
                #$UserEligiableRole = Invoke-RestMethod -Headers $headers -Uri $uri -Method Get
                # Bang it in an array
                $AzurerAdminObj     = New-Object System.Object
                $AzurerAdminObj    | Add-Member -type NoteProperty -name DisplayName -Value $UserEligiable.displayName
                $AzurerAdminObj      | Add-Member -type NoteProperty -name UPN -Value $UserEligiable.UserPrincipalName
                $AzurerAdminObj     | Add-Member -type NoteProperty -name GroupName  -Value "NA"
                $AzurerAdminObj     | Add-Member -type NoteProperty -name Role  -Value $UserEligiableRole.Displayname
                $AzurerAdminObj     | Add-Member -type NoteProperty -name Type  -Value "Eligiable"
                $AzurerAdminObj     | Add-Member -type NoteProperty -name Assignment  -Value "Indirect"
                $AzurerAdminObj     | Add-Member -type NoteProperty -name ADType -Value "User"
                $AzurerAdminObj     | Add-Member -type NoteProperty -name Tenant  -Value $TenantName
                $AzurerAdmin += $AzurerAdminObj  
            }

        }

    }
    # Lastly we will search for admin users, you need to use single quotes around the string and use double quotes around the search
    # works in graph explorer https://graph.microsoft.com/v1.0/users/?$search="displayName:admin"
    #$uri = 'https://graph.microsoft.com/v1.0/users/?$search="displayName:admin"'
    $uri = ('{0}/users/?$search="displayName:admin"' -f $UriRoot)

    $Data = while (-not [string]::IsNullOrEmpty($uri)) {
        # API Call
        $apiCall = try {

            $headers = @{
                Authorization = "Bearer $($Tokenresponse.access_token)"
                ConsistencyLevel="eventual"
            }
            Invoke-RestMethod -Headers $headers -Uri $uri -Method Get
        }
        catch {
            $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
            write-host $errorMessage 
        }
        $uri = $null
        if ($apiCall) {
            # Check if any data is left
            $uri = $apiCall.'@odata.nextLink'
            $apiCall
        }
    }
    # Add data to array and loop through the entries
    $AzureadminUsers = ($Data | select-object Value).Value 
    FOrEach($AzureadminUser in $AzureadminUsers)
        {
            #bang them in an array
            $AzureuserAdminArrayObj   = New-Object System.Object
            $AzureuserAdminArrayObj     | Add-Member -type NoteProperty -name UserDisplayName -Value $AzureadminUser.displayName
            $AzureuserAdminArrayObj       | Add-Member -type NoteProperty -name UPN -Value $AzureadminUser.UserPrincipalName
            $AzureuserAdminArrayObj      | Add-Member -type NoteProperty -name Tenant  -Value $TenantName
            $AzureuserAdminArray  += $AzureuserAdminArrayObj 
        }

   # Last up export the data
    $AzurerAdmin | export-csv $UseOut -NoClobber -NoTypeInformation
    $AzurerAdminGroup | export-csv $GroupOut -NoClobber -NoTypeInformation
    $AzureuserAdminArray | export-csv $AzureuserAdminArrayOut -NoClobber -NoTypeInformation
