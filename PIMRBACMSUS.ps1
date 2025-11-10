<#
EFP
.SYNOPSIS
    Script PIM con soporte completo Azure RBAC - VERSIÓN CORREGIDA
    
.DESCRIPTION
    Mejoras implementadas:
    - Extracción de roles integrada (-ExtractRoles)
    - Lista blanca por RoleDefinitionId (GUID) en lugar de nombres
    - Detección de roles heredados por ancestros de scope
    - Migración automática controlada (crear elegible + revocar permanente)
    - CORRECCIONES: Regex, funciones duplicadas, paginación, rate limiting
    
.PARAMETER CsvPath
    Ruta al archivo CSV con las asignaciones
    
.PARAMETER Phase
    Fase de controles (0, 1, 2)
    
.PARAMETER SupportAzureRBAC
    Habilita soporte para roles Azure ARM
    
.PARAMETER AutoMigrate
    Habilita migración automática de roles permanentes a PIM
    
.PARAMETER ExtractRoles
    Modo extracción de roles (no requiere CsvPath ni Phase)
    
.PARAMETER DryRun
    Modo simulación
    
.PARAMETER AllowedRolesConfigPath
    Ruta al archivo JSON de configuración de roles permitidos
    
.EXAMPLE
    # Extraer roles
    .\PIM-SecureAssignment-ARM.ps1 -ExtractRoles -SupportAzureRBAC -ExportRolesCsv
    
    # Procesar asignaciones
    .\PIM-SecureAssignment-ARM.ps1 -CsvPath "file.csv" -Phase 1 -SupportAzureRBAC -AutoMigrate -DryRun
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet(0, 1, 2)]
    [int]$Phase = 0,
    
    [switch]$SupportAzureRBAC,
    [switch]$AutoMigrate,
    [switch]$DryRun,
    [switch]$Force,
    
    # Parámetros para extracción de roles
    [switch]$ExtractRoles,
    [switch]$ExportRolesCsv,
    [string]$RolesOutputPath = "roles_reference.csv",
    
    # Soporte multi-suscripción
    [switch]$AllSubscriptions,
    [string[]]$SubscriptionIds,
    
    # CORRECCIÓN: Agregar parámetro faltante
    [string]$AllowedRolesConfigPath = "allowed_roles_config.json"
)

#region Configuration

# Lista blanca de roles Entra ID por GUID
$script:AllowedEntraRoles = @{
    Tier0 = @{
        '62e90394-69f5-4237-9190-012177145e10' = @{ Name = 'Global Administrator'; MaxDuration = 'PT8H'; RequiresApproval = $true }
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = @{ Name = 'Security Administrator'; MaxDuration = 'PT8H'; RequiresApproval = $true }
    }
    Tier1 = @{
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = @{ Name = 'SharePoint Administrator'; MaxDuration = 'P1D'; RequiresApproval = $true }
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = @{ Name = 'User Administrator'; MaxDuration = 'P1D'; RequiresApproval = $false }
    }
    Tier2 = @{
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' = @{ Name = 'Helpdesk Administrator'; MaxDuration = 'P7D'; RequiresApproval = $false }
    }
}

# Lista blanca de roles Azure RBAC por RoleDefinitionId (GUID)
$script:AllowedAzureRoles = @{
    Tier0 = @{
        '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = @{ Name = 'Owner'; MaxDuration = 'PT4H'; RequiresApproval = $true }
        '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = @{ Name = 'User Access Administrator'; MaxDuration = 'PT4H'; RequiresApproval = $true }
    }
    Tier1 = @{
        'b24988ac-6180-42a0-ab88-20f7382dd24c' = @{ Name = 'Contributor'; MaxDuration = 'PT8H'; RequiresApproval = $true }
        '9980e02c-c2be-4d73-94e8-173b1dc7cf3c' = @{ Name = 'Virtual Machine Contributor'; MaxDuration = 'P1D'; RequiresApproval = $false }
        '17d1049b-9a84-46fb-8f53-869881c3d3ab' = @{ Name = 'Storage Account Contributor'; MaxDuration = 'P1D'; RequiresApproval = $false }
        '4d97b98b-1d4f-4787-a291-c67834d212e7' = @{ Name = 'Network Contributor'; MaxDuration = 'P1D'; RequiresApproval = $false }
    }
    Tier2 = @{
        'acdd72a7-3385-48ef-bd42-f606fba81ae7' = @{ Name = 'Reader'; MaxDuration = 'P30D'; RequiresApproval = $false }
        '43d0d8ad-25c7-4714-9337-8ba259a9fe05' = @{ Name = 'Monitoring Reader'; MaxDuration = 'P30D'; RequiresApproval = $false }
        '73c42c96-874c-492b-b04d-ab87d138a893' = @{ Name = 'Log Analytics Reader'; MaxDuration = 'P30D'; RequiresApproval = $false }
    }
}

# Cache de definiciones de roles Azure
$script:AzureRoleDefinitionsCache = @{}

# Permisos requeridos
$script:RequiredPermissions = @{
    EntraID = @{
        0 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup')
        1 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup', 'RoleManagement.Read.Directory')
        2 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup', 'RoleManagement.Read.Directory', 'Policy.Read.All')
    }
}

# Variables globales
$script:AuditLog = @()
$script:CsvHash = $null
$script:ProcessedSubscriptions = @()
$script:AllowedRolesConfigHash = $null
$script:LastApiCall = Get-Date
$script:Statistics = @{
    Total = 0
    Success = 0
    Failed = 0
    Skipped = 0
    Conflicts = 0
    Migrated = 0
    GroupInheritedSkipped = 0
    EntraRoles = 0
    AzureRoles = 0
    Groups = 0
    SubscriptionsProcessed = 0
}

#endregion

#region Configuration Management

function Import-AllowedRolesConfiguration {
    <#
    .SYNOPSIS
        Carga configuración de roles permitidos desde archivo externo JSON
    #>
    [CmdletBinding()]
    param([string]$ConfigPath)
    
    Write-Log "Cargando configuración de roles desde: $ConfigPath" -Level Info
    
    if (-not (Test-Path $ConfigPath)) {
        Write-Log "Archivo de configuración no encontrado, usando configuración por defecto embebida" -Level Warning
        return $false
    }
    
    try {
        $configContent = Get-Content $ConfigPath -Raw -Encoding UTF8
        
        # Calcular hash del archivo de configuración
        $script:AllowedRolesConfigHash = (Get-FileHash -Path $ConfigPath -Algorithm SHA256).Hash
        Write-Log "Hash de configuración: $($script:AllowedRolesConfigHash.Substring(0,16))..." -Level Info
        
        $config = $configContent | ConvertFrom-Json
        
        # Cargar roles Entra ID
        if ($config.EntraIDRoles) {
            $script:AllowedEntraRoles = @{}
            foreach ($tier in $config.EntraIDRoles.PSObject.Properties) {
                $script:AllowedEntraRoles[$tier.Name] = @{}
                foreach ($role in $tier.Value.PSObject.Properties) {
                    $script:AllowedEntraRoles[$tier.Name][$role.Name] = @{
                        Name = $role.Value.Name
                        MaxDuration = $role.Value.MaxDuration
                        RequiresApproval = $role.Value.RequiresApproval
                    }
                }
            }
            Write-Log "Roles Entra ID cargados: $($script:AllowedEntraRoles.Keys.Count) tiers" -Level Success
        }
        
        # Cargar roles Azure RBAC
        if ($config.AzureRBACRoles) {
            $script:AllowedAzureRoles = @{}
            foreach ($tier in $config.AzureRBACRoles.PSObject.Properties) {
                $script:AllowedAzureRoles[$tier.Name] = @{}
                foreach ($role in $tier.Value.PSObject.Properties) {
                    $script:AllowedAzureRoles[$tier.Name][$role.Name] = @{
                        Name = $role.Value.Name
                        MaxDuration = $role.Value.MaxDuration
                        RequiresApproval = $role.Value.RequiresApproval
                    }
                }
            }
            Write-Log "Roles Azure RBAC cargados: $($script:AllowedAzureRoles.Keys.Count) tiers" -Level Success
        }
        
        return $true
    }
    catch {
        Write-Log "Error cargando configuración: $_" -Level Error
        Write-Log "Usando configuración por defecto embebida" -Level Warning
        return $false
    }
}

#endregion

#region Utility Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $colors = @{
        Info = 'White'
        Success = 'Green'
        Warning = 'Yellow'
        Error = 'Red'
    }
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $colors[$Level]
}

function Add-AuditEntry {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleOrGroup = '',
        [string]$Action,
        [string]$Status,
        [string]$Details = '',
        [string]$RequestId = '',
        [string]$Scope = ''
    )
    
    $script:AuditLog += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        PrincipalId = $PrincipalId
        RoleOrGroup = $RoleOrGroup
        Scope = $Scope
        Action = $Action
        Status = $Status
        Details = $Details
        RequestId = $RequestId
        ExecutedBy = try { (Get-MgContext).Account } catch { "Unknown" }
        CsvHash = $script:CsvHash
        Phase = $Phase
        DryRun = $DryRun.IsPresent
        AutoMigrate = $AutoMigrate.IsPresent
    }
}

function Wait-RateLimit {
    <#
    .SYNOPSIS
        NUEVO: Rate limiting proactivo para evitar throttling
    #>
    [CmdletBinding()]
    param([int]$MinDelayMs = 200)
    
    $elapsed = (Get-Date) - $script:LastApiCall
    if ($elapsed.TotalMilliseconds -lt $MinDelayMs) {
        Start-Sleep -Milliseconds ($MinDelayMs - $elapsed.TotalMilliseconds)
    }
    $script:LastApiCall = Get-Date
}

function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [int]$BaseDelaySeconds = 5
    )
    
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        try {
            Wait-RateLimit
            return & $ScriptBlock
        }
        catch {
            if ($_.Exception.Message -match '429|TooManyRequests|throttl') {
                $attempt++
                if ($attempt -ge $MaxRetries) {
                    throw "Falló después de $MaxRetries intentos por throttling"
                }
                
                $delay = $BaseDelaySeconds * [Math]::Pow(2, $attempt)
                Write-Log "Throttling detectado. Reintento $attempt/$MaxRetries en $delay segundos..." -Level Warning
                Start-Sleep -Seconds $delay
            }
            else {
                throw
            }
        }
    }
}

function Test-TokenExpiration {
    <#
    .SYNOPSIS
        NUEVO: Valida expiración de token y reconecta si es necesario
    #>
    [CmdletBinding()]
    param()
    
    try {
        $context = Get-MgContext
        if ($context.TokenCache.ExpiresOn -lt (Get-Date).AddMinutes(10)) {
            Write-Log "Token expira pronto, reconectando..." -Level Warning
            $requiredScopes = $script:RequiredPermissions.EntraID[$Phase]
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        }
    }
    catch {
        Write-Verbose "No se pudo verificar expiración de token: $_"
    }
}

#endregion

#region Role Extraction Functions

function Get-AllRoleDefinitions {
    <#
    .SYNOPSIS
        Extrae todos los roles de Entra ID y Azure RBAC con sus GUIDs
    #>
    [CmdletBinding()]
    param(
        [switch]$ExportCsv,
        [string]$OutputPath = "roles_reference.csv"
    )
    
    Write-Host "`n╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Extractor de RoleDefinitionId (GUIDs)        ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    $allRoles = @()
    
    # === ENTRA ID ROLES ===
    Write-Log "=== ROLES DE ENTRA ID (Azure AD) ===" -Level Info
    
    try {
        $context = Get-MgContext
        if (-not $context) {
            Write-Log "Conectando a Microsoft Graph..." -Level Warning
            Connect-MgGraph -Scopes "RoleManagement.Read.Directory" -NoWelcome
        }
        
        $entraRoles = Get-MgDirectoryRoleTemplate | Sort-Object DisplayName
        
        Write-Log "Roles de Entra ID encontrados: $($entraRoles.Count)" -Level Success
        Write-Host "`nFormato: DisplayName | RoleTemplateId (GUID)`n" -ForegroundColor Yellow
        
        foreach ($role in $entraRoles) {
            $roleData = [PSCustomObject]@{
                Type = "Entra ID"
                DisplayName = $role.DisplayName
                RoleDefinitionId = $role.Id
                Description = $role.Description
                IsBuiltIn = $true
                IsCustom = $false
            }
            
            $allRoles += $roleData
            
            Write-Host "$($role.DisplayName)" -ForegroundColor White -NoNewline
            Write-Host " | " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($role.Id)" -ForegroundColor Cyan
        }
        
        # Roles críticos
        Write-Host "`n--- ROLES CRÍTICOS DE ENTRA ID ---" -ForegroundColor Yellow
        $criticalEntraIds = @(
            '62e90394-69f5-4237-9190-012177145e10',
            '194ae4cb-b126-40b2-bd5b-6091b380977d',
            'f28a1f50-f6e7-4571-818b-6a12f2af6b6c',
            'fe930be7-5e62-47db-91af-98c3a49a38b1',
            '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        )
        
        foreach ($roleId in $criticalEntraIds) {
            $role = $entraRoles | Where-Object { $_.Id -eq $roleId }
            if ($role) {
                Write-Host "'$($role.Id)' = @{ Name = '$($role.DisplayName)'; MaxDuration = 'PT8H'; RequiresApproval = `$true }" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Log "Error obteniendo roles Entra ID: $_" -Level Error
    }
    
    # === AZURE RBAC ROLES ===
    if ($SupportAzureRBAC) {
        Write-Log "`n=== ROLES DE AZURE RBAC ===" -Level Info
        
        try {
            $azContext = Get-AzContext
            if (-not $azContext) {
                Write-Log "Conectando a Azure..." -Level Warning
                Connect-AzAccount
                $azContext = Get-AzContext
            }
            
            if ($azContext) {
                Write-Log "Suscripción activa: $($azContext.Subscription.Name)" -Level Info
                
                $azureRoles = Get-AzRoleDefinition | Sort-Object Name
                
                Write-Log "Roles de Azure encontrados: $($azureRoles.Count)" -Level Success
                Write-Host "`nFormato: Name | Id (GUID) | IsCustom`n" -ForegroundColor Yellow
                
                foreach ($role in $azureRoles) {
                    $roleData = [PSCustomObject]@{
                        Type = "Azure RBAC"
                        DisplayName = $role.Name
                        RoleDefinitionId = $role.Id
                        Description = $role.Description
                        IsBuiltIn = -not $role.IsCustom
                        IsCustom = $role.IsCustom
                    }
                    
                    $allRoles += $roleData
                    
                    $customTag = if ($role.IsCustom) { " [CUSTOM]" } else { "" }
                    Write-Host "$($role.Name)$customTag" -ForegroundColor White -NoNewline
                    Write-Host " | " -ForegroundColor DarkGray -NoNewline
                    Write-Host "$($role.Id)" -ForegroundColor Cyan
                }
                
                # Roles críticos de Azure
                Write-Host "`n--- ROLES CRÍTICOS DE AZURE RBAC ---" -ForegroundColor Yellow
                
                $criticalAzureRoles = @(
                    @{ Name = 'Owner'; MaxDuration = 'PT4H' },
                    @{ Name = 'User Access Administrator'; MaxDuration = 'PT4H' },
                    @{ Name = 'Contributor'; MaxDuration = 'PT8H' },
                    @{ Name = 'Virtual Machine Contributor'; MaxDuration = 'P1D' },
                    @{ Name = 'Storage Account Contributor'; MaxDuration = 'P1D' },
                    @{ Name = 'Network Contributor'; MaxDuration = 'P1D' },
                    @{ Name = 'Reader'; MaxDuration = 'P30D' }
                )
                
                foreach ($roleInfo in $criticalAzureRoles) {
                    $role = $azureRoles | Where-Object { $_.Name -eq $roleInfo.Name }
                    if ($role) {
                        Write-Host "'$($role.Id)' = @{ Name = '$($role.Name)'; MaxDuration = '$($roleInfo.MaxDuration)'; RequiresApproval = `$true }" -ForegroundColor Green
                    }
                }
                
                # Roles custom
                $customRoles = $azureRoles | Where-Object { $_.IsCustom -eq $true }
                if ($customRoles.Count -gt 0) {
                    Write-Host "`n--- ROLES CUSTOM DETECTADOS ---" -ForegroundColor Magenta
                    foreach ($role in $customRoles) {
                        Write-Host "'$($role.Id)' = @{ Name = '$($role.Name)'; MaxDuration = 'P1D'; RequiresApproval = `$true }  # CUSTOM" -ForegroundColor Magenta
                    }
                }
            }
        }
        catch {
            Write-Log "Error obteniendo roles Azure: $_" -Level Error
        }
    }
    
    # Exportar CSV
    if ($ExportCsv) {
        try {
            $allRoles | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Log "`n✓ CSV exportado: $OutputPath" -Level Success
        }
        catch {
            Write-Log "Error exportando CSV: $_" -Level Error
        }
    }
    
    Write-Host "`n✓ Extracción completada" -ForegroundColor Green
    return $allRoles
}

#endregion

#region Azure RBAC Enhanced Functions

function Initialize-AzureRoleDefinitionsCache {
    [CmdletBinding()]
    param()
    
    Write-Log "Inicializando cache de roles Azure..." -Level Info
    
    try {
        $allRoles = Get-AzRoleDefinition
        
        foreach ($role in $allRoles) {
            $script:AzureRoleDefinitionsCache[$role.Id] = @{
                Name = $role.Name
                Id = $role.Id
                Description = $role.Description
                IsCustom = $role.IsCustom
            }
        }
        
        Write-Log "Cache inicializado: $($script:AzureRoleDefinitionsCache.Count) roles" -Level Success
    }
    catch {
        Write-Log "Error inicializando cache: $_" -Level Error
        throw
    }
}

function Get-AzureRoleNameById {
    [CmdletBinding()]
    param([string]$RoleDefinitionId)
    
    if ($script:AzureRoleDefinitionsCache.ContainsKey($RoleDefinitionId)) {
        return $script:AzureRoleDefinitionsCache[$RoleDefinitionId].Name
    }
    
    $role = Get-AzRoleDefinition -Id $RoleDefinitionId -ErrorAction SilentlyContinue
    if ($role) {
        $script:AzureRoleDefinitionsCache[$RoleDefinitionId] = @{
            Name = $role.Name
            Id = $role.Id
            Description = $role.Description
            IsCustom = $role.IsCustom
        }
        return $role.Name
    }
    
    return $RoleDefinitionId
}

function Get-ScopeAncestors {
    <#
    .SYNOPSIS
        CORREGIDO: Obtiene ancestros de un scope (recurso → RG → suscripción)
    #>
    [CmdletBinding()]
    param([string]$Scope)
    
    $ancestors = @()
    $currentScope = $Scope.TrimEnd('/')
    
    # No incluir '/' como scope válido
    while ($currentScope -and $currentScope -match '^/subscriptions/') {
        $ancestors += $currentScope
        
        # Extraer scope padre
        if ($currentScope -match '^(.+)/[^/]+$') {
            $currentScope = $matches[1]
        }
        else {
            break
        }
    }
    
    # TODO: Si en el futuro se necesita Management Groups, agregar aquí
    # Get-AzManagementGroup -GroupName "..." para resolver jerarquía
    
    return $ancestors
}

function Get-UserGroupMemberships {
    <#
    .SYNOPSIS
        NUEVO: Obtiene grupos del usuario para detectar herencia real
    #>
    [CmdletBinding()]
    param([string]$PrincipalId)
    
    try {
        $groups = Invoke-WithRetry -ScriptBlock {
            Get-AzADUser -ObjectId $PrincipalId -ErrorAction Stop | 
                Select-Object -ExpandProperty AdditionalProperties
        }
        
        # Extraer IDs de grupos
        $groupIds = @()
        if ($groups.memberOf) {
            $groupIds = $groups.memberOf | ForEach-Object {
                if ($_ -match '/([a-f0-9\-]{36})$') { $matches[1] }
            }
        }
        
        return $groupIds
    }
    catch {
        Write-Verbose "Error obteniendo membresías de grupo: $_"
        return @()
    }
}

function Test-AzureRoleAllowedByGuid {
    [CmdletBinding()]
    param(
        [string]$RoleDefinitionId,
        [string]$PrincipalId
    )
    
    $allAllowed = @{}
    foreach ($tier in $script:AllowedAzureRoles.Keys) {
        $allAllowed += $script:AllowedAzureRoles[$tier]
    }
    
    if ($RoleDefinitionId -notin $allAllowed.Keys) {
        $roleName = Get-AzureRoleNameById -RoleDefinitionId $RoleDefinitionId
        Write-Log "ROL BLOQUEADO: '$roleName' ($RoleDefinitionId) no autorizado" -Level Warning
        
        Add-AuditEntry -PrincipalId $PrincipalId -Action "AzureRoleBlocked" -Status "Blocked" `
            -Details "Rol no autorizado: $roleName ($RoleDefinitionId)"
        return $false
    }
    
    return $true
}

function Test-ExistingAzureRoleAssignmentWithAncestors {
    <#
    .SYNOPSIS
        CORREGIDO: Detecta asignaciones permanentes con paginación y detección de grupos
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$Scope
    )
    
    $roleName = Get-AzureRoleNameById -RoleDefinitionId $RoleDefinitionId
    $conflictingAssignments = @()
    
    $ancestors = Get-ScopeAncestors -Scope $Scope
    
    Write-Verbose "Verificando asignaciones en $($ancestors.Count) scopes (incluyendo ancestros)"
    
    # MEJORA: Obtener grupos del usuario para detección precisa
    $userGroups = Get-UserGroupMemberships -PrincipalId $PrincipalId
    
    foreach ($ancestorScope in $ancestors) {
        try {
            # CORRECCIÓN: Agregar paginación y reintentos
            $assignments = Invoke-WithRetry -ScriptBlock {
                Get-AzRoleAssignment -Scope $ancestorScope -ErrorAction Stop
            } | Where-Object { 
                $_.RoleDefinitionId -eq $RoleDefinitionId -and 
                ($_.ObjectId -eq $PrincipalId -or $_.ObjectId -in $userGroups)
            }
            
            if ($assignments) {
                foreach ($assignment in $assignments) {
                    # Detectar si viene de grupo
                    $isGroupInherited = ($assignment.ObjectId -ne $PrincipalId -and $assignment.ObjectId -in $userGroups)
                    
                    if ($isGroupInherited) {
                        Write-Log "⚠️  ASIGNACIÓN HEREDADA POR GRUPO detectada:" -Level Warning
                        Write-Log "    Principal: $PrincipalId" -Level Warning
                        Write-Log "    Grupo: $($assignment.DisplayName) ($($assignment.ObjectId))" -Level Warning
                        Write-Log "    Scope: $ancestorScope" -Level Warning
                        Write-Log "    → Acción requerida: Migrar grupo o remover usuario del grupo" -Level Warning
                    }
                    
                    $conflictingAssignments += [PSCustomObject]@{
                        Scope = $ancestorScope
                        RoleDefinitionId = $RoleDefinitionId
                        RoleName = $roleName
                        AssignmentId = $assignment.RoleAssignmentId
                        IsInherited = ($ancestorScope -ne $Scope)
                        IsGroupInherited = $isGroupInherited
                        GroupObjectId = if ($isGroupInherited) { $assignment.ObjectId } else { $null }
                        GroupDisplayName = if ($isGroupInherited) { $assignment.DisplayName } else { $null }
                        CanAutoRemove = -not $isGroupInherited
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error verificando scope $ancestorScope: $_"
        }
    }
    
    if ($conflictingAssignments.Count -gt 0) {
        $directAssignments = ($conflictingAssignments | Where-Object { -not $_.IsGroupInherited }).Count
        $groupAssignments = ($conflictingAssignments | Where-Object { $_.IsGroupInherited }).Count
        
        Write-Log "CONFLICTO AZURE: $($conflictingAssignments.Count) asignación(es) de '$roleName'" -Level Warning
        Write-Log "  - Directas: $directAssignments (removibles con -AutoMigrate)" -Level Warning
        Write-Log "  - Por Grupo: $groupAssignments (requieren acción manual)" -Level Warning
        
        foreach ($conflict in $conflictingAssignments) {
            $inheritedMsg = if ($conflict.IsInherited) { " (HEREDADO)" } else { "" }
            $groupMsg = if ($conflict.IsGroupInherited) { " [VÍA GRUPO: $($conflict.GroupDisplayName)]" } else { "" }
            Write-Log "  → Scope: $($conflict.Scope)$inheritedMsg$groupMsg" -Level Warning
        }
        
        $script:Statistics.Conflicts++
        
        # Contar asignaciones heredadas por grupo
        $groupInheritedCount = ($conflictingAssignments | Where-Object { $_.IsGroupInherited }).Count
        if ($groupInheritedCount -gt 0) {
            $script:Statistics.GroupInheritedSkipped += $groupInheritedCount
        }
        
        Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $roleName `
            -Action "AzureConflictDetected" -Status "Warning" `
            -Details "Total: $($conflictingAssignments.Count), Directas: $directAssignments, Por Grupo: $groupAssignments" `
            -Scope $Scope
        
        return @{
            HasConflict = $true
            Assignments = $conflictingAssignments
            HasGroupInherited = ($groupAssignments -gt 0)
        }
    }
    
    return @{ 
        HasConflict = $false
        HasGroupInherited = $false
    }
}

function Remove-AzureRoleAssignmentSafe {
    <#
    .SYNOPSIS
        Remueve asignación permanente Azure - SOLO si no es heredada por grupo
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject]$Assignment,
        [string]$PrincipalId
    )
    
    try {
        $roleName = Get-AzureRoleNameById -RoleDefinitionId $Assignment.RoleDefinitionId
        
        # No intentar remover si viene de grupo
        if ($Assignment.IsGroupInherited) {
            Write-Log "⚠️  SKIP: Asignación heredada por GRUPO no se puede remover automáticamente" -Level Warning
            Write-Log "    Grupo: $($Assignment.GroupDisplayName)" -Level Warning
            Write-Log "    Acción requerida: Remover usuario del grupo o migrar grupo a PIM" -Level Warning
            
            Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $roleName `
                -Action "AzureGroupInheritedSkipped" -Status "Skipped" `
                -Details "Heredado por grupo: $($Assignment.GroupDisplayName) ($($Assignment.GroupObjectId))" `
                -Scope $Assignment.Scope
            
            return $false
        }
        
        if ($DryRun) {
            Write-Log "[DRY-RUN] Removería: $roleName en $($Assignment.Scope)" -Level Warning
            return $true
        }
        
        Write-Log "Removiendo permanente: $roleName en $($Assignment.Scope)..." -Level Warning
        
        # Usar retry en remoción
        Invoke-WithRetry -ScriptBlock {
            Remove-AzRoleAssignment -ObjectId $PrincipalId `
                -RoleDefinitionId $Assignment.RoleDefinitionId `
                -Scope $Assignment.Scope `
                -ErrorAction Stop
        }
        
        Write-Log "✓ Asignación permanente removida" -Level Success
        
        Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $roleName `
            -Action "AzurePermanentRemoved" -Status "Success" `
            -Details "Removido de: $($Assignment.Scope)" `
            -Scope $Assignment.Scope
        
        return $true
    }
    catch {
        Write-Log "Error removiendo asignación: $_" -Level Error
        Add-AuditEntry -PrincipalId $PrincipalId -Action "AzureRemovalFailed" `
            -Status "Error" -Details $_.Exception.Message -Scope $Assignment.Scope
        return $false
    }
}

function Test-ExistingAzureEligibility {
    <#
    .SYNOPSIS
        CORREGIDO: Verifica eligibilidad existente con paginación y reintentos
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$Scope
    )
    
    try {
        # CORRECCIÓN: Agregar reintentos
        $existing = Invoke-WithRetry -ScriptBlock {
            Get-AzRoleEligibilityScheduleInstance -Scope $Scope -Filter "asTarget()" -ErrorAction Stop
        } | Where-Object { $_.PrincipalId -eq $PrincipalId -and $_.RoleDefinitionId -eq $RoleDefinitionId }
        
        if ($existing) {
            $roleName = Get-AzureRoleNameById -RoleDefinitionId $RoleDefinitionId
            Write-Log "IDEMPOTENCIA: Eligibilidad ya existe para '$roleName'" -Level Warning
            
            $script:Statistics.Skipped++
            Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $roleName `
                -Action "AzureSkipped" -Status "AlreadyExists" `
                -Details "Eligibilidad existente" -Scope $Scope
            return $true
        }
    }
    catch {
        Write-Verbose "Error verificando eligibilidad: $_"
    }
    
    return $false
}

function New-AzureRBACEligibility {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$Scope,
        [string]$Justification,
        [string]$Duration
    )
    
    try {
        $scheduleInfo = New-AzRoleEligibilityScheduleRequest `
            -Name (New-Guid) `
            -Scope $Scope `
            -PrincipalId $PrincipalId `
            -RoleDefinitionId $RoleDefinitionId `
            -RequestType "AdminAssign" `
            -Justification $Justification `
            -ScheduleInfoStartDateTime (Get-Date).ToUniversalTime() `
            -ExpirationType "AfterDuration" `
            -ExpirationDuration $Duration `
            -ErrorAction Stop
        
        return $scheduleInfo
    }
    catch {
        throw "Error creando eligibilidad Azure: $_"
    }
}

#endregion

#region Entra ID Functions

function Test-EntraRoleAllowed {
    [CmdletBinding()]
    param(
        [string]$RoleDefinitionId,
        [string]$PrincipalId
    )
    
    $allAllowed = @{}
    foreach ($tier in $script:AllowedEntraRoles.Keys) {
        $allAllowed += $script:AllowedEntraRoles[$tier]
    }
    
    if ($RoleDefinitionId -notin $allAllowed.Keys) {
        Write-Log "ROL ENTRA ID BLOQUEADO: $RoleDefinitionId no autorizado" -Level Warning
        Add-AuditEntry -PrincipalId $PrincipalId -Action "EntraRoleBlocked" -Status "Blocked" `
            -Details "Rol no autorizado: $RoleDefinitionId"
        return $false
    }
    
    return $true
}

function Test-ExistingEntraRoleAssignment {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$DirectoryScopeId
    )
    
    try {
        $filter = "principalId eq '$PrincipalId' and roleDefinitionId eq '$RoleDefinitionId'"
        $existing = Get-MgRoleManagementDirectoryRoleAssignment -Filter $filter -ErrorAction Stop
        
        if ($existing) {
            Write-Log "CONFLICTO ENTRA ID: Asignación permanente existe" -Level Warning
            
            $script:Statistics.Conflicts++
            Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $RoleDefinitionId `
                -Action "EntraConflictDetected" -Status "Warning" `
                -Details "Asignación permanente: $($existing[0].Id)"
            
            return @{
                HasConflict = $true
                Assignments = $existing
            }
        }
    }
    catch {
        Write-Verbose "Error verificando asignaciones Entra ID: $_"
    }
    
    return @{ HasConflict = $false }
}

function Remove-EntraRoleAssignmentSafe {
    <#
    .SYNOPSIS
        Remueve asignación permanente de Entra ID de forma segura
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject]$Assignment,
        [string]$PrincipalId
    )
    
    try {
        if ($DryRun) {
            Write-Log "[DRY-RUN] Removería asignación Entra ID permanente: $($Assignment.RoleDefinitionId)" -Level Warning
            return $true
        }
        
        Write-Log "Removiendo asignación permanente Entra ID..." -Level Warning
        
        Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $Assignment.Id -ErrorAction Stop
        
        Write-Log "✓ Asignación permanente Entra ID removida" -Level Success
        
        Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $Assignment.RoleDefinitionId `
            -Action "EntraPermanentRemoved" -Status "Success" `
            -Details "Removido: $($Assignment.Id)"
        
        return $true
    }
    catch {
        Write-Log "Error removiendo asignación Entra ID: $_" -Level Error
        return $false
    }
}

function Test-ExistingEntraEligibility {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId
    )
    
    try {
        $filter = "principalId eq '$PrincipalId' and roleDefinitionId eq '$RoleDefinitionId'"
        $existing = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter $filter -ErrorAction SilentlyContinue
        
        if ($existing) {
            Write-Log "IDEMPOTENCIA ENTRA ID: Eligibilidad ya existe" -Level Warning
            $script:Statistics.Skipped++
            Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $RoleDefinitionId `
                -Action "EntraSkipped" -Status "AlreadyExists" -Details "Eligibilidad existente"
            return $true
        }
    }
    catch {
        Write-Verbose "Error verificando eligibilidad Entra ID: $_"
    }
    
    return $false
}

function Test-EntraDurationCompliance {
    <#
    .SYNOPSIS
        Verifica límites de duración para roles Entra ID
    #>
    [CmdletBinding()]
    param(
        [string]$RoleDefinitionId,
        [string]$Duration
    )
    
    $roleConfig = $null
    foreach ($tier in $script:AllowedEntraRoles.Keys) {
        if ($script:AllowedEntraRoles[$tier].ContainsKey($RoleDefinitionId)) {
            $roleConfig = $script:AllowedEntraRoles[$tier][$RoleDefinitionId]
            break
        }
    }
    
    if (-not $roleConfig) {
        return $true
    }
    
    $requestedDuration = [System.Xml.XmlConvert]::ToTimeSpan($Duration)
    $maxDuration = [System.Xml.XmlConvert]::ToTimeSpan($roleConfig.MaxDuration)
    
    if ($requestedDuration -gt $maxDuration) {
        Write-Log "Duración excede límite Entra ID: $Duration > $($roleConfig.MaxDuration)" -Level Warning
        return $false
    }
    
    return $true
}

function New-EntraIDEligibility {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$DirectoryScopeId,
        [string]$Justification,
        [string]$Duration
    )
    
    try {
        $params = @{
            PrincipalId = $PrincipalId
            RoleDefinitionId = $RoleDefinitionId
            DirectoryScopeId = $DirectoryScopeId
            Action = "AdminAssign"
            Justification = $Justification
            ScheduleInfo = @{
                StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                Expiration = @{
                    Type = "AfterDuration"
                    Duration = $Duration
                }
            }
        }
        
        $response = New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop
        return $response
    }
    catch {
        throw "Error creando eligibilidad Entra ID: $_"
    }
}

#endregion

#region Group Functions

function Test-ExistingGroupEligibility {
    <#
    .SYNOPSIS
        CORREGIDO: Verifica eligibilidad existente en grupo PIM con paginación
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$GroupId
    )
    
    try {
        $filter = "principalId eq '$PrincipalId'"
        
        # CORRECCIÓN: Agregar reintentos y paginación
        $existing = Invoke-WithRetry -ScriptBlock {
            Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule `
                -PrivilegedAccessGroupId $GroupId `
                -Filter $filter `
                -All `
                -ErrorAction Stop
        }
        
        if ($existing) {
            Write-Log "IDEMPOTENCIA GRUPO: Membresía ya existe" -Level Warning
            $script:Statistics.Skipped++
            Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $GroupId `
                -Action "GroupSkipped" -Status "AlreadyExists" `
                -Details "Membresía existente en grupo"
            return $true
        }
    }
    catch {
        Write-Verbose "Error verificando eligibilidad grupo: $_"
    }
    
    return $false
}

function New-GroupEligibility {
    <#
    .SYNOPSIS
        Crea eligibilidad de membresía en grupo PIM
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$GroupId,
        [string]$Justification,
        [string]$Duration
    )
    
    try {
        $params = @{
            AccessId = "member"
            PrincipalId = $PrincipalId
            GroupId = $GroupId
            Action = "AdminAssign"
            Justification = $Justification
            ScheduleInfo = @{
                StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                Expiration = @{
                    Type = "AfterDuration"
                    Duration = $Duration
                }
            }
        }
        
        $response = New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest `
            -BodyParameter $params `
            -ErrorAction Stop
        
        return $response
    }
    catch {
        throw "Error creando membresía grupo: $_"
    }
}

#endregion

#region Prerequisites and Validation

function Test-Prerequisites {
    [CmdletBinding()]
    param([int]$Phase)
    
    Write-Log "=== Validando Prerequisites (Fase $Phase) ===" -Level Info
    
    if (-not (Test-Path $CsvPath)) {
        throw "ERROR: Archivo CSV no encontrado: $CsvPath"
    }
    
    $script:CsvHash = (Get-FileHash -Path $CsvPath -Algorithm SHA256).Hash
    Write-Log "CSV Hash: $($script:CsvHash.Substring(0,16))..." -Level Info
    
    $requiredModules = @('Microsoft.Graph.Identity.Governance', 'Microsoft.Graph.Identity.SignIns')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            throw "ERROR: Módulo requerido no instalado: $module"
        }
        Import-Module $module -ErrorAction Stop
        Write-Log "Módulo cargado: $module" -Level Success
    }
    
    $context = Get-MgContext
    if ($null -eq $context) {
        throw "ERROR: No conectado a Microsoft Graph"
    }
    
    $requiredScopes = $script:RequiredPermissions.EntraID[$Phase]
    $grantedScopes = $context.Scopes
    
    foreach ($scope in $requiredScopes) {
        if ($scope -notin $grantedScopes) {
            throw "ERROR: Falta permiso: $scope"
        }
    }
    
    Write-Log "Permisos validados" -Level Success
    Write-Log "Usuario: $($context.Account)" -Level Info
    
    # NUEVO: Validar expiración de token
    Test-TokenExpiration
}

function Test-AzureRBACPrerequisites {
    [CmdletBinding()]
    param()
    
    Write-Log "=== Validando Prerequisites Azure RBAC ===" -Level Info
    
    if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
        Write-Log "Instalando Az.Resources..." -Level Warning
        Install-Module Az.Resources -Scope CurrentUser -Force -AllowClobber
    }
    
    Import-Module Az.Resources -ErrorAction Stop
    
    $azContext = Get-AzContext
    if ($null -eq $azContext) {
        Write-Log "Conectando a Azure..." -Level Warning
        Connect-AzAccount
        $azContext = Get-AzContext
    }
    
    if ($null -eq $azContext) {
        throw "ERROR: No se pudo conectar a Azure"
    }
    
    Write-Log "Conectado a Azure" -Level Success
    Write-Log "Suscripción actual: $($azContext.Subscription.Name)" -Level Info
    
    # Obtener lista de suscripciones a procesar
    $subscriptionsToProcess = Get-SubscriptionsToProcess
    
    Write-Log "Suscripciones a procesar: $($subscriptionsToProcess.Count)" -Level Info
    
    # NUEVO: Validar acceso a cada suscripción
    $accessibleSubs = @()
    foreach ($sub in $subscriptionsToProcess) {
        try {
            Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
            Write-Log "  ✓ $($sub.Name) ($($sub.Id))" -Level Success
            $accessibleSubs += $sub
        }
        catch {
            Write-Log "  ✗ Sin acceso: $($sub.Name)" -Level Warning
        }
    }
    
    if ($accessibleSubs.Count -eq 0) {
        throw "ERROR: Sin acceso a ninguna suscripción"
    }
    
    # Restaurar contexto original
    Set-AzContext -SubscriptionId $azContext.Subscription.Id | Out-Null
    
    # Inicializar cache con roles de la suscripción actual
    Initialize-AzureRoleDefinitionsCache
    
    return $azContext
}

function Get-SubscriptionsToProcess {
    <#
    .SYNOPSIS
        Determina qué suscripciones procesar según parámetros
    #>
    [CmdletBinding()]
    param()
    
    if ($AllSubscriptions) {
        Write-Log "Modo: Todas las suscripciones del tenant" -Level Info
        $allSubs = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }
        return $allSubs
    }
    elseif ($SubscriptionIds) {
        Write-Log "Modo: Suscripciones específicas ($($SubscriptionIds.Count))" -Level Info
        $subs = @()
        foreach ($subId in $SubscriptionIds) {
            $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue
            if ($sub) {
                $subs += $sub
            }
            else {
                Write-Log "Advertencia: Suscripción no encontrada: $subId" -Level Warning
            }
        }
        return $subs
    }
    else {
        $currentContext = Get-AzContext
        Write-Log "Modo: Solo suscripción actual" -Level Info
        return @(Get-AzSubscription -SubscriptionId $currentContext.Subscription.Id)
    }
}

function Set-AzureSubscriptionContext {
    <#
    .SYNOPSIS
        Cambia el contexto a una suscripción específica
    #>
    [CmdletBinding()]
    param([string]$SubscriptionId)
    
    try {
        $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
        Write-Verbose "Contexto cambiado a suscripción: $($context.Subscription.Name)"
        
        # Actualizar cache de roles para esta suscripción
        $script:AzureRoleDefinitionsCache = @{}
        Initialize-AzureRoleDefinitionsCache
        
        return $context
    }
    catch {
        Write-Log "Error cambiando a suscripción $SubscriptionId: $_" -Level Error
        throw
    }
}

function Test-CsvStructureExtended {
    [CmdletBinding()]
    param([array]$CsvData)
    
    Write-Log "=== Validando Estructura CSV ===" -Level Info
    
    $requiredColumns = @('PrincipalId', 'Reason', 'Duration')
    $csvHeaders = $CsvData[0].PSObject.Properties.Name
    
    foreach ($col in $requiredColumns) {
        if ($col -notin $csvHeaders) {
            throw "ERROR: Falta columna requerida: $col"
        }
    }
    
    $hasEntraRole = ($csvHeaders -contains 'RoleDefinitionId' -and $csvHeaders -contains 'DirectoryScopeId')
    $hasAzureRole = ($csvHeaders -contains 'AzureRoleDefinitionId' -and $csvHeaders -contains 'AzureScope')
    $hasGroup = ($csvHeaders -contains 'GroupId')
    
    if (-not ($hasEntraRole -or $hasAzureRole -or $hasGroup)) {
        throw "ERROR: CSV debe contener RoleDefinitionId+DirectoryScopeId, AzureRoleDefinitionId+AzureScope, o GroupId"
    }
    
    if ($hasAzureRole -and -not $SupportAzureRBAC) {
        Write-Log "CSV contiene roles Azure pero -SupportAzureRBAC no habilitado" -Level Warning
    }
    
    Write-Log "Estructura CSV válida: $($CsvData.Count) filas" -Level Success
}

function Test-InputValidations {
    [CmdletBinding()]
    param([hashtable]$Row)
    
    $errors = @()
    
    try { [System.Guid]::Parse($Row.PrincipalId) | Out-Null }
    catch { $errors += "PrincipalId inválido: $($Row.PrincipalId)" }
    
    if ($Row.RoleDefinitionId) {
        try { [System.Guid]::Parse($Row.RoleDefinitionId) | Out-Null }
        catch { $errors += "RoleDefinitionId inválido: $($Row.RoleDefinitionId)" }
    }
    
    if ($Row.AzureRoleDefinitionId) {
        try { [System.Guid]::Parse($Row.AzureRoleDefinitionId) | Out-Null }
        catch { $errors += "AzureRoleDefinitionId inválido: $($Row.AzureRoleDefinitionId)" }
    }
    
    if ($Row.GroupId) {
        try { [System.Guid]::Parse($Row.GroupId) | Out-Null }
        catch { $errors += "GroupId inválido: $($Row.GroupId)" }
    }
    
    # CORRECCIÓN: Agregar $ al final de la regex
    if ($Row.Duration -notmatch '^P(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?) {
        $errors += "Duration formato ISO-8601 inválido: $($Row.Duration)"
    }
    
    if ($Row.Reason.Length -lt 5) {
        $errors += "Justificación insuficiente (mínimo 5 caracteres)"
    }
    
    if ($errors.Count -gt 0) {
        Write-Log "Validaciones fallidas para Principal $($Row.PrincipalId):" -Level Warning
        $errors | ForEach-Object { Write-Log "  - $_" -Level Warning }
        return $false
    }
    
    return $true
}

#endregion

#region Main Processing

function New-PIMEligibilityAssignmentExtended {
    [CmdletBinding()]
    param(
        [hashtable]$Row,
        [int]$Phase
    )
    
    $script:Statistics.Total++
    
    # Progress bar global
    if ($script:Statistics.Total % 10 -eq 0) {
        $percentComplete = if ($script:Statistics.Total -gt 0) { 
            ($script:Statistics.Success / $script:Statistics.Total) * 100 
        } else { 0 }
        
        Write-Progress -Activity "Procesamiento PIM Global" `
            -Status "$($script:Statistics.Success)/$($script:Statistics.Total) completados" `
            -PercentComplete $percentComplete
    }
    
    try {
        $isEntraRole = ($Row.RoleDefinitionId -and $Row.DirectoryScopeId)
        $isAzureRole = ($Row.AzureRoleDefinitionId -and $Row.AzureScope)
        $isGroup = ($Row.GroupId)
        
        # === AZURE RBAC ===
        if ($isAzureRole) {
            if (-not $SupportAzureRBAC) {
                Write-Log "Omitido: Rol Azure sin -SupportAzureRBAC" -Level Warning
                $script:Statistics.Skipped++
                return
            }
            
            if (-not (Test-AzureRoleAllowedByGuid -RoleDefinitionId $Row.AzureRoleDefinitionId -PrincipalId $Row.PrincipalId)) {
                $script:Statistics.Failed++
                return
            }
            
            $conflictCheck = Test-ExistingAzureRoleAssignmentWithAncestors `
                -PrincipalId $Row.PrincipalId `
                -RoleDefinitionId $Row.AzureRoleDefinitionId `
                -Scope $Row.AzureScope
            
            if ($conflictCheck.HasConflict) {
                if ($conflictCheck.HasGroupInherited) {
                    Write-Log "⚠️  Asignaciones heredadas por GRUPO detectadas" -Level Warning
                    Write-Log "    AutoMigrate solo procesará asignaciones directas" -Level Warning
                }
                
                if ($AutoMigrate) {
                    $removableAssignments = $conflictCheck.Assignments | Where-Object { $_.CanAutoRemove }
                    $groupInheritedAssignments = $conflictCheck.Assignments | Where-Object { $_.IsGroupInherited }
                    
                    if ($removableAssignments.Count -eq 0 -and $groupInheritedAssignments.Count -gt 0) {
                        Write-Log "SKIP: TODAS las asignaciones son heredadas por grupo" -Level Warning
                        $script:Statistics.Skipped++
                        return
                    }
                    
                    Write-Log "AutoMigrate: Procesando $($removableAssignments.Count) asignaciones directas..." -Level Warning
                    
                    if (-not $DryRun) {
                        $eligibility = New-AzureRBACEligibility `
                            -PrincipalId $Row.PrincipalId `
                            -RoleDefinitionId $Row.AzureRoleDefinitionId `
                            -Scope $Row.AzureScope `
                            -Justification $Row.Reason `
                            -Duration $Row.Duration
                        
                        Write-Log "✓ Eligibilidad Azure creada" -Level Success
                        
                        $removedCount = 0
                        foreach ($assignment in $removableAssignments) {
                            $removed = Remove-AzureRoleAssignmentSafe -Assignment $assignment -PrincipalId $Row.PrincipalId
                            if ($removed) {
                                $removedCount++
                                $script:Statistics.Migrated++
                            }
                        }
                        
                        $script:Statistics.Success++
                        $script:Statistics.AzureRoles++
                        
                        $roleName = Get-AzureRoleNameById -RoleDefinitionId $Row.AzureRoleDefinitionId
                        $details = "Eligibilidad creada, $removedCount permanentes removidos"
                        if ($groupInheritedAssignments.Count -gt 0) {
                            $details += ", $($groupInheritedAssignments.Count) heredadas por grupo requieren acción manual"
                        }
                        
                        Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $roleName `
                            -Action "AzureMigrated" -Status "Success" `
                            -Details $details `
                            -RequestId $eligibility.Name -Scope $Row.AzureScope
                    }
                    else {
                        $roleName = Get-AzureRoleNameById -RoleDefinitionId $Row.AzureRoleDefinitionId
                        Write-Log "[DRY-RUN] Eligibilidad: $roleName" -Level Warning
                        Write-Log "[DRY-RUN] Remover: $($removableAssignments.Count) directas" -Level Warning
                        if ($groupInheritedAssignments.Count -gt 0) {
                            Write-Log "[DRY-RUN] Omitir: $($groupInheritedAssignments.Count) heredadas por grupo" -Level Warning
                        }
                        $script:Statistics.Success++
                        $script:Statistics.AzureRoles++
                    }
                }
                else {
                    Write-Log "Conflicto detectado. Use -AutoMigrate" -Level Warning
                    $script:Statistics.Skipped++
                    return
                }
                return
            }
            
            if (Test-ExistingAzureEligibility -PrincipalId $Row.PrincipalId `
                    -RoleDefinitionId $Row.AzureRoleDefinitionId -Scope $Row.AzureScope) {
                return
            }
            
            if ($Phase -ge 1) {
                if (-not (Test-InputValidations -Row $Row)) {
                    $script:Statistics.Failed++
                    return
                }
                
                $roleConfig = $null
                foreach ($tier in $script:AllowedAzureRoles.Keys) {
                    if ($script:AllowedAzureRoles[$tier].ContainsKey($Row.AzureRoleDefinitionId)) {
                        $roleConfig = $script:AllowedAzureRoles[$tier][$Row.AzureRoleDefinitionId]
                        break
                    }
                }
                
                if ($roleConfig) {
                    $requestedDuration = [System.Xml.XmlConvert]::ToTimeSpan($Row.Duration)
                    $maxDuration = [System.Xml.XmlConvert]::ToTimeSpan($roleConfig.MaxDuration)
                    
                    if ($requestedDuration -gt $maxDuration) {
                        $roleName = Get-AzureRoleNameById -RoleDefinitionId $Row.AzureRoleDefinitionId
                        Write-Log "Duración excede límite: $($Row.Duration) > $($roleConfig.MaxDuration)" -Level Warning
                        $script:Statistics.Failed++
                        return
                    }
                }
            }
            
            if ($DryRun) {
                $roleName = Get-AzureRoleNameById -RoleDefinitionId $Row.AzureRoleDefinitionId
                Write-Log "[DRY-RUN] Eligibilidad Azure: $roleName" -Level Info
                Write-Log "[DRY-RUN] Scope: $($Row.AzureScope) | Duration: $($Row.Duration)" -Level Info
                $script:Statistics.Success++
                $script:Statistics.AzureRoles++
                Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $roleName `
                    -Action "AzureDryRunSimulated" -Status "Success" -Scope $Row.AzureScope
                return
            }
            
            if ($Phase -ge 2) {
                $response = Invoke-WithRetry -ScriptBlock {
                    New-AzureRBACEligibility -PrincipalId $Row.PrincipalId `
                        -RoleDefinitionId $Row.AzureRoleDefinitionId `
                        -Scope $Row.AzureScope `
                        -Justification $Row.Reason `
                        -Duration $Row.Duration
                }
            }
            else {
                $response = New-AzureRBACEligibility -PrincipalId $Row.PrincipalId `
                    -RoleDefinitionId $Row.AzureRoleDefinitionId `
                    -Scope $Row.AzureScope `
                    -Justification $Row.Reason `
                    -Duration $Row.Duration
            }
            
            $roleName = Get-AzureRoleNameById -RoleDefinitionId $Row.AzureRoleDefinitionId
            Write-Log "✓ Eligibilidad Azure creada: $roleName" -Level Success
            $script:Statistics.Success++
            $script:Statistics.AzureRoles++
            Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $roleName `
                -Action "AzureEligibilityCreated" -Status "Success" `
                -Details "Scope: $($Row.AzureScope)" -RequestId $response.Name -Scope $Row.AzureScope
            
            return
        }
        
        # === ENTRA ID ROLES ===
        if ($isEntraRole) {
            if (-not (Test-EntraRoleAllowed -RoleDefinitionId $Row.RoleDefinitionId -PrincipalId $Row.PrincipalId)) {
                $script:Statistics.Failed++
                return
            }
            
            $conflictCheck = Test-ExistingEntraRoleAssignment `
                -PrincipalId $Row.PrincipalId `
                -RoleDefinitionId $Row.RoleDefinitionId `
                -DirectoryScopeId $Row.DirectoryScopeId
            
            if ($conflictCheck.HasConflict) {
                if ($AutoMigrate) {
                    Write-Log "AutoMigrate Entra ID: Creando eligibilidad y removiendo permanente..." -Level Warning
                    
                    if (-not $DryRun) {
                        $eligibility = New-EntraIDEligibility `
                            -PrincipalId $Row.PrincipalId `
                            -RoleDefinitionId $Row.RoleDefinitionId `
                            -DirectoryScopeId $Row.DirectoryScopeId `
                            -Justification $Row.Reason `
                            -Duration $Row.Duration
                        
                        Write-Log "✓ Eligibilidad Entra ID creada" -Level Success
                        
                        foreach ($assignment in $conflictCheck.Assignments) {
                            $removed = Remove-EntraRoleAssignmentSafe -Assignment $assignment -PrincipalId $Row.PrincipalId
                            if ($removed) {
                                $script:Statistics.Migrated++
                            }
                        }
                        
                        $script:Statistics.Success++
                        $script:Statistics.EntraRoles++
                        
                        Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.RoleDefinitionId `
                            -Action "EntraMigrated" -Status "Success" `
                            -Details "Eligibilidad creada y $($conflictCheck.Assignments.Count) permanentes removidos" `
                            -RequestId $eligibility.Id
                    }
                    else {
                        Write-Log "[DRY-RUN] Se crearía eligibilidad Entra ID y removerían $($conflictCheck.Assignments.Count) permanentes" -Level Warning
                        $script:Statistics.Success++
                        $script:Statistics.EntraRoles++
                    }
                }
                else {
                    Write-Log "Conflicto Entra ID. Use -AutoMigrate" -Level Warning
                    $script:Statistics.Skipped++
                    return
                }
                return
            }
            
            if (Test-ExistingEntraEligibility -PrincipalId $Row.PrincipalId -RoleDefinitionId $Row.RoleDefinitionId) {
                return
            }
            
            if ($Phase -ge 1) {
                if (-not (Test-InputValidations -Row $Row)) {
                    $script:Statistics.Failed++
                    return
                }
                
                if (-not (Test-EntraDurationCompliance -RoleDefinitionId $Row.RoleDefinitionId -Duration $Row.Duration)) {
                    $script:Statistics.Failed++
                    return
                }
            }
            
            if ($DryRun) {
                Write-Log "[DRY-RUN] Eligibilidad Entra ID: $($Row.RoleDefinitionId)" -Level Info
                $script:Statistics.Success++
                $script:Statistics.EntraRoles++
                Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.RoleDefinitionId `
                    -Action "EntraDryRunSimulated" -Status "Success"
                return
            }
            
            if ($Phase -ge 2) {
                $response = Invoke-WithRetry -ScriptBlock {
                    New-EntraIDEligibility -PrincipalId $Row.PrincipalId `
                        -RoleDefinitionId $Row.RoleDefinitionId `
                        -DirectoryScopeId $Row.DirectoryScopeId `
                        -Justification $Row.Reason `
                        -Duration $Row.Duration
                }
            }
            else {
                $response = New-EntraIDEligibility -PrincipalId $Row.PrincipalId `
                    -RoleDefinitionId $Row.RoleDefinitionId `
                    -DirectoryScopeId $Row.DirectoryScopeId `
                    -Justification $Row.Reason `
                    -Duration $Row.Duration
            }
            
            Write-Log "✓ Eligibilidad Entra ID creada: $($Row.RoleDefinitionId)" -Level Success
            $script:Statistics.Success++
            $script:Statistics.EntraRoles++
            Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.RoleDefinitionId `
                -Action "EntraEligibilityCreated" -Status "Success" -RequestId $response.Id
            
            return
        }
        
        # === GRUPOS PIM ===
        if ($isGroup) {
            if (Test-ExistingGroupEligibility -PrincipalId $Row.PrincipalId -GroupId $Row.GroupId) {
                return
            }
            
            if ($Phase -ge 1 -and -not (Test-InputValidations -Row $Row)) {
                $script:Statistics.Failed++
                return
            }
            
            if ($DryRun) {
                Write-Log "[DRY-RUN] Membresía grupo: $($Row.GroupId)" -Level Info
                $script:Statistics.Success++
                $script:Statistics.Groups++
                return
            }
            
            if ($Phase -ge 2) {
                $response = Invoke-WithRetry -ScriptBlock {
                    New-GroupEligibility -PrincipalId $Row.PrincipalId `
                        -GroupId $Row.GroupId `
                        -Justification $Row.Reason `
                        -Duration $Row.Duration
                }
            }
            else {
                $response = New-GroupEligibility -PrincipalId $Row.PrincipalId `
                    -GroupId $Row.GroupId `
                    -Justification $Row.Reason `
                    -Duration $Row.Duration
            }
            
            Write-Log "✓ Membresía grupo creada" -Level Success
            $script:Statistics.Success++
            $script:Statistics.Groups++
            Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.GroupId `
                -Action "GroupMembershipCreated" -Status "Success" -RequestId $response.Id
            
            return
        }
        
        Write-Log "Fila omitida: sin tipo válido" -Level Warning
        $script:Statistics.Skipped++
    }
    catch {
        Write-Log "Error procesando Principal $($Row.PrincipalId): $_" -Level Error
        $script:Statistics.Failed++
        Add-AuditEntry -PrincipalId $Row.PrincipalId -Action "Error" -Status "Failed" `
            -Details $_.Exception.Message
    }
}

function Start-PIMAssignmentExtended {
    [CmdletBinding()]
    param()
    
    $title = if ($SupportAzureRBAC) { "PIM Assignment - Fase $Phase [Entra ID + Azure RBAC]" } 
             else { "PIM Assignment - Fase $Phase [Solo Entra ID]" }
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  $title  ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    if ($AutoMigrate) {
        Write-Host "⚠️  AUTO-MIGRATE ACTIVO: Roles permanentes DIRECTOS serán migrados" -ForegroundColor Yellow
        Write-Host "⚠️  Roles heredados por GRUPO requerirán acción manual" -ForegroundColor Yellow
    }
    
    if ($AllSubscriptions) {
        Write-Host "🌐 MULTI-SUSCRIPCIÓN: Procesando todas las suscripciones del tenant" -ForegroundColor Cyan
    }
    elseif ($SubscriptionIds) {
        Write-Host "🎯 MULTI-SUSCRIPCIÓN: Procesando $($SubscriptionIds.Count) suscripciones específicas" -ForegroundColor Cyan
    }
    
    # Cargar configuración externa
    if (Test-Path $AllowedRolesConfigPath) {
        $configLoaded = Import-AllowedRolesConfiguration -ConfigPath $AllowedRolesConfigPath
        if ($configLoaded) {
            Write-Host "✓ Configuración cargada desde: $AllowedRolesConfigPath" -ForegroundColor Green
        }
    }
    
    Test-Prerequisites -Phase $Phase
    
    $subscriptionsToProcess = @()
    if ($SupportAzureRBAC) {
        $azContext = Test-AzureRBACPrerequisites
        $subscriptionsToProcess = Get-SubscriptionsToProcess
    }
    
    Write-Log "=== Cargando CSV ===" -Level Info
    $csvData = Import-Csv -Path $CsvPath -Encoding UTF8
    Test-CsvStructureExtended -CsvData $csvData
    
    # Agrupar asignaciones por suscripción
    $assignmentsBySubscription = @{}
    $nonAzureAssignments = @()
    
    foreach ($row in $csvData) {
        if ($row.AzureScope) {
            if ($row.AzureScope -match '/subscriptions/([^/]+)') {
                $subId = $matches[1]
                if (-not $assignmentsBySubscription.ContainsKey($subId)) {
                    $assignmentsBySubscription[$subId] = @()
                }
                $assignmentsBySubscription[$subId] += $row
            }
            else {
                Write-Log "Advertencia: Scope inválido en fila: $($row.AzureScope)" -Level Warning
            }
        }
        else {
            $nonAzureAssignments += $row
        }
    }
    
    if (-not $Force -and -not $DryRun) {
        Write-Host "`n⚠️  CONFIRMACIÓN:" -ForegroundColor Yellow
        Write-Host "  Asignaciones totales: $($csvData.Count)" -ForegroundColor White
        Write-Host "  - Entra ID/Grupos: $($nonAzureAssignments.Count)" -ForegroundColor White
        Write-Host "  - Azure RBAC: $($csvData.Count - $nonAzureAssignments.Count)" -ForegroundColor White
        if ($SupportAzureRBAC) {
            Write-Host "  Suscripciones afectadas: $($assignmentsBySubscription.Keys.Count)" -ForegroundColor White
        }
        Write-Host "  Fase: $Phase" -ForegroundColor White
        Write-Host "  Modo: PRODUCCIÓN" -ForegroundColor White
        if ($AutoMigrate) {
            Write-Host "  AutoMigrate: HABILITADO" -ForegroundColor Yellow
        }
        
        $confirm = Read-Host "`n¿Continuar? (escriba 'SI')"
        if ($confirm -ne 'SI') {
            Write-Log "Operación cancelada" -Level Warning
            return
        }
    }
    
    Write-Log "=== Procesando Asignaciones ===" -Level Info
    if ($DryRun) {
        Write-Host "[MODO DRY-RUN ACTIVO]`n" -ForegroundColor Yellow
    }
    
    # Procesar asignaciones no-Azure primero
    if ($nonAzureAssignments.Count -gt 0) {
        Write-Log "=== Procesando Asignaciones Entra ID y Grupos ($($nonAzureAssignments.Count)) ===" -Level Info
        
        $progress = 0
        foreach ($row in $nonAzureAssignments) {
            $progress++
            Write-Progress -Activity "Procesando asignaciones no-Azure" `
                -Status "Fila $progress de $($nonAzureAssignments.Count)" `
                -PercentComplete (($progress / $nonAzureAssignments.Count) * 100)
            
            Write-Log "[$progress/$($nonAzureAssignments.Count)] Principal: $($row.PrincipalId)" -Level Info
            
            $rowHash = @{}
            $row.PSObject.Properties | ForEach-Object { $rowHash[$_.Name] = $_.Value }
            
            New-PIMEligibilityAssignmentExtended -Row $rowHash -Phase $Phase
        }
        Write-Progress -Activity "Procesando asignaciones no-Azure" -Completed
    }
    
    # Procesar asignaciones Azure RBAC por suscripción
    if ($SupportAzureRBAC -and $assignmentsBySubscription.Keys.Count -gt 0) {
        $currentSubIndex = 0
        foreach ($subId in $assignmentsBySubscription.Keys) {
            $currentSubIndex++
            $assignments = $assignmentsBySubscription[$subId]
            
            $shouldProcess = $false
            if ($AllSubscriptions) {
                $shouldProcess = $true
            }
            elseif ($SubscriptionIds) {
                $shouldProcess = $subId -in $SubscriptionIds
            }
            else {
                $currentContext = Get-AzContext
                $shouldProcess = $subId -eq $currentContext.Subscription.Id
            }
            
            if (-not $shouldProcess) {
                Write-Log "Omitiendo suscripción $subId (no en scope de procesamiento)" -Level Warning
                $script:Statistics.Skipped += $assignments.Count
                continue
            }
            
            $subscription = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue
            if (-not $subscription) {
                Write-Log "Suscripción no encontrada: $subId" -Level Error
                $script:Statistics.Failed += $assignments.Count
                continue
            }
            
            Write-Log "`n=== Procesando Suscripción [$currentSubIndex/$($assignmentsBySubscription.Keys.Count)]: $($subscription.Name) ($subId) ===" -Level Info
            Write-Log "Asignaciones en esta suscripción: $($assignments.Count)" -Level Info
            
            try {
                Set-AzureSubscriptionContext -SubscriptionId $subId
                $script:Statistics.SubscriptionsProcessed++
                $script:ProcessedSubscriptions += $subscription.Name
            }
            catch {
                Write-Log "Error cambiando a suscripción $($subscription.Name): $_" -Level Error
                $script:Statistics.Failed += $assignments.Count
                continue
            }
            
            $progress = 0
            foreach ($row in $assignments) {
                $progress++
                Write-Progress -Activity "Procesando suscripción: $($subscription.Name)" `
                    -Status "Fila $progress de $($assignments.Count)" `
                    -PercentComplete (($progress / $assignments.Count) * 100)
                
                Write-Log "  [$progress/$($assignments.Count)] Principal: $($row.PrincipalId)" -Level Info
                
                $rowHash = @{}
                $row.PSObject.Properties | ForEach-Object { $rowHash[$_.Name] = $_.Value }
                
                New-PIMEligibilityAssignmentExtended -Row $rowHash -Phase $Phase
            }
            Write-Progress -Activity "Procesando suscripción: $($subscription.Name)" -Completed
        }
    }
    
    Write-Progress -Activity "Procesamiento PIM Global" -Completed
    
    Write-Log "=== Generando Reportes ===" -Level Info
    Export-AuditReportExtended
    
    if ($DryRun) {
        Write-Log "✓ Simulación completada" -Level Success
    }
    else {
        Write-Log "✓ Procesamiento completado" -Level Success
    }
}

function Export-AuditReportExtended {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $shortHash = $script:CsvHash.Substring(0, 8)
    
    $csvFile = "PIM_Audit_${shortHash}_${timestamp}.csv"
    $script:AuditLog | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Log "✓ Reporte CSV: $csvFile" -Level Success
    
    $jsonFile = "PIM_Audit_${shortHash}_${timestamp}.json"
    $auditData = @{
        Metadata = @{
            CsvHash = $script:CsvHash
            ConfigHash = $script:AllowedRolesConfigHash
            Phase = $Phase
            DryRun = $DryRun.IsPresent
            AutoMigrate = $AutoMigrate.IsPresent
            AzureRBACSupport = $SupportAzureRBAC.IsPresent
            ExecutedBy = try { (Get-MgContext).Account } catch { "Unknown" }
            ExecutedAt = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        }
        Statistics = $script:Statistics
        Entries = $script:AuditLog
    }
    $auditData | ConvertTo-Json -Depth 10 | Out-File $jsonFile -Encoding UTF8
    Write-Log "✓ Reporte JSON: $jsonFile" -Level Success
    
    Write-Host "`n╔════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  RESUMEN DE EJECUCIÓN              ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "Total:      $($script:Statistics.Total)" -ForegroundColor White
    Write-Host "Exitoso:    $($script:Statistics.Success)" -ForegroundColor Green
    Write-Host "  - Entra:  $($script:Statistics.EntraRoles)" -ForegroundColor White
    Write-Host "  - Azure:  $($script:Statistics.AzureRoles)" -ForegroundColor White
    Write-Host "  - Grupos: $($script:Statistics.Groups)" -ForegroundColor White
    if ($SupportAzureRBAC) {
        Write-Host "Suscripciones procesadas: $($script:Statistics.SubscriptionsProcessed)" -ForegroundColor Cyan
        if ($script:ProcessedSubscriptions.Count -gt 0) {
            Write-Host "  Suscripciones:" -ForegroundColor White
            $script:ProcessedSubscriptions | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkGray }
        }
    }
    if ($AutoMigrate) {
        Write-Host "Migrados:   $($script:Statistics.Migrated)" -ForegroundColor Cyan
        if ($script:Statistics.GroupInheritedSkipped -gt 0) {
            Write-Host "  ⚠️  Heredados por grupo (requieren acción manual): $($script:Statistics.GroupInheritedSkipped)" -ForegroundColor Yellow
        }
    }
    Write-Host "Fallido:    $($script:Statistics.Failed)" -ForegroundColor Red
    Write-Host "Omitido:    $($script:Statistics.Skipped)" -ForegroundColor Yellow
    Write-Host "Conflictos: $($script:Statistics.Conflicts)" -ForegroundColor Magenta
    
    if ($script:AllowedRolesConfigHash) {
        Write-Host "`nConfig Hash: $($script:AllowedRolesConfigHash.Substring(0,16))..." -ForegroundColor DarkGray
    }
}

#endregion

#region Main Execution

if ($ExtractRoles) {
    try {
        Get-AllRoleDefinitions -ExportCsv:$ExportRolesCsv -OutputPath $RolesOutputPath
    }
    catch {
        Write-Log "Error en extracción: $_" -Level Error
    }
    exit 0
}

if (-not $CsvPath) {
    Write-Host "ERROR: -CsvPath es obligatorio (o use -ExtractRoles)" -ForegroundColor Red
    Write-Host "`nEjemplos:" -ForegroundColor Yellow
    Write-Host "  .\PIM-SecureAssignment-ARM.ps1 -ExtractRoles -SupportAzureRBAC -ExportRolesCsv" -ForegroundColor Cyan
    Write-Host "  .\PIM-SecureAssignment-ARM.ps1 -CsvPath 'file.csv' -Phase 1 -SupportAzureRBAC -DryRun" -ForegroundColor Cyan
    Write-Host "  .\PIM-SecureAssignment-ARM.ps1 -CsvPath 'file.csv' -Phase 2 -SupportAzureRBAC -AutoMigrate" -ForegroundColor Cyan
    exit 1
}

try {
    $transcriptFile = "PIM_Execution_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $transcriptFile
    
    Start-PIMAssignmentExtended
}
catch {
    Write-Log "Error fatal: $_" -Level Error
    $script:Statistics.Failed++
}
finally {
    Stop-Transcript
    Write-Host "`nLog completo: $transcriptFile" -ForegroundColor Cyan
}

#endregion<#
EFP
.SYNOPSIS
    Script PIM con soporte completo Azure RBAC - VERSIÓN COMPLETA
    
.DESCRIPTION
    Mejoras implementadas:
    - Extracción de roles integrada (-ExtractRoles)
    - Lista blanca por RoleDefinitionId (GUID) en lugar de nombres
    - Detección de roles heredados por ancestros de scope
    - Migración automática controlada (crear elegible + revocar permanente)
    
.PARAMETER CsvPath
    Ruta al archivo CSV con las asignaciones
    
.PARAMETER Phase
    Fase de controles (0, 1, 2)
    
.PARAMETER SupportAzureRBAC
    Habilita soporte para roles Azure ARM
    
.PARAMETER AutoMigrate
    Habilita migración automática de roles permanentes a PIM
    
.PARAMETER ExtractRoles
    Modo extracción de roles (no requiere CsvPath ni Phase)
    
.PARAMETER DryRun
    Modo simulación
    
.EXAMPLE
    # Extraer roles
    .\PIM-SecureAssignment-ARM.ps1 -ExtractRoles -SupportAzureRBAC -ExportRolesCsv
    
    # Procesar asignaciones
    .\PIM-SecureAssignment-ARM.ps1 -CsvPath "file.csv" -Phase 1 -SupportAzureRBAC -AutoMigrate -DryRun
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet(0, 1, 2)]
    [int]$Phase = 0,
    
    [switch]$SupportAzureRBAC,
    [switch]$AutoMigrate,
    [switch]$DryRun,
    [switch]$Force,
    
    # Parámetros para extracción de roles
    [switch]$ExtractRoles,
    [switch]$ExportRolesCsv,
    [string]$RolesOutputPath = "roles_reference.csv",
    
    # Nuevo: Soporte multi-suscripción
    [switch]$AllSubscriptions,
    [string[]]$SubscriptionIds
)

#region Configuration

# Lista blanca de roles Entra ID por GUID
$script:AllowedEntraRoles = @{
    Tier0 = @{
        '62e90394-69f5-4237-9190-012177145e10' = @{ Name = 'Global Administrator'; MaxDuration = 'PT8H'; RequiresApproval = $true }
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = @{ Name = 'Security Administrator'; MaxDuration = 'PT8H'; RequiresApproval = $true }
    }
    Tier1 = @{
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = @{ Name = 'SharePoint Administrator'; MaxDuration = 'P1D'; RequiresApproval = $true }
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = @{ Name = 'User Administrator'; MaxDuration = 'P1D'; RequiresApproval = $false }
    }
    Tier2 = @{
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' = @{ Name = 'Helpdesk Administrator'; MaxDuration = 'P7D'; RequiresApproval = $false }
    }
}

# Lista blanca de roles Azure RBAC por RoleDefinitionId (GUID)
$script:AllowedAzureRoles = @{
    Tier0 = @{
        '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = @{ Name = 'Owner'; MaxDuration = 'PT4H'; RequiresApproval = $true }
        '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = @{ Name = 'User Access Administrator'; MaxDuration = 'PT4H'; RequiresApproval = $true }
    }
    Tier1 = @{
        'b24988ac-6180-42a0-ab88-20f7382dd24c' = @{ Name = 'Contributor'; MaxDuration = 'PT8H'; RequiresApproval = $true }
        '9980e02c-c2be-4d73-94e8-173b1dc7cf3c' = @{ Name = 'Virtual Machine Contributor'; MaxDuration = 'P1D'; RequiresApproval = $false }
        '17d1049b-9a84-46fb-8f53-869881c3d3ab' = @{ Name = 'Storage Account Contributor'; MaxDuration = 'P1D'; RequiresApproval = $false }
        '4d97b98b-1d4f-4787-a291-c67834d212e7' = @{ Name = 'Network Contributor'; MaxDuration = 'P1D'; RequiresApproval = $false }
    }
    Tier2 = @{
        'acdd72a7-3385-48ef-bd42-f606fba81ae7' = @{ Name = 'Reader'; MaxDuration = 'P30D'; RequiresApproval = $false }
        '43d0d8ad-25c7-4714-9337-8ba259a9fe05' = @{ Name = 'Monitoring Reader'; MaxDuration = 'P30D'; RequiresApproval = $false }
        '73c42c96-874c-492b-b04d-ab87d138a893' = @{ Name = 'Log Analytics Reader'; MaxDuration = 'P30D'; RequiresApproval = $false }
    }
}

# Cache de definiciones de roles Azure
$script:AzureRoleDefinitionsCache = @{}

# Permisos requeridos
$script:RequiredPermissions = @{
    EntraID = @{
        0 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup')
        1 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup', 'RoleManagement.Read.Directory')
        2 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup', 'RoleManagement.Read.Directory', 'Policy.Read.All')
    }
}

# Variables globales
$script:AuditLog = @()
$script:CsvHash = $null
$script:ProcessedSubscriptions = @()
$script:Statistics = @{
    Total = 0
    Success = 0
    Failed = 0
    Skipped = 0
    Conflicts = 0
    Migrated = 0
    EntraRoles = 0
    AzureRoles = 0
    Groups = 0
    SubscriptionsProcessed = 0
}

#endregion

#region Utility Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $colors = @{
        Info = 'White'
        Success = 'Green'
        Warning = 'Yellow'
        Error = 'Red'
    }
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $colors[$Level]
}

function Add-AuditEntry {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleOrGroup = '',
        [string]$Action,
        [string]$Status,
        [string]$Details = '',
        [string]$RequestId = '',
        [string]$Scope = ''
    )
    
    $script:AuditLog += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        PrincipalId = $PrincipalId
        RoleOrGroup = $RoleOrGroup
        Scope = $Scope
        Action = $Action
        Status = $Status
        Details = $Details
        RequestId = $RequestId
        ExecutedBy = try { (Get-MgContext).Account } catch { "Unknown" }
        CsvHash = $script:CsvHash
        Phase = $Phase
        DryRun = $DryRun.IsPresent
        AutoMigrate = $AutoMigrate.IsPresent
    }
}

function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [int]$BaseDelaySeconds = 5
    )
    
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        try {
            return & $ScriptBlock
        }
        catch {
            if ($_.Exception.Message -match '429|TooManyRequests|throttl') {
                $attempt++
                if ($attempt -ge $MaxRetries) {
                    throw "Falló después de $MaxRetries intentos por throttling"
                }
                
                $delay = $BaseDelaySeconds * [Math]::Pow(2, $attempt)
                Write-Log "Throttling detectado. Reintento $attempt/$MaxRetries en $delay segundos..." -Level Warning
                Start-Sleep -Seconds $delay
            }
            else {
                throw
            }
        }
    }
}

#endregion

#region Role Extraction Functions

function Get-AllRoleDefinitions {
    <#
    .SYNOPSIS
        Extrae todos los roles de Entra ID y Azure RBAC con sus GUIDs
    #>
    [CmdletBinding()]
    param(
        [switch]$ExportCsv,
        [string]$OutputPath = "roles_reference.csv"
    )
    
    Write-Host "`n╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Extractor de RoleDefinitionId (GUIDs)        ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    $allRoles = @()
    
    # === ENTRA ID ROLES ===
    Write-Log "=== ROLES DE ENTRA ID (Azure AD) ===" -Level Info
    
    try {
        $context = Get-MgContext
        if (-not $context) {
            Write-Log "Conectando a Microsoft Graph..." -Level Warning
            Connect-MgGraph -Scopes "RoleManagement.Read.Directory" -NoWelcome
        }
        
        $entraRoles = Get-MgDirectoryRoleTemplate | Sort-Object DisplayName
        
        Write-Log "Roles de Entra ID encontrados: $($entraRoles.Count)" -Level Success
        Write-Host "`nFormato: DisplayName | RoleTemplateId (GUID)`n" -ForegroundColor Yellow
        
        foreach ($role in $entraRoles) {
            $roleData = [PSCustomObject]@{
                Type = "Entra ID"
                DisplayName = $role.DisplayName
                RoleDefinitionId = $role.Id
                Description = $role.Description
                IsBuiltIn = $true
                IsCustom = $false
            }
            
            $allRoles += $roleData
            
            Write-Host "$($role.DisplayName)" -ForegroundColor White -NoNewline
            Write-Host " | " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($role.Id)" -ForegroundColor Cyan
        }
        
        # Roles críticos
        Write-Host "`n--- ROLES CRÍTICOS DE ENTRA ID ---" -ForegroundColor Yellow
        $criticalEntraIds = @(
            '62e90394-69f5-4237-9190-012177145e10',
            '194ae4cb-b126-40b2-bd5b-6091b380977d',
            'f28a1f50-f6e7-4571-818b-6a12f2af6b6c',
            'fe930be7-5e62-47db-91af-98c3a49a38b1',
            '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        )
        
        foreach ($roleId in $criticalEntraIds) {
            $role = $entraRoles | Where-Object { $_.Id -eq $roleId }
            if ($role) {
                Write-Host "'$($role.Id)' = @{ Name = '$($role.DisplayName)'; MaxDuration = 'PT8H'; RequiresApproval = `$true }" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Log "Error obteniendo roles Entra ID: $_" -Level Error
    }
    
    # === AZURE RBAC ROLES ===
    if ($SupportAzureRBAC) {
        Write-Log "`n=== ROLES DE AZURE RBAC ===" -Level Info
        
        try {
            $azContext = Get-AzContext
            if (-not $azContext) {
                Write-Log "Conectando a Azure..." -Level Warning
                Connect-AzAccount
                $azContext = Get-AzContext
            }
            
            if ($azContext) {
                Write-Log "Suscripción activa: $($azContext.Subscription.Name)" -Level Info
                
                $azureRoles = Get-AzRoleDefinition | Sort-Object Name
                
                Write-Log "Roles de Azure encontrados: $($azureRoles.Count)" -Level Success
                Write-Host "`nFormato: Name | Id (GUID) | IsCustom`n" -ForegroundColor Yellow
                
                foreach ($role in $azureRoles) {
                    $roleData = [PSCustomObject]@{
                        Type = "Azure RBAC"
                        DisplayName = $role.Name
                        RoleDefinitionId = $role.Id
                        Description = $role.Description
                        IsBuiltIn = -not $role.IsCustom
                        IsCustom = $role.IsCustom
                    }
                    
                    $allRoles += $roleData
                    
                    $customTag = if ($role.IsCustom) { " [CUSTOM]" } else { "" }
                    Write-Host "$($role.Name)$customTag" -ForegroundColor White -NoNewline
                    Write-Host " | " -ForegroundColor DarkGray -NoNewline
                    Write-Host "$($role.Id)" -ForegroundColor Cyan
                }
                
                # Roles críticos de Azure
                Write-Host "`n--- ROLES CRÍTICOS DE AZURE RBAC ---" -ForegroundColor Yellow
                
                $criticalAzureRoles = @(
                    @{ Name = 'Owner'; MaxDuration = 'PT4H' },
                    @{ Name = 'User Access Administrator'; MaxDuration = 'PT4H' },
                    @{ Name = 'Contributor'; MaxDuration = 'PT8H' },
                    @{ Name = 'Virtual Machine Contributor'; MaxDuration = 'P1D' },
                    @{ Name = 'Storage Account Contributor'; MaxDuration = 'P1D' },
                    @{ Name = 'Network Contributor'; MaxDuration = 'P1D' },
                    @{ Name = 'Reader'; MaxDuration = 'P30D' }
                )
                
                foreach ($roleInfo in $criticalAzureRoles) {
                    $role = $azureRoles | Where-Object { $_.Name -eq $roleInfo.Name }
                    if ($role) {
                        Write-Host "'$($role.Id)' = @{ Name = '$($role.Name)'; MaxDuration = '$($roleInfo.MaxDuration)'; RequiresApproval = `$true }" -ForegroundColor Green
                    }
                }
                
                # Roles custom
                $customRoles = $azureRoles | Where-Object { $_.IsCustom -eq $true }
                if ($customRoles.Count -gt 0) {
                    Write-Host "`n--- ROLES CUSTOM DETECTADOS ---" -ForegroundColor Magenta
                    foreach ($role in $customRoles) {
                        Write-Host "'$($role.Id)' = @{ Name = '$($role.Name)'; MaxDuration = 'P1D'; RequiresApproval = `$true }  # CUSTOM" -ForegroundColor Magenta
                    }
                }
            }
        }
        catch {
            Write-Log "Error obteniendo roles Azure: $_" -Level Error
        }
    }
    
    # Exportar CSV
    if ($ExportCsv) {
        try {
            $allRoles | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Log "`n✓ CSV exportado: $OutputPath" -Level Success
        }
        catch {
            Write-Log "Error exportando CSV: $_" -Level Error
        }
    }
    
    Write-Host "`n✓ Extracción completada" -ForegroundColor Green
    return $allRoles
}

#endregion

#region Azure RBAC Enhanced Functions

function Initialize-AzureRoleDefinitionsCache {
    [CmdletBinding()]
    param()
    
    Write-Log "Inicializando cache de roles Azure..." -Level Info
    
    try {
        $allRoles = Get-AzRoleDefinition
        
        foreach ($role in $allRoles) {
            $script:AzureRoleDefinitionsCache[$role.Id] = @{
                Name = $role.Name
                Id = $role.Id
                Description = $role.Description
                IsCustom = $role.IsCustom
            }
        }
        
        Write-Log "Cache inicializado: $($script:AzureRoleDefinitionsCache.Count) roles" -Level Success
    }
    catch {
        Write-Log "Error inicializando cache: $_" -Level Error
        throw
    }
}

function Get-AzureRoleNameById {
    [CmdletBinding()]
    param([string]$RoleDefinitionId)
    
    if ($script:AzureRoleDefinitionsCache.ContainsKey($RoleDefinitionId)) {
        return $script:AzureRoleDefinitionsCache[$RoleDefinitionId].Name
    }
    
    $role = Get-AzRoleDefinition -Id $RoleDefinitionId -ErrorAction SilentlyContinue
    if ($role) {
        $script:AzureRoleDefinitionsCache[$RoleDefinitionId] = @{
            Name = $role.Name
            Id = $role.Id
            Description = $role.Description
            IsCustom = $role.IsCustom
        }
        return $role.Name
    }
    
    return $RoleDefinitionId
}

function Get-ScopeAncestors {
    [CmdletBinding()]
    param([string]$Scope)
    
    $ancestors = @()
    $currentScope = $Scope.TrimEnd('/')
    
    while ($currentScope -and $currentScope -ne '/') {
        $ancestors += $currentScope
        
        if ($currentScope -match '^(.+)/[^/]+$') {
            $currentScope = $matches[1]
        }
        else {
            break
        }
    }
    
    if ($ancestors[-1] -ne '/') {
        $ancestors += '/'
    }
    
    return $ancestors
}

function Test-AzureRoleAllowedByGuid {
    [CmdletBinding()]
    param(
        [string]$RoleDefinitionId,
        [string]$PrincipalId
    )
    
    $allAllowed = @{}
    foreach ($tier in $script:AllowedAzureRoles.Keys) {
        $allAllowed += $script:AllowedAzureRoles[$tier]
    }
    
    if ($RoleDefinitionId -notin $allAllowed.Keys) {
        $roleName = Get-AzureRoleNameById -RoleDefinitionId $RoleDefinitionId
        Write-Log "ROL BLOQUEADO: '$roleName' ($RoleDefinitionId) no autorizado" -Level Warning
        
        Add-AuditEntry -PrincipalId $PrincipalId -Action "AzureRoleBlocked" -Status "Blocked" `
            -Details "Rol no autorizado: $roleName ($RoleDefinitionId)"
        return $false
    }
    
    return $true
}

function Test-ExistingAzureRoleAssignmentWithAncestors {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$Scope
    )
    
    $roleName = Get-AzureRoleNameById -RoleDefinitionId $RoleDefinitionId
    $conflictingAssignments = @()
    
    $ancestors = Get-ScopeAncestors -Scope $Scope
    
    Write-Verbose "Verificando asignaciones en $($ancestors.Count) scopes (incluyendo ancestros)"
    
    foreach ($ancestorScope in $ancestors) {
        try {
            $assignments = Get-AzRoleAssignment -ObjectId $PrincipalId -Scope $ancestorScope -ErrorAction SilentlyContinue |
                Where-Object { $_.RoleDefinitionId -eq $RoleDefinitionId }
            
            if ($assignments) {
                foreach ($assignment in $assignments) {
                    $conflictingAssignments += [PSCustomObject]@{
                        Scope = $ancestorScope
                        RoleDefinitionId = $RoleDefinitionId
                        RoleName = $roleName
                        AssignmentId = $assignment.RoleAssignmentId
                        IsInherited = ($ancestorScope -ne $Scope)
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error verificando scope $ancestorScope: $_"
        }
    }
    
    if ($conflictingAssignments.Count -gt 0) {
        Write-Log "CONFLICTO AZURE: $($conflictingAssignments.Count) asignación(es) permanente(s) de '$roleName'" -Level Warning
        
        foreach ($conflict in $conflictingAssignments) {
            $inheritedMsg = if ($conflict.IsInherited) { " (HEREDADO)" } else { "" }
            Write-Log "  → Scope: $($conflict.Scope)$inheritedMsg" -Level Warning
        }
        
        $script:Statistics.Conflicts++
        Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $roleName `
            -Action "AzureConflictDetected" -Status "Warning" `
            -Details "Asignaciones: $($conflictingAssignments.Count) (incluyendo heredadas)" `
            -Scope $Scope
        
        return @{
            HasConflict = $true
            Assignments = $conflictingAssignments
        }
    }
    
    return @{ HasConflict = $false }
}

function Remove-AzureRoleAssignmentSafe {
    [CmdletBinding()]
    param(
        [PSCustomObject]$Assignment,
        [string]$PrincipalId
    )
    
    try {
        $roleName = Get-AzureRoleNameById -RoleDefinitionId $Assignment.RoleDefinitionId
        
        if ($DryRun) {
            Write-Log "[DRY-RUN] Removería: $roleName en $($Assignment.Scope)" -Level Warning
            return $true
        }
        
        Write-Log "Removiendo permanente: $roleName en $($Assignment.Scope)..." -Level Warning
        
        Remove-AzRoleAssignment -ObjectId $PrincipalId `
            -RoleDefinitionId $Assignment.RoleDefinitionId `
            -Scope $Assignment.Scope `
            -ErrorAction Stop
        
        Write-Log "✓ Asignación permanente removida" -Level Success
        
        Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $roleName `
            -Action "AzurePermanentRemoved" -Status "Success" `
            -Details "Removido de: $($Assignment.Scope)" `
            -Scope $Assignment.Scope
        
        return $true
    }
    catch {
        Write-Log "Error removiendo asignación: $_" -Level Error
        return $false
    }
}

function Test-ExistingAzureEligibility {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$Scope
    )
    
    try {
        $existing = Get-AzRoleEligibilityScheduleInstance -Scope $Scope -Filter "asTarget()" -ErrorAction SilentlyContinue |
            Where-Object { $_.PrincipalId -eq $PrincipalId -and $_.RoleDefinitionId -eq $RoleDefinitionId }
        
        if ($existing) {
            $roleName = Get-AzureRoleNameById -RoleDefinitionId $RoleDefinitionId
            Write-Log "IDEMPOTENCIA: Eligibilidad ya existe para '$roleName'" -Level Warning
            
            $script:Statistics.Skipped++
            Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $roleName `
                -Action "AzureSkipped" -Status "AlreadyExists" `
                -Details "Eligibilidad existente" -Scope $Scope
            return $true
        }
    }
    catch {
        Write-Verbose "Error verificando eligibilidad: $_"
    }
    
    return $false
}

function New-AzureRBACEligibility {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$Scope,
        [string]$Justification,
        [string]$Duration
    )
    
    try {
        $scheduleInfo = New-AzRoleEligibilityScheduleRequest `
            -Name (New-Guid) `
            -Scope $Scope `
            -PrincipalId $PrincipalId `
            -RoleDefinitionId $RoleDefinitionId `
            -RequestType "AdminAssign" `
            -Justification $Justification `
            -ScheduleInfoStartDateTime (Get-Date).ToUniversalTime() `
            -ExpirationType "AfterDuration" `
            -ExpirationDuration $Duration `
            -ErrorAction Stop
        
        return $scheduleInfo
    }
    catch {
        throw "Error creando eligibilidad Azure: $_"
    }
}

#endregion

#region Entra ID Functions

function Test-EntraRoleAllowed {
    [CmdletBinding()]
    param(
        [string]$RoleDefinitionId,
        [string]$PrincipalId
    )
    
    $allAllowed = @{}
    foreach ($tier in $script:AllowedEntraRoles.Keys) {
        $allAllowed += $script:AllowedEntraRoles[$tier]
    }
    
    if ($RoleDefinitionId -notin $allAllowed.Keys) {
        Write-Log "ROL ENTRA ID BLOQUEADO: $RoleDefinitionId no autorizado" -Level Warning
        Add-AuditEntry -PrincipalId $PrincipalId -Action "EntraRoleBlocked" -Status "Blocked" `
            -Details "Rol no autorizado: $RoleDefinitionId"
        return $false
    }
    
    return $true
}

function Test-ExistingEntraRoleAssignment {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$DirectoryScopeId
    )
    
    try {
        $filter = "principalId eq '$PrincipalId' and roleDefinitionId eq '$RoleDefinitionId'"
        $existing = Get-MgRoleManagementDirectoryRoleAssignment -Filter $filter -ErrorAction Stop
        
        if ($existing) {
            Write-Log "CONFLICTO ENTRA ID: Asignación permanente existe" -Level Warning
            
            $script:Statistics.Conflicts++
            Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $RoleDefinitionId `
                -Action "EntraConflictDetected" -Status "Warning" `
                -Details "Asignación permanente: $($existing[0].Id)"
            
            return @{
                HasConflict = $true
                Assignments = $existing
            }
        }
    }
    catch {
        Write-Verbose "Error verificando asignaciones Entra ID: $_"
    }
    
    return @{ HasConflict = $false }
}

function Remove-EntraRoleAssignmentSafe {
    <#
    .SYNOPSIS
        Remueve asignación permanente de Entra ID de forma segura
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject]$Assignment,
        [string]$PrincipalId
    )
    
    try {
        if ($DryRun) {
            Write-Log "[DRY-RUN] Removería asignación Entra ID permanente: $($Assignment.RoleDefinitionId)" -Level Warning
            return $true
        }
        
        Write-Log "Removiendo asignación permanente Entra ID..." -Level Warning
        
        Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $Assignment.Id -ErrorAction Stop
        
        Write-Log "✓ Asignación permanente Entra ID removida" -Level Success
        
        Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $Assignment.RoleDefinitionId `
            -Action "EntraPermanentRemoved" -Status "Success" `
            -Details "Removido: $($Assignment.Id)"
        
        return $true
    }
    catch {
        Write-Log "Error removiendo asignación Entra ID: $_" -Level Error
        return $false
    }
}

function Test-ExistingEntraEligibility {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId
    )
    
    try {
        $filter = "principalId eq '$PrincipalId' and roleDefinitionId eq '$RoleDefinitionId'"
        $existing = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter $filter -ErrorAction SilentlyContinue
        
        if ($existing) {
            Write-Log "IDEMPOTENCIA ENTRA ID: Eligibilidad ya existe" -Level Warning
            $script:Statistics.Skipped++
            Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $RoleDefinitionId `
                -Action "EntraSkipped" -Status "AlreadyExists" -Details "Eligibilidad existente"
            return $true
        }
    }
    catch {
        Write-Verbose "Error verificando eligibilidad Entra ID: $_"
    }
    
    return $false
}

function Test-EntraDurationCompliance {
    <#
    .SYNOPSIS
        Verifica límites de duración para roles Entra ID
    #>
    [CmdletBinding()]
    param(
        [string]$RoleDefinitionId,
        [string]$Duration
    )
    
    $roleConfig = $null
    foreach ($tier in $script:AllowedEntraRoles.Keys) {
        if ($script:AllowedEntraRoles[$tier].ContainsKey($RoleDefinitionId)) {
            $roleConfig = $script:AllowedEntraRoles[$tier][$RoleDefinitionId]
            break
        }
    }
    
    if (-not $roleConfig) {
        return $true
    }
    
    $requestedDuration = [System.Xml.XmlConvert]::ToTimeSpan($Duration)
    $maxDuration = [System.Xml.XmlConvert]::ToTimeSpan($roleConfig.MaxDuration)
    
    if ($requestedDuration -gt $maxDuration) {
        Write-Log "Duración excede límite Entra ID: $Duration > $($roleConfig.MaxDuration)" -Level Warning
        return $false
    }
    
    return $true
}

function New-EntraIDEligibility {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$DirectoryScopeId,
        [string]$Justification,
        [string]$Duration
    )
    
    try {
        $params = @{
            PrincipalId = $PrincipalId
            RoleDefinitionId = $RoleDefinitionId
            DirectoryScopeId = $DirectoryScopeId
            Action = "AdminAssign"
            Justification = $Justification
            ScheduleInfo = @{
                StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                Expiration = @{
                    Type = "AfterDuration"
                    Duration = $Duration
                }
            }
        }
        
        $response = New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop
        return $response
    }
    catch {
        throw "Error creando eligibilidad Entra ID: $_"
    }
}

#endregion

#region Group Functions

function Test-ExistingGroupEligibility {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$GroupId
    )
    
    try {
        $filter = "principalId eq '$PrincipalId'"
        $existing = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule `
            -PrivilegedAccessGroupId $GroupId -Filter $filter -ErrorAction SilentlyContinue
        
        if ($existing) {
            Write-Log "IDEMPOTENCIA GRUPO: Membresía ya existe" -Level Warning
            $script:Statistics.Skipped++
            return $true
        }
    }
    catch {
        Write-Verbose "Error verificando eligibilidad grupo: $_"
    }
    
    return $false
}

function New-GroupEligibility {
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$GroupId,
        [string]$Justification,
        [string]$Duration
    )
    
    try {
        $params = @{
            AccessId = "member"
            PrincipalId = $PrincipalId
            GroupId = $GroupId
            Action = "AdminAssign"
            Justification = $Justification
            ScheduleInfo = @{
                StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                Expiration = @{
                    Type = "AfterDuration"
                    Duration = $Duration
                }
            }
        }
        
        $response = New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop
        return $response
    }
    catch {
        throw "Error creando membresía grupo: $_"
    }
}

#endregion

#region Prerequisites and Validation

function Test-Prerequisites {
    [CmdletBinding()]
    param([int]$Phase)
    
    Write-Log "=== Validando Prerequisites (Fase $Phase) ===" -Level Info
    
    if (-not (Test-Path $CsvPath)) {
        throw "ERROR: Archivo CSV no encontrado: $CsvPath"
    }
    
    $script:CsvHash = (Get-FileHash -Path $CsvPath -Algorithm SHA256).Hash
    Write-Log "CSV Hash: $($script:CsvHash.Substring(0,16))..." -Level Info
    
    $requiredModules = @('Microsoft.Graph.Identity.Governance', 'Microsoft.Graph.Identity.SignIns')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            throw "ERROR: Módulo requerido no instalado: $module"
        }
        Import-Module $module -ErrorAction Stop
        Write-Log "Módulo cargado: $module" -Level Success
    }
    
    $context = Get-MgContext
    if ($null -eq $context) {
        throw "ERROR: No conectado a Microsoft Graph"
    }
    
    $requiredScopes = $script:RequiredPermissions.EntraID[$Phase]
    $grantedScopes = $context.Scopes
    
    foreach ($scope in $requiredScopes) {
        if ($scope -notin $grantedScopes) {
            throw "ERROR: Falta permiso: $scope"
        }
    }
    Write-Log "Permisos validados" -Level Success
    Write-Log "Usuario: $($context.Account)" -Level Info
}

function Test-AzureRBACPrerequisites {
    [CmdletBinding()]
    param()
    
    Write-Log "=== Validando Prerequisites Azure RBAC ===" -Level Info
    
    if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
        Write-Log "Instalando Az.Resources..." -Level Warning
        Install-Module Az.Resources -Scope CurrentUser -Force -AllowClobber
    }
    
    Import-Module Az.Resources -ErrorAction Stop
    
    $azContext = Get-AzContext
    if ($null -eq $azContext) {
        Write-Log "Conectando a Azure..." -Level Warning
        Connect-AzAccount
        $azContext = Get-AzContext
    }
    
    if ($null -eq $azContext) {
        throw "ERROR: No se pudo conectar a Azure"
    }
    
    Write-Log "Conectado a Azure" -Level Success
    Write-Log "Suscripción actual: $($azContext.Subscription.Name)" -Level Info
    
    # Obtener lista de suscripciones a procesar
    $subscriptionsToProcess = Get-SubscriptionsToProcess
    
    Write-Log "Suscripciones a procesar: $($subscriptionsToProcess.Count)" -Level Info
    foreach ($sub in $subscriptionsToProcess) {
        Write-Log "  - $($sub.Name) ($($sub.Id))" -Level Info
    }
    
    # Inicializar cache con roles de la suscripción actual
    # (El cache se actualizará por suscripción durante el procesamiento)
    Initialize-AzureRoleDefinitionsCache
    
    return $azContext
}

function Get-SubscriptionsToProcess {
    <#
    .SYNOPSIS
        Determina qué suscripciones procesar según parámetros
    #>
    [CmdletBinding()]
    param()
    
    if ($AllSubscriptions) {
        # Procesar todas las suscripciones accesibles
        Write-Log "Modo: Todas las suscripciones del tenant" -Level Info
        $allSubs = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }
        return $allSubs
    }
    elseif ($SubscriptionIds) {
        # Procesar suscripciones específicas
        Write-Log "Modo: Suscripciones específicas ($($SubscriptionIds.Count))" -Level Info
        $subs = @()
        foreach ($subId in $SubscriptionIds) {
            $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue
            if ($sub) {
                $subs += $sub
            }
            else {
                Write-Log "Advertencia: Suscripción no encontrada: $subId" -Level Warning
            }
        }
        return $subs
    }
    else {
        # Procesar solo suscripción actual
        $currentContext = Get-AzContext
        Write-Log "Modo: Solo suscripción actual" -Level Info
        return @(Get-AzSubscription -SubscriptionId $currentContext.Subscription.Id)
    }
}

function Set-AzureSubscriptionContext {
    <#
    .SYNOPSIS
        Cambia el contexto a una suscripción específica
    #>
    [CmdletBinding()]
    param([string]$SubscriptionId)
    
    try {
        $context = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
        Write-Verbose "Contexto cambiado a suscripción: $($context.Subscription.Name)"
        
        # Actualizar cache de roles para esta suscripción
        $script:AzureRoleDefinitionsCache = @{}
        Initialize-AzureRoleDefinitionsCache
        
        return $context
    }
    catch {
        Write-Log "Error cambiando a suscripción $SubscriptionId: $_" -Level Error
        throw
    }
}

function Test-CsvStructureExtended {
    [CmdletBinding()]
    param([array]$CsvData)
    
    Write-Log "=== Validando Estructura CSV ===" -Level Info
    
    $requiredColumns = @('PrincipalId', 'Reason', 'Duration')
    $csvHeaders = $CsvData[0].PSObject.Properties.Name
    
    foreach ($col in $requiredColumns) {
        if ($col -notin $csvHeaders) {
            throw "ERROR: Falta columna requerida: $col"
        }
    }
    
    $hasEntraRole = ($csvHeaders -contains 'RoleDefinitionId' -and $csvHeaders -contains 'DirectoryScopeId')
    $hasAzureRole = ($csvHeaders -contains 'AzureRoleDefinitionId' -and $csvHeaders -contains 'AzureScope')
    $hasGroup = ($csvHeaders -contains 'GroupId')
    
    if (-not ($hasEntraRole -or $hasAzureRole -or $hasGroup)) {
        throw "ERROR: CSV debe contener RoleDefinitionId+DirectoryScopeId, AzureRoleDefinitionId+AzureScope, o GroupId"
    }
    
    if ($hasAzureRole -and -not $SupportAzureRBAC) {
        Write-Log "CSV contiene roles Azure pero -SupportAzureRBAC no habilitado" -Level Warning
    }
    
    Write-Log "Estructura CSV válida: $($CsvData.Count) filas" -Level Success
}

function Test-InputValidations {
    [CmdletBinding()]
    param([hashtable]$Row)
    
    $errors = @()
    
    try { [System.Guid]::Parse($Row.PrincipalId) | Out-Null }
    catch { $errors += "PrincipalId inválido: $($Row.PrincipalId)" }
    
    if ($Row.RoleDefinitionId) {
        try { [System.Guid]::Parse($Row.RoleDefinitionId) | Out-Null }
        catch { $errors += "RoleDefinitionId inválido: $($Row.RoleDefinitionId)" }
    }
    
    if ($Row.AzureRoleDefinitionId) {
        try { [System.Guid]::Parse($Row.AzureRoleDefinitionId) | Out-Null }
        catch { $errors += "AzureRoleDefinitionId inválido: $($Row.AzureRoleDefinitionId)" }
    }
    
    if ($Row.GroupId) {
        try { [System.Guid]::Parse($Row.GroupId) | Out-Null }
        catch { $errors += "GroupId inválido: $($Row.GroupId)" }
    }
    
    if ($Row.Duration -notmatch '^P(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?) {
        $errors += "Duration formato ISO-8601 inválido: $($Row.Duration)"
    }
    
    if ($Row.Reason.Length -lt 5) {
        $errors += "Justificación insuficiente (mínimo 5 caracteres)"
    }
    
    if ($errors.Count -gt 0) {
        Write-Log "Validaciones fallidas para Principal $($Row.PrincipalId):" -Level Warning
        $errors | ForEach-Object { Write-Log "  - $_" -Level Warning }
        return $false
    }
    
    return $true
}

#endregion

#region Main Processing

function New-PIMEligibilityAssignmentExtended {
    [CmdletBinding()]
    param(
        [hashtable]$Row,
        [int]$Phase
    )
    
    $script:Statistics.Total++
    
    try {
        $isEntraRole = ($Row.RoleDefinitionId -and $Row.DirectoryScopeId)
        $isAzureRole = ($Row.AzureRoleDefinitionId -and $Row.AzureScope)
        $isGroup = ($Row.GroupId)
        
        # === AZURE RBAC ===
        if ($isAzureRole) {
            if (-not $SupportAzureRBAC) {
                Write-Log "Omitido: Rol Azure sin -SupportAzureRBAC" -Level Warning
                $script:Statistics.Skipped++
                return
            }
            
            # Validaciones Fase 0+
            if (-not (Test-AzureRoleAllowedByGuid -RoleDefinitionId $Row.AzureRoleDefinitionId -PrincipalId $Row.PrincipalId)) {
                $script:Statistics.Failed++
                return
            }
            
            # Detectar conflictos con ancestros
            $conflictCheck = Test-ExistingAzureRoleAssignmentWithAncestors `
                -PrincipalId $Row.PrincipalId `
                -RoleDefinitionId $Row.AzureRoleDefinitionId `
                -Scope $Row.AzureScope
            
            if ($conflictCheck.HasConflict) {
                if ($AutoMigrate) {
                    Write-Log "AutoMigrate: Creando eligibilidad y removiendo permanentes..." -Level Warning
                    
                    if (-not $DryRun) {
                        $eligibility = New-AzureRBACEligibility `
                            -PrincipalId $Row.PrincipalId `
                            -RoleDefinitionId $Row.AzureRoleDefinitionId `
                            -Scope $Row.AzureScope `
                            -Justification $Row.Reason `
                            -Duration $Row.Duration
                        
                        Write-Log "✓ Eligibilidad Azure creada" -Level Success
                        
                        foreach ($assignment in $conflictCheck.Assignments) {
                            $removed = Remove-AzureRoleAssignmentSafe -Assignment $assignment -PrincipalId $Row.PrincipalId
                            if ($removed) {
                                $script:Statistics.Migrated++
                            }
                        }
                        
                        $script:Statistics.Success++
                        $script:Statistics.AzureRoles++
                        
                        $roleName = Get-AzureRoleNameById -RoleDefinitionId $Row.AzureRoleDefinitionId
                        Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $roleName `
                            -Action "AzureMigrated" -Status "Success" `
                            -Details "Eligibilidad creada y $($conflictCheck.Assignments.Count) permanentes removidos" `
                            -RequestId $eligibility.Name -Scope $Row.AzureScope
                    }
                    else {
                        Write-Log "[DRY-RUN] Se crearía eligibilidad y removerían $($conflictCheck.Assignments.Count) permanentes" -Level Warning
                        $script:Statistics.Success++
                        $script:Statistics.AzureRoles++
                    }
                }
                else {
                    Write-Log "Conflicto detectado. Use -AutoMigrate" -Level Warning
                    $script:Statistics.Skipped++
                    return
                }
                return
            }
            
            # Verificar idempotencia
            if (Test-ExistingAzureEligibility -PrincipalId $Row.PrincipalId `
                    -RoleDefinitionId $Row.AzureRoleDefinitionId -Scope $Row.AzureScope) {
                return
            }
            
            # Validaciones Fase 1+
            if ($Phase -ge 1) {
                if (-not (Test-InputValidations -Row $Row)) {
                    $script:Statistics.Failed++
                    return
                }
                
                # Validar duración
                $roleConfig = $null
                foreach ($tier in $script:AllowedAzureRoles.Keys) {
                    if ($script:AllowedAzureRoles[$tier].ContainsKey($Row.AzureRoleDefinitionId)) {
                        $roleConfig = $script:AllowedAzureRoles[$tier][$Row.AzureRoleDefinitionId]
                        break
                    }
                }
                
                if ($roleConfig) {
                    $requestedDuration = [System.Xml.XmlConvert]::ToTimeSpan($Row.Duration)
                    $maxDuration = [System.Xml.XmlConvert]::ToTimeSpan($roleConfig.MaxDuration)
                    
                    if ($requestedDuration -gt $maxDuration) {
                        $roleName = Get-AzureRoleNameById -RoleDefinitionId $Row.AzureRoleDefinitionId
                        Write-Log "Duración excede límite: $($Row.Duration) > $($roleConfig.MaxDuration)" -Level Warning
                        $script:Statistics.Failed++
                        return
                    }
                }
            }
            
            # Modo Dry-Run
            if ($DryRun) {
                $roleName = Get-AzureRoleNameById -RoleDefinitionId $Row.AzureRoleDefinitionId
                Write-Log "[DRY-RUN] Eligibilidad Azure: $roleName" -Level Info
                Write-Log "[DRY-RUN] Scope: $($Row.AzureScope) | Duration: $($Row.Duration)" -Level Info
                $script:Statistics.Success++
                $script:Statistics.AzureRoles++
                Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $roleName `
                    -Action "AzureDryRunSimulated" -Status "Success" -Scope $Row.AzureScope
                return
            }
            
            # Crear eligibilidad real
            if ($Phase -ge 2) {
                $response = Invoke-WithRetry -ScriptBlock {
                    New-AzureRBACEligibility -PrincipalId $Row.PrincipalId `
                        -RoleDefinitionId $Row.AzureRoleDefinitionId `
                        -Scope $Row.AzureScope `
                        -Justification $Row.Reason `
                        -Duration $Row.Duration
                }
            }
            else {
                $response = New-AzureRBACEligibility -PrincipalId $Row.PrincipalId `
                    -RoleDefinitionId $Row.AzureRoleDefinitionId `
                    -Scope $Row.AzureScope `
                    -Justification $Row.Reason `
                    -Duration $Row.Duration
            }
            
            $roleName = Get-AzureRoleNameById -RoleDefinitionId $Row.AzureRoleDefinitionId
            Write-Log "✓ Eligibilidad Azure creada: $roleName" -Level Success
            $script:Statistics.Success++
            $script:Statistics.AzureRoles++
            Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $roleName `
                -Action "AzureEligibilityCreated" -Status "Success" `
                -Details "Scope: $($Row.AzureScope)" -RequestId $response.Name -Scope $Row.AzureScope
            
            return
        }
        
        # === ENTRA ID ROLES ===
        if ($isEntraRole) {
            if (-not (Test-EntraRoleAllowed -RoleDefinitionId $Row.RoleDefinitionId -PrincipalId $Row.PrincipalId)) {
                $script:Statistics.Failed++
                return
            }
            
            $conflictCheck = Test-ExistingEntraRoleAssignment `
                -PrincipalId $Row.PrincipalId `
                -RoleDefinitionId $Row.RoleDefinitionId `
                -DirectoryScopeId $Row.DirectoryScopeId
            
            if ($conflictCheck.HasConflict) {
                Write-Log "Conflicto Entra ID. Migración manual requerida" -Level Warning
                $script:Statistics.Skipped++
                return
            }
            
            if (Test-ExistingEntraEligibility -PrincipalId $Row.PrincipalId -RoleDefinitionId $Row.RoleDefinitionId) {
                return
            }
            
            if ($Phase -ge 1 -and -not (Test-InputValidations -Row $Row)) {
                $script:Statistics.Failed++
                return
            }
            
            if ($DryRun) {
                Write-Log "[DRY-RUN] Eligibilidad Entra ID: $($Row.RoleDefinitionId)" -Level Info
                $script:Statistics.Success++
                $script:Statistics.EntraRoles++
                return
            }
            
            if ($Phase -ge 2) {
                $response = Invoke-WithRetry -ScriptBlock {
                    New-EntraIDEligibility -PrincipalId $Row.PrincipalId `
                        -RoleDefinitionId $Row.RoleDefinitionId `
                        -DirectoryScopeId $Row.DirectoryScopeId `
                        -Justification $Row.Reason `
                        -Duration $Row.Duration
                }
            }
            else {
                $response = New-EntraIDEligibility -PrincipalId $Row.PrincipalId `
                    -RoleDefinitionId $Row.RoleDefinitionId `
                    -DirectoryScopeId $Row.DirectoryScopeId `
                    -Justification $Row.Reason `
                    -Duration $Row.Duration
            }
            
            Write-Log "✓ Eligibilidad Entra ID creada" -Level Success
            $script:Statistics.Success++
            $script:Statistics.EntraRoles++
            Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.RoleDefinitionId `
                -Action "EntraEligibilityCreated" -Status "Success" -RequestId $response.Id
            
            return
        }
        
        # === GRUPOS PIM ===
        if ($isGroup) {
            if (Test-ExistingGroupEligibility -PrincipalId $Row.PrincipalId -GroupId $Row.GroupId) {
                return
            }
            
            if ($Phase -ge 1 -and -not (Test-InputValidations -Row $Row)) {
                $script:Statistics.Failed++
                return
            }
            
            if ($DryRun) {
                Write-Log "[DRY-RUN] Membresía grupo: $($Row.GroupId)" -Level Info
                $script:Statistics.Success++
                $script:Statistics.Groups++
                return
            }
            
            if ($Phase -ge 2) {
                $response = Invoke-WithRetry -ScriptBlock {
                    New-GroupEligibility -PrincipalId $Row.PrincipalId `
                        -GroupId $Row.GroupId `
                        -Justification $Row.Reason `
                        -Duration $Row.Duration
                }
            }
            else {
                $response = New-GroupEligibility -PrincipalId $Row.PrincipalId `
                    -GroupId $Row.GroupId `
                    -Justification $Row.Reason `
                    -Duration $Row.Duration
            }
            
            Write-Log "✓ Membresía grupo creada" -Level Success
            $script:Statistics.Success++
            $script:Statistics.Groups++
            Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.GroupId `
                -Action "GroupMembershipCreated" -Status "Success" -RequestId $response.Id
            
            return
        }
        
        Write-Log "Fila omitida: sin tipo válido" -Level Warning
        $script:Statistics.Skipped++
    }
    catch {
        Write-Log "Error procesando Principal $($Row.PrincipalId): $_" -Level Error
        $script:Statistics.Failed++
        Add-AuditEntry -PrincipalId $Row.PrincipalId -Action "Error" -Status "Failed" `
            -Details $_.Exception.Message
    }
}

function Start-PIMAssignmentExtended {
    [CmdletBinding()]
    param()
    
    $title = if ($SupportAzureRBAC) { "PIM Assignment - Fase $Phase [Entra ID + Azure RBAC]" } 
             else { "PIM Assignment - Fase $Phase [Solo Entra ID]" }
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  $title  ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    if ($AutoMigrate) {
        Write-Host "⚠️  AUTO-MIGRATE ACTIVO: Roles permanentes serán migrados" -ForegroundColor Yellow
    }
    
    if ($AllSubscriptions) {
        Write-Host "🌐 MULTI-SUSCRIPCIÓN: Procesando todas las suscripciones del tenant" -ForegroundColor Cyan
    }
    elseif ($SubscriptionIds) {
        Write-Host "🎯 MULTI-SUSCRIPCIÓN: Procesando $($SubscriptionIds.Count) suscripciones específicas" -ForegroundColor Cyan
    }
    
    Test-Prerequisites -Phase $Phase
    
    $subscriptionsToProcess = @()
    if ($SupportAzureRBAC) {
        $azContext = Test-AzureRBACPrerequisites
        $subscriptionsToProcess = Get-SubscriptionsToProcess
    }
    
    Write-Log "=== Cargando CSV ===" -Level Info
    $csvData = Import-Csv -Path $CsvPath -Encoding UTF8
    Test-CsvStructureExtended -CsvData $csvData
    
    # Agrupar asignaciones por suscripción (si hay Azure RBAC)
    $assignmentsBySubscription = @{}
    $nonAzureAssignments = @()
    
    foreach ($row in $csvData) {
        if ($row.AzureScope) {
            # Extraer subscription ID del scope
            if ($row.AzureScope -match '/subscriptions/([^/]+)') {
                $subId = $matches[1]
                if (-not $assignmentsBySubscription.ContainsKey($subId)) {
                    $assignmentsBySubscription[$subId] = @()
                }
                $assignmentsBySubscription[$subId] += $row
            }
            else {
                Write-Log "Advertencia: Scope inválido en fila: $($row.AzureScope)" -Level Warning
            }
        }
        else {
            # Asignaciones de Entra ID o Grupos (no dependen de suscripción)
            $nonAzureAssignments += $row
        }
    }
    
    if (-not $Force -and -not $DryRun) {
        Write-Host "`n⚠️  CONFIRMACIÓN:" -ForegroundColor Yellow
        Write-Host "  Asignaciones totales: $($csvData.Count)" -ForegroundColor White
        Write-Host "  - Entra ID/Grupos: $($nonAzureAssignments.Count)" -ForegroundColor White
        Write-Host "  - Azure RBAC: $($csvData.Count - $nonAzureAssignments.Count)" -ForegroundColor White
        if ($SupportAzureRBAC) {
            Write-Host "  Suscripciones afectadas: $($assignmentsBySubscription.Keys.Count)" -ForegroundColor White
        }
        Write-Host "  Fase: $Phase" -ForegroundColor White
        Write-Host "  Modo: PRODUCCIÓN" -ForegroundColor White
        if ($AutoMigrate) {
            Write-Host "  AutoMigrate: HABILITADO" -ForegroundColor Yellow
        }
        
        $confirm = Read-Host "`n¿Continuar? (escriba 'SI')"
        if ($confirm -ne 'SI') {
            Write-Log "Operación cancelada" -Level Warning
            return
        }
    }
    
    Write-Log "=== Procesando Asignaciones ===" -Level Info
    if ($DryRun) {
        Write-Host "[MODO DRY-RUN ACTIVO]`n" -ForegroundColor Yellow
    }
    
    # Procesar asignaciones no-Azure primero (Entra ID y Grupos)
    if ($nonAzureAssignments.Count -gt 0) {
        Write-Log "=== Procesando Asignaciones Entra ID y Grupos ($($nonAzureAssignments.Count)) ===" -Level Info
        
        $progress = 0
        foreach ($row in $nonAzureAssignments) {
            $progress++
            Write-Progress -Activity "Procesando asignaciones no-Azure" `
                -Status "Fila $progress de $($nonAzureAssignments.Count)" `
                -PercentComplete (($progress / $nonAzureAssignments.Count) * 100)
            
            Write-Log "[$progress/$($nonAzureAssignments.Count)] Principal: $($row.PrincipalId)" -Level Info
            
            $rowHash = @{}
            $row.PSObject.Properties | ForEach-Object { $rowHash[$_.Name] = $_.Value }
            
            New-PIMEligibilityAssignmentExtended -Row $rowHash -Phase $Phase
        }
        Write-Progress -Activity "Procesando asignaciones no-Azure" -Completed
    }
    
    # Procesar asignaciones Azure RBAC por suscripción
    if ($SupportAzureRBAC -and $assignmentsBySubscription.Keys.Count -gt 0) {
        $currentSubIndex = 0
        foreach ($subId in $assignmentsBySubscription.Keys) {
            $currentSubIndex++
            $assignments = $assignmentsBySubscription[$subId]
            
            # Verificar si esta suscripción está en la lista de procesamiento
            $shouldProcess = $false
            if ($AllSubscriptions) {
                $shouldProcess = $true
            }
            elseif ($SubscriptionIds) {
                $shouldProcess = $subId -in $SubscriptionIds
            }
            else {
                # Solo suscripción actual
                $currentContext = Get-AzContext
                $shouldProcess = $subId -eq $currentContext.Subscription.Id
            }
            
            if (-not $shouldProcess) {
                Write-Log "Omitiendo suscripción $subId (no en scope de procesamiento)" -Level Warning
                $script:Statistics.Skipped += $assignments.Count
                continue
            }
            
            # Obtener info de la suscripción
            $subscription = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue
            if (-not $subscription) {
                Write-Log "Suscripción no encontrada: $subId" -Level Error
                $script:Statistics.Failed += $assignments.Count
                continue
            }
            
            Write-Log "`n=== Procesando Suscripción [$currentSubIndex/$($assignmentsBySubscription.Keys.Count)]: $($subscription.Name) ($subId) ===" -Level Info
            Write-Log "Asignaciones en esta suscripción: $($assignments.Count)" -Level Info
            
            # Cambiar contexto
            try {
                Set-AzureSubscriptionContext -SubscriptionId $subId
                $script:Statistics.SubscriptionsProcessed++
                $script:ProcessedSubscriptions += $subscription.Name
            }
            catch {
                Write-Log "Error cambiando a suscripción $($subscription.Name): $_" -Level Error
                $script:Statistics.Failed += $assignments.Count
                continue
            }
            
            # Procesar asignaciones de esta suscripción
            $progress = 0
            foreach ($row in $assignments) {
                $progress++
                Write-Progress -Activity "Procesando suscripción: $($subscription.Name)" `
                    -Status "Fila $progress de $($assignments.Count)" `
                    -PercentComplete (($progress / $assignments.Count) * 100)
                
                Write-Log "  [$progress/$($assignments.Count)] Principal: $($row.PrincipalId)" -Level Info
                
                $rowHash = @{}
                $row.PSObject.Properties | ForEach-Object { $rowHash[$_.Name] = $_.Value }
                
                New-PIMEligibilityAssignmentExtended -Row $rowHash -Phase $Phase
            }
            Write-Progress -Activity "Procesando suscripción: $($subscription.Name)" -Completed
        }
    }
    
    Write-Log "=== Generando Reportes ===" -Level Info
    Export-AuditReportExtended
    
    if ($DryRun) {
        Write-Log "✓ Simulación completada" -Level Success
    }
    else {
        Write-Log "✓ Procesamiento completado" -Level Success
    }
}

function Export-AuditReportExtended {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $shortHash = $script:CsvHash.Substring(0, 8)
    
    $csvFile = "PIM_Audit_${shortHash}_${timestamp}.csv"
    $script:AuditLog | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Log "✓ Reporte CSV: $csvFile" -Level Success
    
    $jsonFile = "PIM_Audit_${shortHash}_${timestamp}.json"
    $auditData = @{
        Metadata = @{
            CsvHash = $script:CsvHash
            Phase = $Phase
            DryRun = $DryRun.IsPresent
            AutoMigrate = $AutoMigrate.IsPresent
            AzureRBACSupport = $SupportAzureRBAC.IsPresent
            ExecutedBy = try { (Get-MgContext).Account } catch { "Unknown" }
            ExecutedAt = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        }
        Statistics = $script:Statistics
        Entries = $script:AuditLog
    }
    $auditData | ConvertTo-Json -Depth 10 | Out-File $jsonFile -Encoding UTF8
    Write-Log "✓ Reporte JSON: $jsonFile" -Level Success
    
    Write-Host "`n╔════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  RESUMEN DE EJECUCIÓN              ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "Total:      $($script:Statistics.Total)" -ForegroundColor White
    Write-Host "Exitoso:    $($script:Statistics.Success)" -ForegroundColor Green
    Write-Host "  - Entra:  $($script:Statistics.EntraRoles)" -ForegroundColor White
    Write-Host "  - Azure:  $($script:Statistics.AzureRoles)" -ForegroundColor White
    Write-Host "  - Grupos: $($script:Statistics.Groups)" -ForegroundColor White
    if ($SupportAzureRBAC) {
        Write-Host "Suscripciones procesadas: $($script:Statistics.SubscriptionsProcessed)" -ForegroundColor Cyan
        if ($script:ProcessedSubscriptions.Count -gt 0) {
            Write-Host "  Suscripciones:" -ForegroundColor White
            $script:ProcessedSubscriptions | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkGray }
        }
    }
    if ($AutoMigrate) {
        Write-Host "Migrados:   $($script:Statistics.Migrated)" -ForegroundColor Cyan
    }
    Write-Host "Fallido:    $($script:Statistics.Failed)" -ForegroundColor Red
    Write-Host "Omitido:    $($script:Statistics.Skipped)" -ForegroundColor Yellow
    Write-Host "Conflictos: $($script:Statistics.Conflicts)" -ForegroundColor Magenta
}

#endregion

#region Main Execution

if ($ExtractRoles) {
    try {
        Get-AllRoleDefinitions -ExportCsv:$ExportRolesCsv -OutputPath $RolesOutputPath
    }
    catch {
        Write-Log "Error en extracción: $_" -Level Error
    }
    exit 0
}

if (-not $CsvPath) {
    Write-Host "ERROR: -CsvPath es obligatorio (o use -ExtractRoles)" -ForegroundColor Red
    Write-Host "`nEjemplos:" -ForegroundColor Yellow
    Write-Host "  .\PIM-SecureAssignment-ARM.ps1 -ExtractRoles -SupportAzureRBAC" -ForegroundColor Cyan
    Write-Host "  .\PIM-SecureAssignment-ARM.ps1 -CsvPath 'file.csv' -Phase 1 -SupportAzureRBAC" -ForegroundColor Cyan
    exit 1
}

try {
    $transcriptFile = "PIM_Execution_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $transcriptFile
    
    Start-PIMAssignmentExtended
}
catch {
    Write-Log "Error fatal: $_" -Level Error
    $script:Statistics.Failed++
}
finally {
    Stop-Transcript
    Write-Host "`nLog: $transcriptFile" -ForegroundColor Cyan
}

#endregion
