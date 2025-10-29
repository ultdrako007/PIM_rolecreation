<#
.SYNOPSIS
    Extensión del script PIM para soportar roles de Azure RBAC (ARM)
EFP
    
.DESCRIPTION
    Añade capacidad de gestionar:
    - Roles de Entra ID (Fase 0-2 original)
    - Roles de Azure RBAC en suscripciones/resource groups
    - Grupos PIM
    
.PARAMETER CsvPath
    Ruta al archivo CSV con las asignaciones
    
.PARAMETER Phase
    Fase de controles a ejecutar (0, 1, 2)
    
.PARAMETER SupportAzureRBAC
    Habilita soporte para roles de Azure ARM
    
.PARAMETER DryRun
    Modo simulación
    
.EXAMPLE
    .\PIM-SecureAssignment-ARM.ps1 -CsvPath "assignments.csv" -Phase 1 -SupportAzureRBAC -DryRun
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet(0, 1, 2)]
    [int]$Phase,
    
    [switch]$SupportAzureRBAC,
    [switch]$DryRun,
    [switch]$Force
)

#region Configuration

# Lista blanca de roles Entra ID (original)
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

# Lista blanca de roles Azure RBAC (NUEVO)
$script:AllowedAzureRoles = @{
    Tier0 = @{
        'Owner' = @{ MaxDuration = 'PT4H'; RequiresApproval = $true; Description = 'Full access to all resources' }
        'User Access Administrator' = @{ MaxDuration = 'PT4H'; RequiresApproval = $true; Description = 'Manage user access to Azure resources' }
    }
    Tier1 = @{
        'Contributor' = @{ MaxDuration = 'PT8H'; RequiresApproval = $true; Description = 'Create and manage all types of Azure resources' }
        'Virtual Machine Contributor' = @{ MaxDuration = 'P1D'; RequiresApproval = $false; Description = 'Manage virtual machines' }
        'Storage Account Contributor' = @{ MaxDuration = 'P1D'; RequiresApproval = $false; Description = 'Manage storage accounts' }
        'Network Contributor' = @{ MaxDuration = 'P1D'; RequiresApproval = $false; Description = 'Manage network resources' }
    }
    Tier2 = @{
        'Reader' = @{ MaxDuration = 'P30D'; RequiresApproval = $false; Description = 'View all resources, but not make any changes' }
        'Monitoring Reader' = @{ MaxDuration = 'P30D'; RequiresApproval = $false; Description = 'Read monitoring data' }
        'Log Analytics Reader' = @{ MaxDuration = 'P30D'; RequiresApproval = $false; Description = 'View and search all data' }
    }
}

# Permisos requeridos extendidos
$script:RequiredPermissions = @{
    EntraID = @{
        0 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup')
        1 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup', 'RoleManagement.Read.Directory')
        2 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup', 'RoleManagement.Read.Directory', 'Policy.Read.All')
    }
    # Azure RBAC no usa Microsoft Graph, usa Az.Resources
}

# Variables globales
$script:AuditLog = @()
$script:CsvHash = $null
$script:Statistics = @{
    Total = 0
    Success = 0
    Failed = 0
    Skipped = 0
    Conflicts = 0
    EntraRoles = 0
    AzureRoles = 0
    Groups = 0
}

#endregion

#region Azure RBAC Functions (NUEVO)

function Test-AzureRBACPrerequisites {
    <#
    .SYNOPSIS
        Valida módulos y conexión para Azure RBAC
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== Validando Prerequisites Azure RBAC ===" -ForegroundColor Cyan
    
    # Validar módulo Az.Resources
    if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
        Write-Host "  Instalando Az.Resources..." -ForegroundColor Yellow
        Install-Module Az.Resources -Scope CurrentUser -Force -AllowClobber
    }
    else {
        Write-Host "✓ Módulo Az.Resources disponible" -ForegroundColor Green
    }
    
    Import-Module Az.Resources -ErrorAction Stop
    
    # Validar conexión a Azure
    $azContext = Get-AzContext
    if ($null -eq $azContext) {
        Write-Warning "No conectado a Azure. Intentando conectar..."
        Connect-AzAccount
        $azContext = Get-AzContext
    }
    
    if ($null -eq $azContext) {
        throw "ERROR: No se pudo conectar a Azure"
    }
    
    Write-Host "✓ Conectado a Azure" -ForegroundColor Green
    Write-Host "  Suscripción: $($azContext.Subscription.Name)" -ForegroundColor White
    Write-Host "  Cuenta: $($azContext.Account.Id)" -ForegroundColor White
    
    # Listar suscripciones disponibles
    $subscriptions = Get-AzSubscription
    Write-Host "✓ Suscripciones accesibles: $($subscriptions.Count)" -ForegroundColor Green
    
    return $azContext
}

function Test-AzureRoleAllowed {
    <#
    .SYNOPSIS
        Verifica si un rol de Azure está en la lista blanca
    #>
    [CmdletBinding()]
    param(
        [string]$RoleName,
        [string]$PrincipalId
    )
    
    $allAllowed = @{}
    foreach ($tier in $script:AllowedAzureRoles.Keys) {
        $allAllowed += $script:AllowedAzureRoles[$tier]
    }
    
    if ($RoleName -notin $allAllowed.Keys) {
        Write-Warning "ROL AZURE BLOQUEADO: '$RoleName' no está en lista blanca para Principal $PrincipalId"
        Add-AuditEntry -PrincipalId $PrincipalId -Action "AzureRoleBlocked" -Status "Blocked" `
            -Details "Rol Azure no autorizado: $RoleName"
        return $false
    }
    
    return $true
}

function Get-AzureRoleDefinitionByName {
    <#
    .SYNOPSIS
        Obtiene el ID de definición de un rol Azure por nombre
    #>
    [CmdletBinding()]
    param(
        [string]$RoleName,
        [string]$Scope
    )
    
    $roleDef = Get-AzRoleDefinition -Name $RoleName -Scope $Scope -ErrorAction SilentlyContinue
    
    if (-not $roleDef) {
        # Intentar buscar en suscripción actual
        $roleDef = Get-AzRoleDefinition -Name $RoleName -ErrorAction SilentlyContinue
    }
    
    return $roleDef
}

function Test-ExistingAzureRoleAssignment {
    <#
    .SYNOPSIS
        Detecta conflictos con asignaciones permanentes de Azure
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleName,
        [string]$Scope
    )
    
    try {
        $existingAssignments = Get-AzRoleAssignment -ObjectId $PrincipalId -Scope $Scope -RoleDefinitionName $RoleName -ErrorAction SilentlyContinue
        
        if ($existingAssignments) {
            Write-Warning "CONFLICTO AZURE: Principal $PrincipalId tiene asignación permanente de '$RoleName'"
            
            $script:Statistics.Conflicts++
            Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $RoleName `
                -Action "AzureConflictDetected" -Status "Warning" `
                -Details "Asignación permanente Azure existente en scope: $Scope"
            
            return @{
                HasConflict = $true
                Assignments = $existingAssignments
            }
        }
    }
    catch {
        Write-Verbose "Error verificando asignaciones Azure: $_"
    }
    
    return @{ HasConflict = $false }
}

function Test-ExistingAzureEligibility {
    <#
    .SYNOPSIS
        Verifica eligibilidad existente en Azure RBAC
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleName,
        [string]$Scope
    )
    
    try {
        # Obtener eligibilidades existentes
        $existing = Get-AzRoleEligibilityScheduleInstance -Scope $Scope -Filter "asTarget()" -ErrorAction SilentlyContinue |
            Where-Object { $_.PrincipalId -eq $PrincipalId -and $_.RoleDefinitionDisplayName -eq $RoleName }
        
        if ($existing) {
            Write-Host "IDEMPOTENCIA AZURE: Eligibilidad ya existe para Principal $PrincipalId en rol '$RoleName'" -ForegroundColor Yellow
            $script:Statistics.Skipped++
            Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $RoleName -Action "AzureSkipped" `
                -Status "AlreadyExists" -Details "Eligibilidad Azure existente en: $Scope"
            return $true
        }
    }
    catch {
        Write-Verbose "Error verificando eligibilidad Azure: $_"
    }
    
    return $false
}

function New-AzureRBACEligibility {
    <#
    .SYNOPSIS
        Crea eligibilidad PIM para roles de Azure
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleName,
        [string]$Scope,
        [string]$Justification,
        [string]$Duration
    )
    
    try {
        # Obtener definición del rol
        $roleDef = Get-AzureRoleDefinitionByName -RoleName $RoleName -Scope $Scope
        
        if (-not $roleDef) {
            throw "No se encontró definición para rol: $RoleName"
        }
        
        # Crear request de eligibilidad
        $scheduleInfo = New-AzRoleEligibilityScheduleRequest `
            -Name (New-Guid) `
            -Scope $Scope `
            -PrincipalId $PrincipalId `
            -RoleDefinitionId $roleDef.Id `
            -RequestType "AdminAssign" `
            -Justification $Justification `
            -ScheduleInfoStartDateTime (Get-Date).ToUniversalTime() `
            -ExpirationType "AfterDuration" `
            -ExpirationDuration $Duration
        
        return $scheduleInfo
    }
    catch {
        throw "Error creando eligibilidad Azure: $_"
    }
}

#endregion

#region Enhanced CSV Structure Validation

function Test-CsvStructureExtended {
    <#
    .SYNOPSIS
        Valida estructura CSV extendida con soporte Azure RBAC
    #>
    [CmdletBinding()]
    param([array]$CsvData)
    
    Write-Host "`n=== Validando Estructura CSV Extendida ===" -ForegroundColor Cyan
    
    # Columnas requeridas base
    $requiredColumns = @('PrincipalId', 'Reason', 'Duration')
    $csvHeaders = $CsvData[0].PSObject.Properties.Name
    
    foreach ($col in $requiredColumns) {
        if ($col -notin $csvHeaders) {
            throw "ERROR: Falta columna requerida en CSV: $col"
        }
    }
    
    # Validar que tiene al menos una columna de destino
    $hasEntraRole = ($csvHeaders -contains 'RoleDefinitionId' -and $csvHeaders -contains 'DirectoryScopeId')
    $hasAzureRole = ($csvHeaders -contains 'AzureRoleName' -and $csvHeaders -contains 'AzureScope')
    $hasGroup = ($csvHeaders -contains 'GroupId')
    
    if (-not ($hasEntraRole -or $hasAzureRole -or $hasGroup)) {
        throw @"
ERROR: CSV debe contener al menos uno de:
  - RoleDefinitionId + DirectoryScopeId (roles Entra ID)
  - AzureRoleName + AzureScope (roles Azure RBAC)
  - GroupId (grupos PIM)
"@
    }
    
    if ($hasAzureRole -and -not $SupportAzureRBAC) {
        Write-Warning "CSV contiene roles Azure RBAC pero -SupportAzureRBAC no está habilitado"
        Write-Warning "Las filas con roles Azure serán omitidas"
    }
    
    Write-Host "✓ Estructura CSV válida: $($CsvData.Count) filas" -ForegroundColor Green
    if ($hasEntraRole) { Write-Host "  - Roles Entra ID detectados" -ForegroundColor White }
    if ($hasAzureRole) { Write-Host "  - Roles Azure RBAC detectados" -ForegroundColor White }
    if ($hasGroup) { Write-Host "  - Grupos PIM detectados" -ForegroundColor White }
}

#endregion

#region Main Processing Extended

function New-PIMEligibilityAssignmentExtended {
    <#
    .SYNOPSIS
        Procesa asignación con soporte extendido para Azure RBAC
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Row,
        [int]$Phase
    )
    
    $script:Statistics.Total++
    
    try {
        # Determinar tipo de asignación
        $isEntraRole = ($Row.RoleDefinitionId -and $Row.DirectoryScopeId)
        $isAzureRole = ($Row.AzureRoleName -and $Row.AzureScope)
        $isGroup = ($Row.GroupId)
        
        # === ROLES DE AZURE RBAC === (NUEVO)
        if ($isAzureRole) {
            if (-not $SupportAzureRBAC) {
                Write-Warning "Fila omitida: Rol Azure detectado pero -SupportAzureRBAC no habilitado"
                $script:Statistics.Skipped++
                return
            }
            
            # Validaciones Fase 0
            if (-not (Test-AzureRoleAllowed -RoleName $Row.AzureRoleName -PrincipalId $Row.PrincipalId)) {
                $script:Statistics.Failed++
                return
            }
            
            $conflictCheck = Test-ExistingAzureRoleAssignment -PrincipalId $Row.PrincipalId `
                -RoleName $Row.AzureRoleName -Scope $Row.AzureScope
            
            if ($conflictCheck.HasConflict) {
                Write-Host "  → Requiere migración manual de rol Azure permanente" -ForegroundColor Yellow
                $script:Statistics.Skipped++
                return
            }
            
            if (Test-ExistingAzureEligibility -PrincipalId $Row.PrincipalId `
                    -RoleName $Row.AzureRoleName -Scope $Row.AzureScope) {
                return
            }
            
            # Validaciones Fase 1+
            if ($Phase -ge 1) {
                if (-not (Test-InputValidations -Row $Row)) {
                    $script:Statistics.Failed++
                    return
                }
                
                # Validar duración vs límites
                $roleConfig = $null
                foreach ($tier in $script:AllowedAzureRoles.Keys) {
                    if ($script:AllowedAzureRoles[$tier].ContainsKey($Row.AzureRoleName)) {
                        $roleConfig = $script:AllowedAzureRoles[$tier][$Row.AzureRoleName]
                        break
                    }
                }
                
                if ($roleConfig) {
                    $requestedDuration = [System.Xml.XmlConvert]::ToTimeSpan($Row.Duration)
                    $maxDuration = [System.Xml.XmlConvert]::ToTimeSpan($roleConfig.MaxDuration)
                    
                    if ($requestedDuration -gt $maxDuration) {
                        Write-Warning "Duración excede límite para rol Azure '$($Row.AzureRoleName)': $($Row.Duration) > $($roleConfig.MaxDuration)"
                        $script:Statistics.Failed++
                        return
                    }
                }
            }
            
            # Dry-Run o ejecución real
            if ($DryRun) {
                Write-Host "[DRY-RUN] Eligibilidad Azure para: $($Row.PrincipalId)" -ForegroundColor Cyan
                Write-Host "[DRY-RUN] Rol: $($Row.AzureRoleName) | Scope: $($Row.AzureScope) | Duración: $($Row.Duration)" -ForegroundColor Cyan
                $script:Statistics.Success++
                $script:Statistics.AzureRoles++
                Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.AzureRoleName `
                    -Action "AzureDryRunSimulated" -Status "Success" -Details "Scope: $($Row.AzureScope)"
                return
            }
            
            # Crear eligibilidad real
            if ($Phase -ge 2) {
                $response = Invoke-WithRetry -ScriptBlock {
                    New-AzureRBACEligibility -PrincipalId $Row.PrincipalId `
                        -RoleName $Row.AzureRoleName -Scope $Row.AzureScope `
                        -Justification $Row.Reason -Duration $Row.Duration
                }
            }
            else {
                $response = New-AzureRBACEligibility -PrincipalId $Row.PrincipalId `
                    -RoleName $Row.AzureRoleName -Scope $Row.AzureScope `
                    -Justification $Row.Reason -Duration $Row.Duration
            }
            
            Write-Host "✓ Eligibilidad Azure creada: $($Row.AzureRoleName) para Principal $($Row.PrincipalId)" -ForegroundColor Green
            $script:Statistics.Success++
            $script:Statistics.AzureRoles++
            Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.AzureRoleName `
                -Action "AzureEligibilityCreated" -Status "Success" `
                -Details "Scope: $($Row.AzureScope)" -RequestId $response.Name
            
            return
        }
        
        # === ROLES DE ENTRA ID === (Código original optimizado)
        if ($isEntraRole) {
            # [Aquí va el código original de roles Entra ID del script anterior]
            # Lo omito por brevedad, pero es idéntico al script original
            $script:Statistics.EntraRoles++
            # ... resto del código original
        }
        
        # === GRUPOS PIM === (Código original)
        if ($isGroup) {
            # [Código original de grupos]
            $script:Statistics.Groups++
            # ... resto del código original
        }
        
        if (-not ($isEntraRole -or $isAzureRole -or $isGroup)) {
            Write-Warning "Fila omitida: sin tipo de asignación válido para Principal: $($Row.PrincipalId)"
            $script:Statistics.Skipped++
        }
    }
    catch {
        Write-Error "Error procesando Principal $($Row.PrincipalId): $_"
        $script:Statistics.Failed++
        Add-AuditEntry -PrincipalId $Row.PrincipalId -Action "Error" -Status "Failed" `
            -Details $_.Exception.Message
    }
}

#endregion

#region Main Execution Extended

function Start-PIMAssignmentExtended {
    <#
    .SYNOPSIS
        Función principal extendida
    #>
    [CmdletBinding()]
    param()
    
    $title = if ($SupportAzureRBAC) { "PIM Secure Assignment - Fase $Phase [Entra ID + Azure RBAC]" } 
             else { "PIM Secure Assignment - Fase $Phase [Solo Entra ID]" }
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  $title  ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    # 1. Validar prerequisites Entra ID
    Test-Prerequisites -Phase $Phase
    
    # 2. Validar prerequisites Azure RBAC (si habilitado)
    if ($SupportAzureRBAC) {
        $azContext = Test-AzureRBACPrerequisites
    }
    
    # 3. Cargar y validar CSV
    Write-Host "`n=== Cargando CSV ===" -ForegroundColor Cyan
    $csvData = Import-Csv -Path $CsvPath -Encoding UTF8
    Test-CsvStructureExtended -CsvData $csvData
    
    # 4. Confirmación
    if (-not $Force -and -not $DryRun) {
        Write-Host "`n⚠️  Se procesarán $($csvData.Count) asignaciones" -ForegroundColor Yellow
        Write-Host "⚠️  Fase: $Phase | Modo: PRODUCCIÓN" -ForegroundColor Yellow
        if ($SupportAzureRBAC) {
            Write-Host "⚠️  Azure RBAC: HABILITADO" -ForegroundColor Yellow
        }
        $confirm = Read-Host "`n¿Continuar? (escriba 'SI' para confirmar)"
        if ($confirm -ne 'SI') {
            Write-Host "`nOperación cancelada" -ForegroundColor Red
            return
        }
    }
    
    # 5. Procesar asignaciones
    Write-Host "`n=== Procesando Asignaciones ===" -ForegroundColor Cyan
    if ($DryRun) {
        Write-Host "[MODO DRY-RUN ACTIVO]`n" -ForegroundColor Yellow
    }
    
    $progress = 0
    foreach ($row in $csvData) {
        $progress++
        Write-Progress -Activity "Procesando asignaciones PIM" `
            -Status "Fila $progress de $($csvData.Count)" `
            -PercentComplete (($progress / $csvData.Count) * 100)
        
        Write-Host "`n[$progress/$($csvData.Count)] Procesando Principal: $($row.PrincipalId)" -ForegroundColor White
        
        $rowHash = @{}
        $row.PSObject.Properties | ForEach-Object { $rowHash[$_.Name] = $_.Value }
        
        New-PIMEligibilityAssignmentExtended -Row $rowHash -Phase $Phase
    }
    
    Write-Progress -Activity "Procesando asignaciones PIM" -Completed
    
    # 6. Exportar auditoría
    Write-Host "`n=== Generando Reportes ===" -ForegroundColor Cyan
    Export-AuditReportExtended
    
    # 7. Mensaje final
    if ($DryRun) {
        Write-Host "`n✓ Simulación completada" -ForegroundColor Green
    }
    else {
        Write-Host "`n✓ Procesamiento completado" -ForegroundColor Green
    }
}

function Export-AuditReportExtended {
    <#
    .SYNOPSIS
        Exporta reporte con estadísticas extendidas
    #>
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $shortHash = $script:CsvHash.Substring(0, 8)
    
    # CSV
    $csvFile = "PIM_Audit_${shortHash}_${timestamp}.csv"
    $script:AuditLog | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "`n✓ Reporte CSV: $csvFile" -ForegroundColor Green
    
    # JSON
    $jsonFile = "PIM_Audit_${shortHash}_${timestamp}.json"
    $auditData = @{
        Metadata = @{
            CsvHash = $script:CsvHash
            Phase = $Phase
            DryRun = $DryRun.IsPresent
            AzureRBACSupport = $SupportAzureRBAC.IsPresent
            ExecutedBy = (Get-MgContext).Account
            ExecutedAt = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        }
        Statistics = $script:Statistics
        Entries = $script:AuditLog
    }
    $auditData | ConvertTo-Json -Depth 10 | Out-File $jsonFile -Encoding UTF8
    Write-Host "✓ Reporte JSON: $jsonFile" -ForegroundColor Green
    
    # Resumen
    Write-Host "`n=== RESUMEN DE EJECUCIÓN ===" -ForegroundColor Cyan
    Write-Host "Total procesado:    $($script:Statistics.Total)" -ForegroundColor White
    Write-Host "Exitoso:            $($script:Statistics.Success)" -ForegroundColor Green
    Write-Host "  - Roles Entra ID: $($script:Statistics.EntraRoles)" -ForegroundColor White
    Write-Host "  - Roles Azure:    $($script:Statistics.AzureRoles)" -ForegroundColor White
    Write-Host "  - Grupos PIM:     $($script:Statistics.Groups)" -ForegroundColor White
    Write-Host "Fallido:            $($script:Statistics.Failed)" -ForegroundColor Red
    Write-Host "Omitido:            $($script:Statistics.Skipped)" -ForegroundColor Yellow
    Write-Host "Conflictos:         $($script:Statistics.Conflicts)" -ForegroundColor Magenta
}

# Importar funciones del script original (omitidas por brevedad)
# - Test-Prerequisites, Add-AuditEntry, Test-InputValidations, Invoke-WithRetry, etc.

try {
    Start-Transcript -Path "PIM_Execution_${timestamp}.log"
    Start-PIMAssignmentExtended
}
catch {
    Write-Error "Error fatal: $_"
}
finally {
    Stop-Transcript
}

#endregion
