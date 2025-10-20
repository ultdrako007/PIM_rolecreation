<#
.SYNOPSIS
    Script modular para asignación segura de roles PIM en Entra ID
    
.DESCRIPTION
    Implementa controles de seguridad en fases:
    - Fase 0: Controles críticos de seguridad
    - Fase 1: Validaciones avanzadas y auditoría
    - Fase 2: Optimizaciones y manejo robusto
    
.PARAMETER CsvPath
    Ruta al archivo CSV con las asignaciones
    
.PARAMETER Phase
    Fase de controles a ejecutar (0, 1, 2)
    
.PARAMETER DryRun
    Modo simulación - no ejecuta cambios reales
    
.PARAMETER Force
    Omite confirmaciones interactivas
    
.EXAMPLE
    .\PIM-SecureAssignment.ps1 -CsvPath "assignments.csv" -Phase 0 -DryRun
    .\PIM-SecureAssignment.ps1 -CsvPath "assignments.csv" -Phase 2 -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet(0, 1, 2)]
    [int]$Phase = -1,
    
    [switch]$DryRun,
    [switch]$Force
)

#region Configuration

# Lista blanca de roles por Tier
$script:AllowedRoles = @{
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
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b' = @{ Name = 'Directory Readers'; MaxDuration = 'P30D'; RequiresApproval = $false }
    }
}

# Permisos mínimos por fase
$script:RequiredPermissions = @{
    0 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup')
    1 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup', 'RoleManagement.Read.Directory')
    2 = @('RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup', 'RoleManagement.Read.Directory', 'Policy.Read.All')
}

# Variables globales para auditoría
$script:AuditLog = @()
$script:CsvHash = $null
$script:Statistics = @{
    Total = 0
    Success = 0
    Failed = 0
    Skipped = 0
    Conflicts = 0
}

#endregion

#region Menu & User Interface

function Show-PIMMenu {
    <#
    .SYNOPSIS
        Muestra menú interactivo con información del script
    #>
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "                    SCRIPT DE ASIGNACIÓN SEGURA DE ROLES PIM" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    Write-Host "DESCRIPCIÓN:" -ForegroundColor Yellow
    Write-Host "  Este script implementa asignaciones seguras de roles PIM en Entra ID" -ForegroundColor White
    Write-Host "  con controles de seguridad graduales por fases y auditoría completa." -ForegroundColor White
    
    Write-Host "`nFUNCIONALIDADES PRINCIPALES:" -ForegroundColor Yellow
    Write-Host "  ✓ Lista blanca de roles permitidos por Tier" -ForegroundColor Green
    Write-Host "  ✓ Validación de conflictos con roles permanentes" -ForegroundColor Green
    Write-Host "  ✓ Verificación de políticas PIM (MFA requerida)" -ForegroundColor Green
    Write-Host "  ✓ Auditoría detallada con hash de integridad" -ForegroundColor Green
    Write-Host "  ✓ Manejo robusto de errores y throttling" -ForegroundColor Green
    Write-Host "  ✓ Modo simulación (Dry-Run) para pruebas" -ForegroundColor Green
    
    Write-Host "`nFASES DE SEGURIDAD:" -ForegroundColor Yellow
    Write-Host "  [0] FASE CRÍTICA - Controles básicos de seguridad" -ForegroundColor White
    Write-Host "      • Validación de roles permitidos" -ForegroundColor Gray
    Write-Host "      • Detección de conflictos con roles permanentes" -ForegroundColor Gray
    Write-Host "      • Verificación de idempotencia" -ForegroundColor Gray
    
    Write-Host "  [1] FASE AVANZADA - Validaciones extendidas" -ForegroundColor White
    Write-Host "      • Validación de formato de datos (GUID, ISO-8601)" -ForegroundColor Gray
    Write-Host "      • Cumplimiento de duraciones máximas" -ForegroundColor Gray
    Write-Host "      • Verificación de políticas PIM" -ForegroundColor Gray
    
    Write-Host "  [2] FASE OPTIMIZADA - Robustez y performance" -ForegroundColor White
    Write-Host "      • Manejo de throttling con reintentos" -ForegroundColor Gray
    Write-Host "      • Nombres descriptivos de roles" -ForegroundColor Gray
    Write-Host "      • Reportes mejorados" -ForegroundColor Gray
    
    Write-Host "`nDATOS SOLICITADOS:" -ForegroundColor Yellow
    Write-Host "  • Archivo CSV con las asignaciones a procesar" -ForegroundColor White
    Write-Host "  • Fase de seguridad a ejecutar (0, 1, 2)" -ForegroundColor White
    Write-Host "  • Confirmación para ejecución en producción" -ForegroundColor White
    
    Write-Host "`nCOLUMNAS REQUERIDAS EN CSV:" -ForegroundColor Yellow
    Write-Host "  • PrincipalId    (GUID del usuario/entidad de servicio)" -ForegroundColor White
    Write-Host "  • RoleDefinitionId (GUID del rol de Entra ID)" -ForegroundColor White
    Write-Host "  • DirectoryScopeId (GUID del ámbito, típicamente '/')" -ForegroundColor White
    Write-Host "  • Duration       (Duración en formato ISO-8601: PT8H, P1D, etc.)" -ForegroundColor White
    Write-Host "  • Reason         (Justificación con referencia a ticket)" -ForegroundColor White
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
}

function Get-UserInput {
    <#
    .SYNOPSIS
        Solicita datos al usuario de forma interactiva
    #>
    
    # Mostrar menú informativo
    Show-PIMMenu
    
    # Solicitar ruta del CSV si no se proporcionó
    while ([string]::IsNullOrWhiteSpace($script:CsvPath)) {
        $script:CsvPath = Read-Host "`n📁 Ingrese la ruta del archivo CSV"
        if (-not (Test-Path $script:CsvPath)) {
            Write-Host "❌ Archivo no encontrado. Verifique la ruta." -ForegroundColor Red
            $script:CsvPath = $null
        }
    }
    
    # Solicitar fase si no se proporcionó
    while ($script:Phase -eq -1) {
        $phaseInput = Read-Host "`n🔒 Ingrese la fase de seguridad a ejecutar (0, 1, 2)"
        if ($phaseInput -in @('0','1','2')) {
            $script:Phase = [int]$phaseInput
        } else {
            Write-Host "❌ Fase inválida. Debe ser 0, 1 o 2." -ForegroundColor Red
        }
    }
    
    # Solicitar modo DryRun si no se especificó
    if (-not $DryRun) {
        $dryRunInput = Read-Host "`n🧪 ¿Ejecutar en modo simulación (DryRun)? (S/N)"
        $DryRun = ($dryRunInput -eq 'S' -or $dryRunInput -eq 's')
    }
    
    # Mostrar resumen de configuración
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "           RESUMEN DE CONFIGURACIÓN" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    Write-Host "📁 Archivo CSV: $script:CsvPath" -ForegroundColor White
    Write-Host "🔒 Fase de seguridad: $script:Phase" -ForegroundColor White
    Write-Host "🧪 Modo simulación: $(if($DryRun){'ACTIVADO'}else{'DESACTIVADO'})" -ForegroundColor White
    Write-Host "⏱️  Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    Write-Host "="*80 -ForegroundColor Cyan
    
    # Confirmación final para ejecución en producción
    if (-not $DryRun -and -not $Force) {
        $confirm = Read-Host "`n⚠️  ¿ESTÁ SEGURO DE EJECUTAR EN MODO PRODUCCIÓN? (escriba 'CONFIRMAR' para continuar)"
        if ($confirm -ne 'CONFIRMAR') {
            Write-Host "`n❌ Ejecución cancelada por el usuario." -ForegroundColor Red
            exit
        }
    }
}

#endregion

#region Utility Functions

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Ejecuta comando con reintentos exponenciales ante throttling
    #>
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
                Write-Warning "Throttling detectado. Reintento $attempt/$MaxRetries en $delay segundos..."
                Start-Sleep -Seconds $delay
            }
            else {
                throw
            }
        }
    }
}

function Test-PrincipalExists {
    <#
    .SYNOPSIS
        Verifica que el PrincipalId exista en el directorio
    #>
    [CmdletBinding()]
    param([string]$PrincipalId)
    
    try {
        # Intentar obtener como usuario
        $user = Invoke-WithRetry -ScriptBlock {
            Get-MgUser -UserId $PrincipalId -ErrorAction SilentlyContinue
        }
        if ($user) {
            Write-Verbose "✓ Principal validado (Usuario): $($user.DisplayName)"
            return $true
        }
        
        # Intentar obtener como service principal
        $sp = Invoke-WithRetry -ScriptBlock {
            Get-MgServicePrincipal -ServicePrincipalId $PrincipalId -ErrorAction SilentlyContinue
        }
        if ($sp) {
            Write-Verbose "✓ Principal validado (Service Principal): $($sp.DisplayName)"
            return $true
        }
        
        Write-Warning "PrincipalId no encontrado en el directorio: $PrincipalId"
        return $false
    }
    catch {
        Write-Warning "Error validando PrincipalId $PrincipalId : $_"
        return $false
    }
}

#endregion

#region Phase 0 Functions - Critical Security Controls

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Valida prerequisitos del entorno
    #>
    [CmdletBinding()]
    param([int]$Phase)
    
    Write-Host "`n=== Validando Prerequisites (Fase $Phase) ===" -ForegroundColor Cyan
    
    # Validar archivo CSV
    if (-not (Test-Path $CsvPath)) {
        throw "ERROR: Archivo CSV no encontrado: $CsvPath"
    }
    
    # Calcular hash del CSV
    $script:CsvHash = (Get-FileHash -Path $CsvPath -Algorithm SHA256).Hash
    Write-Host "✓ CSV Hash: $($script:CsvHash.Substring(0,16))..." -ForegroundColor Green
    
    # Validar módulos
    $requiredModules = @('Microsoft.Graph.Identity.Governance', 'Microsoft.Graph.Identity.SignIns')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            throw "ERROR: Módulo requerido no instalado: $module"
        }
        Import-Module $module -ErrorAction Stop
        Write-Host "✓ Módulo cargado: $module" -ForegroundColor Green
    }
    
    # Validar conexión Graph
    $context = Get-MgContext
    if ($null -eq $context) {
        Write-Host "🔐 Conectando a Microsoft Graph..." -ForegroundColor Yellow
        $requiredScopes = $script:RequiredPermissions[$Phase]
        Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
        $context = Get-MgContext
    }
    
    # Validar permisos requeridos
    $requiredScopes = $script:RequiredPermissions[$Phase]
    $grantedScopes = $context.Scopes
    
    foreach ($scope in $requiredScopes) {
        if ($scope -notin $grantedScopes) {
            throw "ERROR: Falta permiso requerido para Fase ${Phase}: $scope"
        }
    }
    Write-Host "✓ Permisos validados: $($requiredScopes.Count) scopes" -ForegroundColor Green
    
    Write-Host "✓ Usuario conectado: $($context.Account)" -ForegroundColor Green
}

function Test-CsvStructure {
    <#
    .SYNOPSIS
        Valida estructura y contenido del CSV
    #>
    [CmdletBinding()]
    param([array]$CsvData)
    
    Write-Host "`n=== Validando Estructura CSV ===" -ForegroundColor Cyan
    
    # Validar columnas requeridas
    $requiredColumns = @('PrincipalId', 'Reason', 'Duration')
    $csvHeaders = $CsvData[0].PSObject.Properties.Name
    
    foreach ($col in $requiredColumns) {
        if ($col -notin $csvHeaders) {
            throw "ERROR: Falta columna requerida en CSV: $col"
        }
    }
    Write-Host "✓ Columnas requeridas presentes" -ForegroundColor Green
    
    # Validar que tiene al menos una columna de destino
    $hasTarget = ($csvHeaders -contains 'RoleDefinitionId') -or ($csvHeaders -contains 'GroupId')
    if (-not $hasTarget) {
        throw "ERROR: CSV debe contener 'RoleDefinitionId' o 'GroupId'"
    }
    
    Write-Host "✓ Estructura CSV válida: $($CsvData.Count) filas" -ForegroundColor Green
}

function Test-RoleAllowed {
    <#
    .SYNOPSIS
        Verifica si un rol está en la lista blanca
    #>
    [CmdletBinding()]
    param(
        [string]$RoleDefinitionId,
        [string]$PrincipalId
    )
    
    $allAllowed = @{}
    foreach ($tier in $script:AllowedRoles.Keys) {
        $allAllowed += $script:AllowedRoles[$tier]
    }
    
    if ($RoleDefinitionId -notin $allAllowed.Keys) {
        Write-Warning "ROL BLOQUEADO: $RoleDefinitionId no está en lista blanca para Principal $PrincipalId"
        Add-AuditEntry -PrincipalId $PrincipalId -Action "RoleBlocked" -Status "Blocked" -Details "Rol no autorizado: $RoleDefinitionId"
        return $false
    }
    
    return $true
}

function Test-ExistingRoleAssignment {
    <#
    .SYNOPSIS
        Detecta conflictos con asignaciones permanentes existentes
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$DirectoryScopeId
    )
    
    try {
        $filter = "principalId eq '$PrincipalId' and roleDefinitionId eq '$RoleDefinitionId'"
        $existingAssignments = Invoke-WithRetry -ScriptBlock {
            Get-MgRoleManagementDirectoryRoleAssignment -Filter $filter -ErrorAction Stop
        }
        
        if ($existingAssignments) {
            Write-Warning "CONFLICTO: Principal $PrincipalId tiene asignación permanente activa"
            
            $script:Statistics.Conflicts++
            Add-AuditEntry -PrincipalId $PrincipalId -RoleOrGroup $RoleDefinitionId `
                -Action "ConflictDetected" -Status "Warning" `
                -Details "Asignación permanente existente: $($existingAssignments[0].Id)"
            
            return @{
                HasConflict = $true
                Assignments = $existingAssignments
            }
        }
    }
    catch {
        Write-Verbose "Error verificando asignaciones: $_"
    }
    
    return @{ HasConflict = $false }
}

function Test-ExistingEligibility {
    <#
    .SYNOPSIS
        Verifica si ya existe una eligibilidad activa (idempotencia)
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$DirectoryScopeId,
        [string]$GroupId
    )
    
    try {
        if ($RoleDefinitionId) {
            $filter = "principalId eq '$PrincipalId' and roleDefinitionId eq '$RoleDefinitionId'"
            $existing = Invoke-WithRetry -ScriptBlock {
                Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter $filter -ErrorAction SilentlyContinue
            }
        }
        elseif ($GroupId) {
            $filter = "principalId eq '$PrincipalId'"
            $existing = Invoke-WithRetry -ScriptBlock {
                Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule `
                    -PrivilegedAccessGroupId $GroupId -Filter $filter -ErrorAction SilentlyContinue
            }
        }
        
        if ($existing) {
            Write-Host "IDEMPOTENCIA: Eligibilidad ya existe para Principal $PrincipalId" -ForegroundColor Yellow
            $script:Statistics.Skipped++
            Add-AuditEntry -PrincipalId $PrincipalId -Action "Skipped" -Status "AlreadyExists" `
                -Details "Eligibilidad existente: $($existing[0].Id)"
            return $true
        }
    }
    catch {
        Write-Verbose "Error verificando eligibilidad: $_"
    }
    
    return $false
}

#endregion

#region Phase 1 Functions - Advanced Validations

function Test-InputValidations {
    <#
    .SYNOPSIS
        Validaciones estrictas de formato de datos
    #>
    [CmdletBinding()]
    param([hashtable]$Row)
    
    $errors = @()
    
    # Validar GUID de PrincipalId
    try {
        [System.Guid]::Parse($Row.PrincipalId) | Out-Null
    }
    catch {
        $errors += "PrincipalId inválido: $($Row.PrincipalId)"
    }
    
    # Validar que el PrincipalId exista en el directorio
    if (-not (Test-PrincipalExists -PrincipalId $Row.PrincipalId)) {
        $errors += "PrincipalId no existe en el directorio: $($Row.PrincipalId)"
    }
    
    # Validar GUID de RoleDefinitionId (si aplica)
    if ($Row.RoleDefinitionId) {
        try {
            [System.Guid]::Parse($Row.RoleDefinitionId) | Out-Null
        }
        catch {
            $errors += "RoleDefinitionId inválido: $($Row.RoleDefinitionId)"
        }
    }
    
    # Validar GUID de GroupId (si aplica)
    if ($Row.GroupId) {
        try {
            [System.Guid]::Parse($Row.GroupId) | Out-Null
        }
        catch {
            $errors += "GroupId inválido: $($Row.GroupId)"
        }
    }
    
    # Validar formato ISO-8601 de Duration
    if ($Row.Duration -notmatch '^P(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$') {
        $errors += "Duration formato ISO-8601 inválido: $($Row.Duration)"
    }
    
    # Validar que Reason contenga referencia a ticket (mínimo 5 caracteres)
    if ($Row.Reason.Length -lt 5) {
        $errors += "Justificación insuficiente (mínimo 5 caracteres)"
    }
    
    if ($errors.Count -gt 0) {
        Write-Warning "Validaciones fallidas para Principal $($Row.PrincipalId):"
        $errors | ForEach-Object { Write-Warning "  - $_" }
        return $false
    }
    
    return $true
}

function Test-DurationCompliance {
    <#
    .SYNOPSIS
        Verifica que la duración cumple límites por Tier
    #>
    [CmdletBinding()]
    param(
        [string]$RoleDefinitionId,
        [string]$Duration
    )
    
    # Buscar configuración del rol
    $roleConfig = $null
    foreach ($tier in $script:AllowedRoles.Keys) {
        if ($script:AllowedRoles[$tier].ContainsKey($RoleDefinitionId)) {
            $roleConfig = $script:AllowedRoles[$tier][$RoleDefinitionId]
            break
        }
    }
    
    if (-not $roleConfig) {
        return $true  # Ya validado en Test-RoleAllowed
    }
    
    # Convertir duraciones a TimeSpan para comparar
    $requestedDuration = [System.Xml.XmlConvert]::ToTimeSpan($Duration)
    $maxDuration = [System.Xml.XmlConvert]::ToTimeSpan($roleConfig.MaxDuration)
    
    if ($requestedDuration -gt $maxDuration) {
        Write-Warning "Duración excede límite para rol $($roleConfig.Name): $Duration > $($roleConfig.MaxDuration)"
        return $false
    }
    
    return $true
}

function Test-PIMPolicyCompliance {
    <#
    .SYNOPSIS
        Valida que las políticas PIM del rol cumplan requisitos de seguridad
    #>
    [CmdletBinding()]
    param([string]$RoleDefinitionId)
    
    try {
        # Obtener política PIM del rol
        $policyAssignment = Invoke-WithRetry -ScriptBlock {
            Get-MgPolicyRoleManagementPolicyAssignment `
                -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleDefinitionId'" `
                -ErrorAction Stop
        }
        
        if (-not $policyAssignment) {
            Write-Warning "No se encontró política PIM para rol: $RoleDefinitionId"
            return $true  # Continuar con advertencia
        }
        
        $policy = Invoke-WithRetry -ScriptBlock {
            Get-MgPolicyRoleManagementPolicy -UnifiedRoleManagementPolicyId $policyAssignment[0].PolicyId -ErrorAction Stop
        }
        
        # Verificar requisitos mínimos
        $requiresMFA = $policy.Rules | Where-Object { 
            $_.Id -eq 'Enablement_EndUser_Assignment' -and 
            $_.AdditionalProperties.enabledRules -contains 'MultiFactorAuthentication'
        }
        
        if (-not $requiresMFA) {
            Write-Warning "POLÍTICA INSEGURA: Rol $RoleDefinitionId no requiere MFA para activación"
            return $false
        }
        
        Write-Verbose "✓ Política PIM verificada para rol $RoleDefinitionId"
        return $true
    }
    catch {
        Write-Warning "Error verificando política PIM: $_"
        return $true  # No bloquear por error de lectura
    }
}

#endregion

#region Phase 2 Functions - Optimization & Robustness

function Get-RoleFriendlyName {
    <#
    .SYNOPSIS
        Obtiene nombre descriptivo del rol
    #>
    [CmdletBinding()]
    param([string]$RoleDefinitionId)
    
    foreach ($tier in $script:AllowedRoles.Keys) {
        if ($script:AllowedRoles[$tier].ContainsKey($RoleDefinitionId)) {
            return $script:AllowedRoles[$tier][$RoleDefinitionId].Name
        }
    }
    return $RoleDefinitionId
}

#endregion

#region Audit & Logging Functions

function Add-AuditEntry {
    <#
    .SYNOPSIS
        Registra evento en el log de auditoría
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$RoleOrGroup = '',
        [string]$Action,
        [string]$Status,
        [string]$Details = '',
        [string]$RequestId = ''
    )
    
    $script:AuditLog += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        PrincipalId = $PrincipalId
        RoleOrGroup = $RoleOrGroup
        Action = $Action
        Status = $Status
        Details = $Details
        RequestId = $RequestId
        ExecutedBy = (Get-MgContext).Account
        CsvHash = $script:CsvHash
        Phase = $Phase
        DryRun = $DryRun.IsPresent
    }
}

function Export-AuditReport {
    <#
    .SYNOPSIS
        Exporta reporte de auditoría
    #>
    [CmdletBinding()]
    param()
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $shortHash = $script:CsvHash.Substring(0, 8)
    
    # Exportar CSV
    $csvFile = "PIM_Audit_${shortHash}_${timestamp}.csv"
    $script:AuditLog | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "`n✓ Reporte CSV: $csvFile" -ForegroundColor Green
    
    # Exportar JSON
    $jsonFile = "PIM_Audit_${shortHash}_${timestamp}.json"
    $auditData = @{
        Metadata = @{
            CsvHash = $script:CsvHash
            Phase = $Phase
            DryRun = $DryRun.IsPresent
            ExecutedBy = (Get-MgContext).Account
            ExecutedAt = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        }
        Statistics = $script:Statistics
        Entries = $script:AuditLog
    }
    $auditData | ConvertTo-Json -Depth 10 | Out-File $jsonFile -Encoding UTF8
    Write-Host "✓ Reporte JSON: $jsonFile" -ForegroundColor Green
    
    # Mostrar resumen
    Write-Host "`n=== RESUMEN DE EJECUCIÓN ===" -ForegroundColor Cyan
    Write-Host "Total procesado:  $($script:Statistics.Total)" -ForegroundColor White
    Write-Host "Exitoso:          $($script:Statistics.Success)" -ForegroundColor Green
    Write-Host "Fallido:          $($script:Statistics.Failed)" -ForegroundColor Red
    Write-Host "Omitido:          $($script:Statistics.Skipped)" -ForegroundColor Yellow
    Write-Host "Conflictos:       $($script:Statistics.Conflicts)" -ForegroundColor Magenta
}

#endregion

#region Main Processing Functions

function New-PIMEligibilityAssignment {
    <#
    .SYNOPSIS
        Crea asignación de eligibilidad PIM
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Row,
        [int]$Phase
    )
    
    $script:Statistics.Total++
    
    try {
        # Fase 0: Validaciones críticas
        if (-not (Test-RoleAllowed -RoleDefinitionId $Row.RoleDefinitionId -PrincipalId $Row.PrincipalId)) {
            $script:Statistics.Failed++
            return
        }
        
        $conflictCheck = Test-ExistingRoleAssignment -PrincipalId $Row.PrincipalId `
            -RoleDefinitionId $Row.RoleDefinitionId -DirectoryScopeId $Row.DirectoryScopeId
        
        if ($conflictCheck.HasConflict) {
            Write-Host "  → Requiere migración manual de rol permanente" -ForegroundColor Yellow
            $script:Statistics.Skipped++
            return
        }
        
        if (Test-ExistingEligibility -PrincipalId $Row.PrincipalId -RoleDefinitionId $Row.RoleDefinitionId `
                -DirectoryScopeId $Row.DirectoryScopeId -GroupId $Row.GroupId) {
            return
        }
        
        # Fase 1: Validaciones avanzadas
        if ($Phase -ge 1) {
            if (-not (Test-InputValidations -Row $Row)) {
                $script:Statistics.Failed++
                Add-AuditEntry -PrincipalId $Row.PrincipalId -Action "ValidationFailed" -Status "Error" `
                    -Details "Falló validación de formato"
                return
            }
            
            if ($Row.RoleDefinitionId -and -not (Test-DurationCompliance -RoleDefinitionId $Row.RoleDefinitionId -Duration $Row.Duration)) {
                $script:Statistics.Failed++
                Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.RoleDefinitionId `
                    -Action "DurationExceeded" -Status "Error" -Details "Duración excede límite permitido"
                return
            }
            
            if ($Row.RoleDefinitionId -and -not (Test-PIMPolicyCompliance -RoleDefinitionId $Row.RoleDefinitionId)) {
                Write-Warning "  → Política PIM no cumple requisitos mínimos, revisar manualmente"
            }
        }
        
        # Modo Dry-Run
        if ($DryRun) {
            $roleName = if ($Phase -ge 2) { Get-RoleFriendlyName -RoleDefinitionId $Row.RoleDefinitionId } else { $Row.RoleDefinitionId }
            Write-Host "[DRY-RUN] Eligibilidad para: $($Row.PrincipalId)" -ForegroundColor Cyan
            Write-Host "[DRY-RUN] Rol: $roleName | Duración: $($Row.Duration)" -ForegroundColor Cyan
            $script:Statistics.Success++
            Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.RoleDefinitionId `
                -Action "DryRunSimulated" -Status "Success" -Details $Row.Reason
            return
        }
        
        # Crear eligibilidad real
        $currentDate = Get-Date
        
        if ($Row.RoleDefinitionId -and $Row.DirectoryScopeId) {
            # Rol de Entra ID
            $params = @{
                PrincipalId = $Row.PrincipalId
                RoleDefinitionId = $Row.RoleDefinitionId
                DirectoryScopeId = $Row.DirectoryScopeId
                Action = "AdminAssign"
                Justification = $Row.Reason
                ScheduleInfo = @{
                    StartDateTime = $currentDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    Expiration = @{
                        Type = "AfterDuration"
                        Duration = $Row.Duration
                    }
                }
            }
            
            $response = Invoke-WithRetry -ScriptBlock {
                New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params
            }
            
            Write-Host "✓ Eligibilidad creada para Principal: $($Row.PrincipalId)" -ForegroundColor Green
            $script:Statistics.Success++
            Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.RoleDefinitionId `
                -Action "EligibilityCreated" -Status "Success" -Details $Row.Reason -RequestId $response.Id
        }
        elseif ($Row.GroupId) {
            # Grupo PIM
            $params = @{
                AccessId = "member"
                PrincipalId = $Row.PrincipalId
                GroupId = $Row.GroupId
                Action = "AdminAssign"
                Justification = $Row.Reason
                ScheduleInfo = @{
                    StartDateTime = $currentDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    Expiration = @{
                        Type = "AfterDuration"
                        Duration = $Row.Duration
                    }
                }
            }
            
            $response = Invoke-WithRetry -ScriptBlock {
                New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params
            }
            
            Write-Host "✓ Membresía de grupo creada para Principal: $($Row.PrincipalId)" -ForegroundColor Green
            $script:Statistics.Success++
            Add-AuditEntry -PrincipalId $Row.PrincipalId -RoleOrGroup $Row.GroupId `
                -Action "GroupMembershipCreated" -Status "Success" -Details $Row.Reason -RequestId $response.Id
        }
        else {
            Write-Warning "Fila omitida: falta RoleDefinitionId/DirectoryScopeId o GroupId para Principal: $($Row.PrincipalId)"
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

function Start-PIMAssignment {
    <#
    .SYNOPSIS
        Función principal de procesamiento
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  PIM Secure Assignment Script - Fase $Phase                    ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    # 1. Obtener datos del usuario si no se proporcionaron por parámetro
    if ([string]::IsNullOrWhiteSpace($CsvPath) -or $Phase -eq -1) {
        Get-UserInput
    }
    
    # 2. Validar prerequisites
    Test-Prerequisites -Phase $Phase
    
    # 3. Cargar y validar CSV
    Write-Host "`n=== Cargando CSV ===" -ForegroundColor Cyan
    $csvData = Import-Csv -Path $CsvPath -Encoding UTF8
    Test-CsvStructure -CsvData $csvData
    
    # 4. Confirmación (si no es Force ni DryRun)
    if (-not $Force -and -not $DryRun) {
        Write-Host "`n⚠️  Se procesarán $($csvData.Count) asignaciones" -ForegroundColor Yellow
        Write-Host "⚠️  Fase: $Phase | Modo: PRODUCCIÓN" -ForegroundColor Yellow
        $confirm = Read-Host "`n¿Continuar? (escriba 'SI' para confirmar)"
        if ($confirm -ne 'SI') {
            Write-Host "`nOperación cancelada por el usuario" -ForegroundColor Red
            return
        }
    }
    
    # 5. Procesar asignaciones
    Write-Host "`n=== Procesando Asignaciones ===" -ForegroundColor Cyan
    if ($DryRun) {
        Write-Host "[MODO DRY-RUN ACTIVO - No se aplicarán cambios]`n" -ForegroundColor Yellow
    }
    
    $progress = 0
    foreach ($row in $csvData) {
        $progress++
        Write-Progress -Activity "Procesando asignaciones PIM" `
            -Status "Fila $progress de $($csvData.Count)" `
            -PercentComplete (($progress / $csvData.Count) * 100)
        
        Write-Host "`n[$progress/$($csvData.Count)] Procesando Principal: $($row.PrincipalId)" -ForegroundColor White
        
        # Convertir fila a hashtable
        $rowHash = @{}
        $row.PSObject.Properties | ForEach-Object { $rowHash[$_.Name] = $_.Value }
        
        New-PIMEligibilityAssignment -Row $rowHash -Phase $Phase
    }
    
    Write-Progress -Activity "Procesando asignaciones PIM" -Completed
    
    # 6. Exportar auditoría
    Write-Host "`n=== Generando Reportes de Auditoría ===" -ForegroundColor Cyan
    Export-AuditReport
    
    # 7. Mensaje final
    if ($DryRun) {
        Write-Host "`n✓ Simulación completada exitosamente" -ForegroundColor Green
        Write-Host "  Para ejecutar en producción, remueva el parámetro -DryRun" -ForegroundColor Yellow
    }
    else {
        Write-Host "`n✓ Procesamiento completado" -ForegroundColor Green
    }
}

#endregion

#region Main Execution

try {
    # Crear directorio para logs si no existe
    $logDir = "PIM_Logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }
    
    $logFile = Join-Path $logDir "PIM_Execution_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $logFile
    
    Write-Host "Iniciando Script de Asignación Segura PIM..." -ForegroundColor Green
    Write-Host "Log de ejecución: $logFile" -ForegroundColor Gray
    
    Start-PIMAssignment
}
catch {
    Write-Error "Error fatal: $_"
    $script:Statistics.Failed++
    Add-AuditEntry -PrincipalId "SYSTEM" -Action "FatalError" -Status "Failed" -Details $_.Exception.Message
}
finally {
    Stop-Transcript
    Write-Host "`nEjecución finalizada. Revisar el log: $logFile" -ForegroundColor Gray
}

#endregion