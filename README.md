# PIM_rolecreation
Script de creacion de roles en PIM 2025
EFP013

🎯 PROPÓSITO Y ALCANCE
Objetivo Principal
El script Creacion_de_roles_PIM.ps1 es una herramienta enterprise-grade diseñada para la gestión segura y automatizada de asignaciones de roles privilegiados en Microsoft Entra ID mediante Privileged Identity Management (PIM).

Problema que Resuelve
Automatiza el proceso de asignación de roles administrativos con controles de seguridad estrictos, eliminando el riesgo de asignaciones permanentes no autorizadas y garantizando el principio de menor privilegio.

Público Objetivo
Administradores de Identidades y Accesos

Equipos de Seguridad de la Información

Administradores de Entra ID/Azure AD

Equipos de Operaciones de TI

🏗️ ARQUITECTURA TÉCNICA
Diseño Modular por Capas
text
CAPA DE PRESENTACIÓN
├── Menú interactivo
├── Solicitud de parámetros
└── Interfaz de usuario

CAPA DE VALIDACIÓN
├── Validaciones de seguridad por fases
├── Verificación de permisos
└── Control de entradas

CAPA DE NEGOCIO
├── Gestión de asignaciones PIM
├── Procesamiento de CSV
└── Lógica de negocios

CAPA DE DATOS
├── Microsoft Graph API
├── Archivos CSV de entrada
└── Reportes de auditoría

CAPA DE AUDITORÍA
├── Logging de operaciones
├── Reportes ejecutivos
└── Trazabilidad completa
Componentes Principales
1. Motor de Configuración (Configuration)
powershell
# Lista blanca de roles por Tier de seguridad
$script:AllowedRoles = @{
    Tier0 = @{  # Roles críticos - Máxima seguridad
        '62e90394-69f5-4237-9190-012177145e10' = @{ 
            Name = 'Global Administrator'; 
            MaxDuration = 'PT8H'; 
            RequiresApproval = $true 
        }
    }
    Tier1 = @{  # Roles administrativos - Seguridad media
        # Configuraciones específicas...
    }
    Tier2 = @{  # Roles operativos - Seguridad básica
        # Configuraciones específicas...
    }
}

2. Motor de Validación (Validation Engine)
Validaciones de Fase 0: Controles críticos de seguridad

Validaciones de Fase 1: Validaciones avanzadas y compliance

Validaciones de Fase 2: Optimizaciones y robustez

3. Motor de Ejecución (Execution Engine)
Procesamiento de asignaciones

Manejo de errores y reintentos

Creación de solicitudes PIM

4. Motor de Auditoría (Audit Engine)
Registro de todas las operaciones

Generación de reportes múltiples

Trazabilidad completa

🔄 FLUJO DE EJECUCIÓN DETALLADO
Fase 1: Inicialización y Configuración
text
1. START Script
   ↓
2. PARSE Parameters (CsvPath, Phase, DryRun, Force)
   ↓
3. SHOW Interactive Menu (si parámetros faltan)
   ↓
4. LOAD Configuration ($AllowedRoles, $RequiredPermissions)
   ↓
5. INIT Global Variables ($AuditLog, $Statistics, $CsvHash)
Fase 2: Validación de Prerrequisitos
text
6. TEST-Prerequisites
   ├── ✅ Verificar archivo CSV existe
   ├── ✅ Calcular hash de integridad CSV
   ├── ✅ Validar módulos PowerShell instalados
   ├── ✅ Conectar a Microsoft Graph (scopes dinámicos)
   ├── ✅ Verificar permisos según fase
   └── ✅ Validar contexto de ejecución
Fase 3: Procesamiento del CSV
text
7. IMPORT-CSV Data
   ↓
8. TEST-CsvStructure
   ├── ✅ Columnas requeridas presentes
   ├── ✅ Formato básico válido
   └── ✅ Integridad de datos
   ↓
9. PROCESS Each Row
   └── ▶️ Por cada fila en el CSV...
   
Fase 4: Validaciones por Fase de Seguridad
Fase 0 - Controles Críticos (Básicos)
powershell
foreach ($row in $csvData) {
    # Validaciones de Fase 0
    Test-RoleAllowed                    # ✅ Lista blanca de roles
    Test-ExistingRoleAssignment         # ✅ Conflictos con roles permanentes
    Test-ExistingEligibility           # ✅ Idempotencia (evita duplicados)
}
Fase 1 - Validaciones Avanzadas
powershell
if ($Phase -ge 1) {
    Test-InputValidations              # ✅ Formatos GUID, ISO-8601
    Test-PrincipalExists               # ✅ Usuario/SPN existe en directorio
    Test-DurationCompliance            # ✅ Límites de duración por rol
    Test-PIMPolicyCompliance           # ✅ Políticas PIM (MFA requerida)
}
Fase 2 - Optimizaciones
powershell
if ($Phase -ge 2) {
    Invoke-WithRetry                   # ✅ Manejo de throttling
    Get-RoleFriendlyName               # ✅ Nombres descriptivos
    # Reportes mejorados y logging extendido
}
Fase 5: Ejecución de Asignaciones
text
10. NEW-PIMEligibilityAssignment
    ├── 🎯 Si DryRun: Simular asignación
    ├── 🚀 Si Producción: Crear asignación real
    │   ├── Para roles de directorio
    │   └── Para membresías de grupo PIM
    └── 📝 Registrar en auditoría
Fase 6: Generación de Reportes
text
11. EXPORT-AuditReport
    ├── 📊 Reporte CSV detallado
    ├── 📋 Reporte JSON estructurado
    ├── 📈 Estadísticas de ejecución
    └── 💾 Log de transcript completo
🔐 CONTROLES DE SEGURIDAD IMPLEMENTADOS
Control 1: Lista Blanca de Roles
powershell
# Solo roles explícitamente permitidos pueden ser asignados
function Test-RoleAllowed {
    param([string]$RoleDefinitionId, [string]$PrincipalId)
    # Bloquea cualquier rol no en $AllowedRoles
}
Control 2: Validación de Conflictos
powershell
# Detecta y previene conflictos con roles permanentes
function Test-ExistingRoleAssignment {
    # Busca asignaciones permanentes existentes
    # Reporta conflictos para resolución manual
}
Control 3: Idempotencia
powershell
# Evita crear duplicados de elegibilidades
function Test-ExistingEligibility {
    # Verifica si ya existe elegibilidad activa
    # Omite creación si ya existe
}
Control 4: Validación de Entidades
powershell
# Confirma que los PrincipalId existen en el directorio
function Test-PrincipalExists {
    # Verifica usuario o service principal
    # Previene asignaciones a entidades inexistentes
}
Control 5: Cumplimiento de Políticas PIM
powershell
# Valida que las políticas PIM cumplan estándares de seguridad
function Test-PIMPolicyCompliance {
    # Verifica que se requiera MFA para activación
    # Alertas sobre políticas inseguras
}
📊 SISTEMA DE AUDITORÍA
Registro de Eventos
Cada operación genera una entrada de auditoría con:

powershell
[PSCustomObject]@{
    Timestamp    = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    PrincipalId  = $PrincipalId
    RoleOrGroup  = $RoleOrGroup
    Action       = $Action           # "EligibilityCreated", "ValidationFailed", etc.
    Status       = $Status           # "Success", "Failed", "Warning"
    Details      = $Details          # Justificación o mensaje de error
    RequestId    = $RequestId        # ID de solicitud PIM (si aplica)
    ExecutedBy   = (Get-MgContext).Account
    CsvHash      = $script:CsvHash   # Hash de integridad del CSV
    Phase        = $Phase
    DryRun       = $DryRun.IsPresent
}
Reportes Generados
Reporte CSV
text
PIM_Audit_[Hash]_[Timestamp].csv
├── Timestamp operación
├── PrincipalId afectado
├── Rol/Grupo asignado
├── Acción realizada
├── Estado de la operación
├── Detalles y justificación
├── ID de solicitud PIM
├── Usuario ejecutor
├── Hash del CSV original
├── Fase ejecutada
└── Modo DryRun
Reporte JSON
json
{
  "Metadata": {
    "CsvHash": "abc123...",
    "Phase": 2,
    "DryRun": false,
    "ExecutedBy": "admin@tenant.com",
    "ExecutedAt": "2023-12-01T14:30:22.123Z"
  },
  "Statistics": {
    "Total": 15,
    "Success": 12,
    "Failed": 1,
    "Skipped": 2,
    "Conflicts": 1
  },
  "Entries": [
    // Todas las entradas de auditoría
  ]
}
🛡️ CARACTERÍSTICAS DE ROBUSTEZ
Manejo de Throttling
powershell
function Invoke-WithRetry {
    param([scriptblock]$ScriptBlock, [int]$MaxRetries = 3)
    
    # Backoff exponencial: 5s → 10s → 20s
    $delay = $BaseDelaySeconds * [Math]::Pow(2, $attempt)
    
    # Aplicado a TODAS las operaciones Graph
    Get-MgUser, Get-MgRoleManagementDirectoryRoleAssignment, etc.
}
Manejo de Errores
powershell
try {
    # Operación principal
    New-PIMEligibilityAssignment -Row $rowHash -Phase $Phase
}
catch {
    # Registro en auditoría
    Add-AuditEntry -PrincipalId $Row.PrincipalId -Action "Error" -Status "Failed" `
        -Details $_.Exception.Message
    
    # Continuación graceful
    $script:Statistics.Failed++
}
Idempotencia Garantizada
Verificación previa de existencia

No creación de duplicados

Estado consistente después de errores

🔧 INTEGRACIÓN CON MICROSOFT GRAPH
Endpoints Utilizados
powershell
# Gestión de Roles de Directorio
Get-MgRoleManagementDirectoryRoleAssignment
New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest
Get-MgRoleManagementDirectoryRoleEligibilitySchedule

# Gestión de Grupos PIM
Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule
New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest

# Políticas y Configuración
Get-MgPolicyRoleManagementPolicyAssignment
Get-MgPolicyRoleManagementPolicy

# Entidades de Directorio
Get-MgUser, Get-MgServicePrincipal
Scopes de Permisos por Fase
powershell
$script:RequiredPermissions = @{
    0 = @(  # Fase Básica
        'RoleEligibilitySchedule.ReadWrite.Directory',
        'PrivilegedAccess.ReadWrite.AzureADGroup'
    )
    1 = @(  # Fase Avanzada (incluye lectura)
        'RoleEligibilitySchedule.ReadWrite.Directory',
        'PrivilegedAccess.ReadWrite.AzureADGroup', 
        'RoleManagement.Read.Directory'
    )
    2 = @(  # Fase Completa (incluye políticas)
        'RoleEligibilitySchedule.ReadWrite.Directory',
        'PrivilegedAccess.ReadWrite.AzureADGroup',
        'RoleManagement.Read.Directory', 
        'Policy.Read.All'
    )
}
🎯 ESCENARIOS DE USO
Escenario 1: Implementación Gradual
powershell
# Fase 1: Validaciones básicas
.\script.ps1 -CsvPath "fase1.csv" -Phase 0 -DryRun

# Fase 2: Validaciones avanzadas  
.\script.ps1 -CsvPath "fase2.csv" -Phase 1 -DryRun

# Fase 3: Producción completa
.\script.ps1 -CsvPath "produccion.csv" -Phase 2
Escenario 2: Emergencias de Seguridad
powershell
# Asignación rápida con controles básicos
.\script.ps1 -CsvPath "emergencia.csv" -Phase 0 -Force

# Auditoría inmediata de lo ejecutado
Get-Content "PIM_Logs/PIM_Execution_*.log"
Escenario 3: Operaciones Programadas
powershell
# Para CI/CD o automatización
.\script.ps1 -CsvPath "automation.csv" -Phase 2 -Force

# Reportes para SIEM
$auditData = Get-Content "PIM_Audit_*.json" | ConvertFrom-Json
📈 BENEFICIOS OPERACIONALES
Para Equipos de Seguridad
Control Granular: Lista blanca de roles por Tier

Auditoría Completa: Trazabilidad de cada asignación

Cumplimiento: Validación automática de políticas

Reportes: Evidencia para auditorías externas

Para Administradores
Automatización: Procesamiento por lotes de asignaciones

Consistencia: Mismo proceso para todos los roles

Eficiencia: Reducción de tiempo en gestiones manuales

Seguridad: Prevención de errores humanos

Para la Organización
Reducción de Riesgo: Eliminación de roles permanentes

Principio de Menor Privilegio: Asignaciones temporales

Transparencia: Reportes ejecutivos de actividad

Escalabilidad: Gestión de grandes volúmenes de asignaciones

🔮 EXTENSIONES FUTURAS
El script está diseñado para ser extendido con:

Integración con sistemas de ticketing (ServiceNow, Jira)

Notificaciones via email/Teams para aprobaciones

Dashboard web para monitoreo

APIs REST para integración con otras plataformas

Soporte para roles de Azure Resources (subscriptions, resource groups)

✅ RESUMEN EJECUTIVO
El script representa una solución enterprise completa para la gestión segura de identidades privilegiadas, combinando controles de seguridad estrictos, auditoría exhaustiva y automatización robusta, todo ello mientras mantiene flexibilidad operativa y cumplimiento normativo.

Estado: ✅ PRODUCTION-READY
