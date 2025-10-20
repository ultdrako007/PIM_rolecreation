🚀 INICIO RÁPIDO
Requisitos Previos
powershell
# Instalar módulo requerido
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser -Force
Ejecución Básica
powershell
# Modo simulación (recomendado para pruebas)
.\PIM-PolicyConfiguration.ps1 -CsvPath "politicas.csv" -DryRun

# Modo producción con confirmación
.\PIM-PolicyConfiguration.ps1 -CsvPath "politicas.csv"

# Modo producción automático
.\PIM-PolicyConfiguration.ps1 -CsvPath "politicas.csv" -Force

# Con ruta personalizada de logs
.\PIM-PolicyConfiguration.ps1 -CsvPath "politicas.csv" -LogPath "C:\Logs\PIM"
📊 ESTRUCTURA DEL CSV
Columnas Requeridas
csv
RoleDisplayName,ActivationMaxDuration,RequireMfaOnActivation,RequireApproval,RequireJustificationOnActivation,RequireTicketInfoOnActivation
Ejemplo de Archivo CSV
csv
RoleDisplayName,ActivationMaxDuration,RequireMfaOnActivation,RequireApproval,RequireJustificationOnActivation,RequireTicketInfoOnActivation
Global Administrator,PT8H,true,true,true,true
User Administrator,P1D,true,false,true,true
Helpdesk Administrator,P7D,true,false,true,false
Directory Readers,P30D,false,false,true,false
Formatos Aceptados
Campo	Tipo	Valores	Descripción
RoleDisplayName	String	Nombre exacto del rol	Debe coincidir con el nombre en Entra ID
ActivationMaxDuration	ISO-8601	PT8H, P1D, P7D	Duración máxima de activación
RequireMfaOnActivation	Boolean	true/false	Requerir MFA para activación
RequireApproval	Boolean	true/false	Requerir aprobación para activación
RequireJustificationOnActivation	Boolean	true/false	Requerir justificación
RequireTicketInfoOnActivation	Boolean	true/false	Requerir información de ticket
🔐 CONTROLES DE SEGURIDAD IMPLEMENTADOS
1. Lista Blanca de Roles Configurables
powershell
# Solo estos roles pueden ser configurados
$script:ConfigurableRoles = @(
    'Global Administrator',
    'Privileged Role Administrator',
    'Security Administrator',
    # ... otros roles autorizados
)
2. Validación de Cambios No Autorizados
Protege contra:

❌ Desactivar MFA en roles críticos

❌ Desactivar aprobación en roles críticos

❌ Aumentar duración beyond 24 horas en roles críticos

Roles críticos protegidos:

Global Administrator

Privileged Role Administrator

Security Administrator

3. Manejo de Throttling
Reintentos exponenciales automáticos (2s → 4s → 8s)

Continuación graceful después de errores

Logging detallado de intentos

4. Modo Dry-Run
powershell
# Simula todos los cambios sin aplicar
.\PIM-PolicyConfiguration.ps1 -CsvPath "politicas.csv" -DryRun

# Muestra exactamente qué cambiaría
[DRY-RUN] Simulando actualización...
  Duración: PT8H → PT4H
  MFA: True → True
  Aprobación: True → False
📋 SISTEMA DE AUDITORÍA
Reportes Generados
text
PIM-Policy-Logs/
├── PIM-Policy-Audit_20231201_143022.csv
├── PIM-Policy-Audit_20231201_143022.json
Estructura del Reporte CSV
csv
Timestamp,RoleDisplayName,Action,Status,Details,ExecutedBy,DryRun
2023-12-01T14:30:22.123Z,Global Administrator,PolicyUpdated,Success,Configuración aplicada,admin@tenant.com,False
2023-12-01T14:30:23.456Z,User Administrator,UnauthorizedChanges,Blocked,Desactivar MFA en rol crítico,admin@tenant.com,False
Estadísticas de Ejecución
text
=== RESUMEN DE EJECUCIÓN ===
Total procesado:  8
Exitoso:          6
Fallido:          1
Omitido:          0
Cambios no autorizados: 1
⚙️ PARÁMETROS DEL SCRIPT
Parámetro	Obligatorio	Descripción
CsvPath	✅ Sí	Ruta al archivo CSV con configuración
DryRun	❌ No	Modo simulación sin cambios reales
Force	❌ No	Omite confirmaciones interactivas
LogPath	❌ No	Ruta personalizada para logs (default: .\PIM-Policy-Logs)
🛠️ ESCENARIOS DE USO
Escenario 1: Implementación Segura
powershell
# 1. Validar configuración
.\PIM-PolicyConfiguration.ps1 -CsvPath "nueva_politica.csv" -DryRun

# 2. Revisar reporte de auditoría
Get-Content ".\PIM-Policy-Logs\PIM-Policy-Audit_*.json" | ConvertFrom-Json

# 3. Aplicar cambios
.\PIM-PolicyConfiguration.ps1 -CsvPath "nueva_politica.csv" -Force
Escenario 2: Auditoría de Cambios
powershell
# Generar línea base actual
.\PIM-PolicyConfiguration.ps1 -CsvPath "config_actual.csv" -DryRun

# Comparar con nueva configuración
.\PIM-PolicyConfiguration.ps1 -CsvPath "config_nueva.csv" -DryRun
Escenario 3: CI/CD Pipeline
powershell
# En pipelines automatizados
.\PIM-PolicyConfiguration.ps1 -CsvPath "$(ConfigPath)" -Force -LogPath "$(Build.ArtifactStagingDirectory)"
🔍 RESOLUCIÓN DE PROBLEMAS
Errores Comunes
Error	Causa	Solución
ROL NO CONFIGURABLE	Rol no en lista blanca	Agregar rol a $ConfigurableRoles
BLOQUEADO: Cambios no autorizados	Intento de reducir seguridad	Revisar política para roles críticos
Throttling detectado	Límites de Graph API	Script reintenta automáticamente
Rol no encontrado	Nombre incorrecto	Verificar nombre exacto en Entra ID
Códigos de Estado en Auditoría
Status	Significado	Acción
Success	Cambio aplicado exitosamente	Ninguna
Failed	Error en la operación	Revisar detalles del error
Blocked	Cambio bloqueado por seguridad	Revisar políticas de roles críticos
Skipped	Rol omitido (no configurable)	Agregar a lista blanca si es necesario
📞 MONITOREO Y MANTENIMIENTO
Archivos de Log Generados
CSV: Para análisis en Excel/Power BI

JSON: Para integración con SIEM/Sistemas de monitoring

Estadísticas: Resumen ejecutivo de la ejecución

Recomendaciones de Seguridad
Siempre usar DryRun primero para validar cambios

Revisar cambios no autorizados en el reporte

Monitorear logs después de cada ejecución

Mantener actualizada la lista de roles críticos

✅ MEJORAS IMPLEMENTADAS
Seguridad
✅ Lista blanca de roles configurables

✅ Validación de cambios no autorizados

✅ Protección de roles críticos

✅ Confirmaciones interactivas

Robustez
✅ Manejo de throttling con reintentos

✅ Modo Dry-Run para pruebas

✅ Manejo graceful de errores

✅ Validación completa de entradas

Auditoría
✅ Reportes CSV y JSON

✅ Estados antes/después

✅ Estadísticas de ejecución

✅ Trazabilidad completa
