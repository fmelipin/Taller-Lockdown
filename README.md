# UAC Bypass - LockDown 2025

Herramienta  de bypass UAC para Windows con capacidades de evasión EDR/AV y ejecución de comandos elevados.

## Características:

- **Bypass UAC Silencioso**: Utiliza técnica cmstp.exe para evadir User Account Control
- **Ofuscación Avanzada**: Comandos ofuscados para evadir detección estática
- **Ejecución como SYSTEM**: Capacidad de ejecutar comandos con privilegios SYSTEM
- **PowerShell Reverse Shell**: Reverse shell integrada y ofuscada
- **Limpieza Automática**: Eliminación de artefactos post-ejecución
- **Compatibilidad Multi-Windows**: Probado en Microsoft Windows 11 Pro 10.0.26100 N/D Compilación 26100

## Instalación:

```powershell

# Descargar y ejecutar
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tu-usuario/UAC-Bypass/main/UAC-Bypass-Final.ps1" -OutFile "UAC-Bypass.ps1"
.\UAC-Bypass.ps1
```

### Cómo usar:

``` powershell
# Ejecutar directamente
.\Bypass_UAC.ps1

Opciones del Menú:
PowerShell Elevado        - Abre PowerShell con privilegios de administrador
Ejecutar Comando          - Ejecuta comandos arbitrarios con elevación
Ejecutar como SYSTEM      - Ejecuta comandos con privilegios SYSTEM
PowerShell Reverse Shell  - Establece conexión reverse shell
Verificar Privilegios     - Verifica privilegios actuales
Limpieza                  - Limpia artefactos temporales
Salir                     - Sale del programa

Ejemplos de Uso:
# Ejecutar comando específico
Ejecutar comando: whoami /priv

# Reverse Shell
IP: 192.168.1.100
Puerto: 4444

# Comando como SYSTEM
Ejecutar comando como SYSTEM: net user hacker Password123! /add
```

## Advertencias:

1. Este proyecto tiene fines exclusivamente educativos y de investigación en seguridad ofensiva.  
2. NO está diseñado ni debe utilizarse como herramienta de intrusión en sistemas de terceros.

