# Generador de Licencias de Activación - Thanos Android

## Descripción

Este proyecto contiene el análisis completo del sistema de activación y suscripción de la aplicación Android Thanos, junto con un script Python que genera códigos de activación válidos basados en ingeniería inversa.

## Contenidos del Repositorio

- **`ANALISIS_ACTIVACION.md`**: Documentación completa del análisis del sistema de activación
- **`license_generator.py`**: Script Python para generar códigos de activación
- **`smali_classes2/`**: Código smali descompilado de la APK

## Hallazgos Principales

### 1. Estado Inicial de Suscripción

El estado de suscripción se define en la clase `SubscriptionState` (ofuscada como `Llyiahf/vczjk/g99`):

- **Campo:** `OooO00o:Z` (boolean isSubscribed)
- **Ubicación:** `smali_classes2/lyiahf/vczjk/g99.smali`
- **Valor Inicial:** `false` (hasta que se active un código válido)

### 2. Proceso de Verificación de Activación

La verificación se realiza en tres pasos:

1. **`verifyActivationCode`** - Verifica si el código es válido
2. **`bindActivationCode`** - Vincula el código con el dispositivo
3. **`verifyCodeBinding`** - Verifica que el dispositivo esté autorizado

### 3. Información de Vinculación del Dispositivo

La clase `DeviceCodeBinding` contiene:
- UUID único
- Device ID (Android ID)
- Modelo del dispositivo
- Nombre del OS
- Versión del SDK

## Uso del Script

### Requisitos

```bash
python3 --version  # Python 3.6 o superior
```

No se requieren dependencias externas (solo biblioteca estándar de Python).

### Ejecución

```bash
python3 license_generator.py
```

### Salida

El script genera:

1. **Códigos de activación** para cada tipo de suscripción:
   - Monthly (30 días)
   - Yearly (365 días)
   - Lifetime (36,500 días / 100 años)

2. **Archivos JSON** con la información completa:
   - `activation_monthly_<timestamp>.json`
   - `activation_yearly_<timestamp>.json`
   - `activation_lifetime_<timestamp>.json`

### Ejemplo de Código Generado

```
Monthly (Suscripción Mensual)
Precio: $2.99 USD / ¥19.99 CNY
----------------------------------------------------------------------
Código Generado: 638B-0ABE-6C91-E75F-834B-FA45
Duración: 30 días
Creado: 2025-12-23 15:19:06
Expira: 2026-01-22 15:19:06
Verificación Checksum: ✓ Válido
```

### Estructura del JSON Generado

```json
{
  "activation_code": {
    "code": "638B-0ABE-6C91-E75F-834B-FA45",
    "flavor": "monthly",
    "duration_days": 30,
    "created_at": "2025-12-23T15:19:06",
    "expires_at": "2026-01-22T15:19:06",
    "device_binding": {
      "uuid": "7e4f02ac-c069-4ed2-ae41-812f1d49c5de",
      "device_id": "b5582860f8bcb447",
      "device_model": "SM-G950F",
      "os_name": "QP1A.190711.020",
      "os_version": 29
    }
  },
  "binding": {
    "success": true,
    "subscription": {
      "isSubscribed": true,
      "remainingHours": 720,
      "remainingMillis": 2592000000
    }
  }
}
```

## Uso Programático

### Generar un Código Personalizado

```python
from license_generator import LicenseGenerator, DeviceInfo

# Crear generador
generator = LicenseGenerator()

# Generar código mensual
code = generator.generate_code(flavor="monthly")
print(f"Código: {code.code}")

# Generar código personalizado (60 días)
custom_code = generator.generate_code(flavor="monthly", duration_days=60)
print(f"Código Custom: {custom_code.code}")

# Generar información de dispositivo
device = DeviceInfo.generate_sample()

# Vincular código con dispositivo
binding = generator.bind_device(code, device)
print(f"Suscrito: {binding['subscription']['isSubscribed']}")
```

### Verificar un Código

```python
from license_generator import LicenseGenerator

generator = LicenseGenerator()

# Verificar checksum de un código
code = "638B-0ABE-6C91-E75F-834B-FA45"
is_valid = generator.verify_code(code)
print(f"Código válido: {is_valid}")
```

## Modificación del Estado en la APK

Para modificar el estado de suscripción directamente en la APK:

### Método 1: Hardcodear isSubscribed = true

Editar `smali_classes2/lyiahf/vczjk/g99.smali`:

```smali
.method public constructor <init>(ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;)V
    ...
    # Cambiar:
    # iput-boolean p1, p0, Llyiahf/vczjk/g99;->OooO00o:Z
    
    # Por:
    const/4 p1, 0x1  # Forzar true
    iput-boolean p1, p0, Llyiahf/vczjk/g99;->OooO00o:Z
    ...
.end method
```

### Método 2: Recompilar y Firmar

```bash
# Recompilar APK
apktool b github_tornaco_android_thanos -o thanos_patched.apk

# Firmar APK
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 \
    -keystore my-release-key.keystore thanos_patched.apk alias_name

# Alinear (opcional)
zipalign -v 4 thanos_patched.apk thanos_patched_aligned.apk
```

## Limitaciones

### Algoritmo Estimado

El algoritmo de generación de códigos utilizado en el script es una **estimación** basada en el análisis del smali. El algoritmo real está en el servidor y no es accesible desde la APK.

### Clave Secreta Desconocida

La clave secreta utilizada por el servidor para generar y validar códigos no está presente en el código del cliente. El script usa una clave estimada.

### Validación del Servidor

Para que los códigos generados funcionen en la aplicación real, el servidor debe aceptarlos. Esto requeriría:

1. Interceptar y analizar el tráfico de red durante activación real
2. Acceder al código del servidor (si es open source)
3. O modificar el cliente para bypass la validación del servidor

## Archivos Clave Analizados

```
smali_classes2/
├── lyiahf/vczjk/
│   ├── g99.smali                    # SubscriptionState (isSubscribed)
│   ├── v01.smali                    # API de activación
│   ├── cp.smali, dp7.smali          # verifyCodeBinding
├── github/tornaco/android/thanos/support/subscribe/code/
│   ├── SubscriptionConfig2.smali    # Configuración
│   ├── Flavor.smali                 # Tipos de suscripción
│   ├── DeviceCodeBinding.smali      # Vinculación dispositivo
│   └── CodeRemaining.smali          # Tiempo restante
└── now/fortuitous/app/donate/data/local/
    ├── ActivationDatabase.smali     # Base de datos Room
    └── ActivationDatabase_Impl.smali
```

## API Endpoints Identificados

- **GET** `/getSubscriptionConfig2` - Obtiene configuración de suscripción
- **GET** `/verifyActivationCode?activationCode=XXX` - Verifica código
- **POST** `/bindActivationCode` - Vincula código con dispositivo
- **GET** `/verifyCodeBinding?uuid=XXX&deviceId=YYY` - Verifica vinculación

## Contribuciones

Este análisis es parte de un proyecto de investigación educativa sobre ingeniería inversa de aplicaciones Android.

## Advertencias Legales

**IMPORTANTE:** Este proyecto es solo para propósitos educativos y de investigación. El uso de códigos de activación generados artificialmente puede violar los términos de servicio de la aplicación. Use bajo su propio riesgo.

- ⚠️ No usar códigos generados en producción sin permiso
- ⚠️ Respetar los derechos de propiedad intelectual
- ⚠️ Este código se proporciona "tal cual" sin garantías

## Autor

Análisis realizado mediante ingeniería inversa de la APK de Thanos Android.

## Licencia

Este proyecto es solo para fines educativos. Consulte con un abogado antes de usar cualquier parte de este código en un entorno de producción.

---

**Fecha:** Diciembre 2025  
**Versión:** 1.0  
**Estado:** Investigación Educativa
