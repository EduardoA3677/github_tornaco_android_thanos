# Guía: Obtener Información Exacta del Dispositivo
## Para Generar Licencias Personalizadas - Thanos Android

---

## 📋 Información Requerida

Para generar una licencia vinculada a tu dispositivo específico, necesitas:

1. **UUID** - Identificador único del dispositivo
2. **Device ID (ANDROID_ID)** - ID de Android
3. **Modelo del dispositivo** - Build.MODEL
4. **Build ID** - Build.ID
5. **API Level** - Build.VERSION.SDK_INT

---

## 🔍 Método 1: Usar Aplicación de Información del Dispositivo

### Opción A: AIDA64

```
1. Instalar AIDA64 desde Play Store
2. Abrir AIDA64
3. Ir a "Sistema" → "Android"
4. Copiar los siguientes datos:
   
   • Android ID: xxxxxxxxxxxxxxxx (16 caracteres hex)
   • Modelo: SM-G950F (ejemplo)
   • ID de compilación: QP1A.190711.020
   • Nivel de API: 29
```

### Opción B: Device Info HW

```
1. Instalar "Device Info HW" desde Play Store
2. Abrir la aplicación
3. Ir a pestaña "Device"
4. Copiar:
   
   • Android ID: xxxxxxxxxxxxxxxx
   • Model: Tu modelo
   • Build ID: ID de compilación
   • SDK Version: Número API
```

---

## 🛠️ Método 2: ADB (Android Debug Bridge)

### Requisitos

- ADB instalado en tu PC
- USB Debugging habilitado en Android
- Cable USB

### Pasos

```bash
# 1. Conectar dispositivo por USB
adb devices

# 2. Obtener Android ID (Device ID)
adb shell settings get secure android_id
# Output: 9774d56d682e549c (ejemplo)

# 3. Obtener Modelo
adb shell getprop ro.product.model
# Output: SM-G950F

# 4. Obtener Build ID
adb shell getprop ro.build.id
# Output: QP1A.190711.020

# 5. Obtener API Level
adb shell getprop ro.build.version.sdk
# Output: 29

# 6. Obtener información completa
adb shell getprop | grep -E "model|build.id|sdk"
```

### Script Automático (ADB)

Crear archivo `get_device_info.sh`:

```bash
#!/bin/bash

echo "======================================"
echo "  INFORMACIÓN DEL DISPOSITIVO"
echo "======================================"
echo ""

echo "Android ID (Device ID):"
ANDROID_ID=$(adb shell settings get secure android_id | tr -d '\r')
echo "  $ANDROID_ID"
echo ""

echo "Modelo:"
MODEL=$(adb shell getprop ro.product.model | tr -d '\r')
echo "  $MODEL"
echo ""

echo "Build ID:"
BUILD_ID=$(adb shell getprop ro.build.id | tr -d '\r')
echo "  $BUILD_ID"
echo ""

echo "API Level:"
SDK=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
echo "  $SDK"
echo ""

echo "Versión de Android:"
VERSION=$(adb shell getprop ro.build.version.release | tr -d '\r')
echo "  Android $VERSION"
echo ""

echo "======================================"
echo "Resumen para el generador:"
echo "======================================"
echo "Device ID:   $ANDROID_ID"
echo "Modelo:      $MODEL"
echo "Build ID:    $BUILD_ID"
echo "API Level:   $SDK"
```

Ejecutar:

```bash
chmod +x get_device_info.sh
./get_device_info.sh
```

---

## 📱 Método 3: Aplicación Android Personalizada

### Crear App Simple

Crear `MainActivity.java`:

```java
package com.example.deviceinfo;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.TextView;

public class MainActivity extends Activity {
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        TextView textView = findViewById(R.id.textView);
        
        // Obtener información
        String androidId = Settings.Secure.getString(
            getContentResolver(), 
            Settings.Secure.ANDROID_ID
        );
        
        String info = "INFORMACIÓN DEL DISPOSITIVO\n\n" +
                      "Device ID: " + androidId + "\n" +
                      "Modelo: " + Build.MODEL + "\n" +
                      "Build ID: " + Build.ID + "\n" +
                      "API Level: " + Build.VERSION.SDK_INT + "\n" +
                      "Android: " + Build.VERSION.RELEASE + "\n" +
                      "Manufacturer: " + Build.MANUFACTURER;
        
        textView.setText(info);
    }
}
```

---

## 🔍 Método 4: Desde el Código Smali Analizado

### Ubicación en el APK

Según el análisis del código:

**Archivo:** `smali_classes2/lyiahf/vczjk/v47.smali`

```smali
# Obtiene ANDROID_ID
const-string v1, "android_id"
invoke-static {v0, v1}, Landroid/provider/Settings$Secure;->getString(
    Landroid/content/ContentResolver;
    Ljava/lang/String;
)Ljava/lang/String;
```

**Archivo:** `smali_classes2/github/tornaco/android/thanos/support/subscribe/code/DeviceCodeBinding.smali`

```smali
# Constructor recibe:
# p1: uuid (String)
# p2: deviceId (String) 
# p3: deviceModel (String) - Build.MODEL
# p4: osName (String) - Build.ID
# p5: osVersion (int) - Build.VERSION.SDK_INT

# Valores por defecto si no se proveen:
sget-object p3, Landroid/os/Build;->MODEL:Ljava/lang/String;
sget-object p4, Landroid/os/Build;->ID:Ljava/lang/String;
sget p5, Landroid/os/Build$VERSION;->SDK_INT:I
```

### Clase Java Equivalente

```java
public class DeviceCodeBinding {
    private final String uuid;
    private final String deviceId;
    private final String deviceModel;  // Build.MODEL
    private final String osName;       // Build.ID
    private final int osVersion;       // Build.VERSION.SDK_INT
    
    public DeviceCodeBinding(
        String uuid,
        String deviceId,
        String deviceModel,  // Default: Build.MODEL
        String osName,       // Default: Build.ID  
        int osVersion        // Default: Build.VERSION.SDK_INT
    ) {
        this.uuid = uuid;
        this.deviceId = deviceId;
        this.deviceModel = deviceModel != null ? deviceModel : Build.MODEL;
        this.osName = osName != null ? osName : Build.ID;
        this.osVersion = osVersion != 0 ? osVersion : Build.VERSION.SDK_INT;
    }
}
```

---

## 🔐 Método 5: Hook con Frida (Avanzado)

### Script Frida para Capturar Datos

Crear `capture_device_info.js`:

```javascript
Java.perform(function() {
    console.log("[*] Hook iniciado - Capturando información del dispositivo\n");
    
    // Hook Settings.Secure.getString para capturar ANDROID_ID
    var Settings_Secure = Java.use("android.provider.Settings$Secure");
    Settings_Secure.getString.overload(
        'android.content.ContentResolver', 
        'java.lang.String'
    ).implementation = function(resolver, name) {
        var result = this.getString(resolver, name);
        
        if (name === "android_id") {
            console.log("[+] ANDROID_ID capturado: " + result);
        }
        
        return result;
    };
    
    // Hook Build para capturar modelo y versión
    var Build = Java.use("android.os.Build");
    console.log("[+] Modelo: " + Build.MODEL.value);
    console.log("[+] Build ID: " + Build.ID.value);
    console.log("[+] Manufacturer: " + Build.MANUFACTURER.value);
    
    var Build_VERSION = Java.use("android.os.Build$VERSION");
    console.log("[+] API Level: " + Build_VERSION.SDK_INT.value);
    console.log("[+] Android Version: " + Build_VERSION.RELEASE.value);
    
    // Hook DeviceCodeBinding constructor
    try {
        var DeviceCodeBinding = Java.use(
            "github.tornaco.android.thanos.support.subscribe.code.DeviceCodeBinding"
        );
        
        DeviceCodeBinding.$init.overload(
            'java.lang.String',
            'java.lang.String', 
            'java.lang.String',
            'java.lang.String',
            'int'
        ).implementation = function(uuid, deviceId, model, osName, osVersion) {
            console.log("\n[*] DeviceCodeBinding creado:");
            console.log("    UUID:       " + uuid);
            console.log("    Device ID:  " + deviceId);
            console.log("    Model:      " + model);
            console.log("    OS Name:    " + osName);
            console.log("    OS Version: " + osVersion);
            
            return this.$init(uuid, deviceId, model, osName, osVersion);
        };
    } catch(e) {
        console.log("[-] No se pudo hook DeviceCodeBinding: " + e);
    }
    
    console.log("\n[*] Hooks establecidos. Esperando actividad...\n");
});
```

### Ejecutar Frida

```bash
# Instalar Frida
pip3 install frida-tools

# Ejecutar hook
frida -U -f com.tornaco.android.thanos -l capture_device_info.js --no-pause

# O si la app ya está ejecutándose
frida -U com.tornaco.android.thanos -l capture_device_info.js
```

---

## 📊 Tabla de Referencia Rápida

| Campo | Fuente Android | Ejemplo |
|-------|---------------|---------|
| **UUID** | Generado (UUID.randomUUID()) | `550e8400-e29b-41d4-a716-446655440000` |
| **Device ID** | Settings.Secure.ANDROID_ID | `9774d56d682e549c` |
| **Modelo** | Build.MODEL | `SM-G950F` |
| **Build ID** | Build.ID | `QP1A.190711.020` |
| **API Level** | Build.VERSION.SDK_INT | `29` |
| **Android Version** | Build.VERSION.RELEASE | `10` |

---

## 🎯 Usar los Datos con el Generador Interactivo

### Paso a Paso

```bash
# 1. Obtener datos de tu dispositivo (cualquier método anterior)
Device ID:   9774d56d682e549c
Modelo:      SM-G950F
Build ID:    QP1A.190711.020
API Level:   29

# 2. Ejecutar generador interactivo
python3 interactive_license_generator.py

# 3. Cuando se solicite, ingresar tus datos exactos:
UUID del dispositivo: [Generar aleatorio o usar específico]
Device ID: 9774d56d682e549c
Modelo: SM-G950F
Build ID: QP1A.190711.020
API Level: 29

# 4. Seleccionar tipo de suscripción y algoritmo

# 5. El script generará:
#    - Código de activación personalizado
#    - Server key específica
#    - Archivo JSON con toda la información
```

---

## ⚠️ Notas Importantes

### UUID vs Device ID

- **UUID**: Generado localmente por la app, puede ser cualquier UUID válido
- **Device ID (ANDROID_ID)**: Único por dispositivo y app, NO cambia en reinstalaciones

### Cambios en Reinstalación

| Dato | ¿Cambia en reinstall? |
|------|----------------------|
| UUID | ✅ SÍ (se genera nuevo) |
| Device ID | ❌ NO (permanece igual) |
| Modelo | ❌ NO |
| Build ID | ❌ NO |
| API Level | ❌ NO |

### Para Testing

Si solo quieres probar el generador, usa datos de ejemplo:

```
Device ID:   9774d56d682e549c
Modelo:      SM-G950F  
Build ID:    QP1A.190711.020
API Level:   29
```

### Para Producción

Usa los datos REALES de tu dispositivo para que la licencia funcione correctamente.

---

## 🔧 Script Completo de Extracción (Python)

### get_device_info.py

```python
#!/usr/bin/env python3
"""
Script para obtener información del dispositivo via ADB
"""

import subprocess
import sys

def run_adb(command):
    """Ejecuta comando ADB y retorna output"""
    try:
        result = subprocess.run(
            f"adb shell {command}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {e}"

def main():
    print("=" * 60)
    print("  EXTRACTOR DE INFORMACIÓN DEL DISPOSITIVO")
    print("=" * 60)
    print()
    
    # Verificar conexión ADB
    print("[*] Verificando conexión ADB...")
    devices = run_adb("echo OK")
    if "OK" not in devices:
        print("❌ Error: No se detectó dispositivo Android")
        print("   Asegúrate de:")
        print("   1. Tener ADB instalado")
        print("   2. USB Debugging habilitado")
        print("   3. Dispositivo conectado por USB")
        sys.exit(1)
    
    print("✓ Dispositivo conectado\n")
    
    # Obtener información
    print("[*] Obteniendo información...\n")
    
    android_id = run_adb("settings get secure android_id")
    model = run_adb("getprop ro.product.model")
    build_id = run_adb("getprop ro.build.id")
    sdk = run_adb("getprop ro.build.version.sdk")
    android_version = run_adb("getprop ro.build.version.release")
    manufacturer = run_adb("getprop ro.product.manufacturer")
    
    # Mostrar resultados
    print("=" * 60)
    print("  INFORMACIÓN DEL DISPOSITIVO")
    print("=" * 60)
    print()
    print(f"Device ID (ANDROID_ID): {android_id}")
    print(f"Fabricante:             {manufacturer}")
    print(f"Modelo:                 {model}")
    print(f"Build ID:               {build_id}")
    print(f"API Level:              {sdk}")
    print(f"Android Version:        {android_version}")
    print()
    print("=" * 60)
    print("  PARA EL GENERADOR INTERACTIVO")
    print("=" * 60)
    print()
    print("Copia estos valores:")
    print(f"  Device ID:   {android_id}")
    print(f"  Modelo:      {model}")
    print(f"  Build ID:    {build_id}")
    print(f"  API Level:   {sdk}")
    print()

if __name__ == "__main__":
    main()
```

**Uso:**

```bash
python3 get_device_info.py
```

---

## 📞 Soporte

Si tienes problemas obteniendo la información:

1. **Revisa logs de ADB:** `adb logcat | grep -i device`
2. **Consulta documentación:** `GUIA_COMPLETA_USO.md`
3. **Usa valores de ejemplo** para testing inicial

---

**Última actualización:** Diciembre 2025  
**Compatibilidad:** Android 5.0+ (API 21+)
