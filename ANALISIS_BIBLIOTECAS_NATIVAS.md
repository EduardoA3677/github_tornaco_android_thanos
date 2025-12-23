# Análisis de Bibliotecas Nativas (.so)
## Sistema de Verificación de Activación - Thanos Android

---

## Resumen Ejecutivo

Se ha identificado que el algoritmo de verificación de códigos de activación está implementado en código nativo (C/C++) en la biblioteca `libtn.so`, no en Java/smali. Esto es una técnica común de ofuscación y protección de lógica crítica.

---

## 1. Bibliotecas Nativas Encontradas

### Ubicación
```
lib/
├── arm64-v8a/      # Android ARM 64-bit
├── armeabi-v7a/    # Android ARM 32-bit
├── x86/            # Android x86 32-bit
└── x86_64/         # Android x86 64-bit
```

### Archivos .so por Arquitectura

| Biblioteca | Tamaño | Descripción |
|-----------|---------|-------------|
| **libtn.so** | 823KB | **Biblioteca principal de Thanos** ⭐ |
| libmmkv.so | 574KB | Almacenamiento key-value (Tencent MMKV) |
| libxcrash.so | 75KB | Captura de crashes |
| libxcrash_dumper.so | 111KB | Dumper de crashes |
| libandroidx.graphics.path.so | 9.9KB | Gráficos AndroidX |
| libdatastore_shared_counter.so | 7KB | Contador compartido |

---

## 2. Análisis de libtn.so

### 2.1 Información Básica

```bash
$ file lib/arm64-v8a/libtn.so
ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV)
dynamically linked, stripped
BuildID: 869de9f8b8d3dbbe55ad36a7f31f88450e776c4b
```

**Características:**
- **Stripped**: Símbolos de depuración eliminados (ofuscación)
- **Dynamically linked**: Enlazado dinámico
- **64-bit ARM**: Compilado para ARM64

### 2.2 Función JNI Exportada

**Símbolo encontrado:**
```c
Java_tornaco_android_sec_net_S_c
```

**Firma en C:**
```c
void Java_tornaco_android_sec_net_S_c(
    JNIEnv* env,
    jclass clazz,
    jstring activationCode,
    jstring serverKey
)
```

**Wrapper Java:**
```java
package tornaco.android.sec.net;

public abstract class S {
    static {
        System.loadLibrary("tn");
    }
    
    public static native void c(String activationCode, String serverKey);
}
```

### 2.3 Algoritmos Criptográficos Detectados

La biblioteca contiene implementaciones de múltiples algoritmos de hash:

#### Funciones Identificadas

```cpp
// MD5
MD5::MD5()
MD5::operator()(const std::string&)
MD5::add(const void*, size_t)
MD5::getHash()
MD5::processBlock(const void*)

// SHA-1
SHA1::SHA1()
SHA1::operator()(const std::string&)
SHA1::add(const void*, size_t)
SHA1::getHash()
SHA1::processBlock(const void*)

// SHA-256
SHA256::SHA256()
SHA256::operator()(const std::string&)
SHA256::add(const void*, size_t)
SHA256::getHash()

// SHA-3 / Keccak
SHA3::SHA3(Bits)
SHA3::add(const void*, size_t)
SHA3::getHash()
Keccak::getHash()

// CRC32
CRC32::getHash()
CRC32::getHash(unsigned char*)
```

**Conclusión:** La biblioteca tiene capacidad para verificar códigos usando cualquiera de estos algoritmos.

---

## 3. Proceso de Verificación Descubierto

### 3.1 Flujo Completo

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Usuario ingresa código de activación                        │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 v
┌─────────────────────────────────────────────────────────────────┐
│ 2. App llama API REST                                           │
│    GET http://thanox.emui.tech/api/verifyActivationCode        │
│    Parámetro: activationCode=XXXX-XXXX-XXXX-XXXX               │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 v
┌─────────────────────────────────────────────────────────────────┐
│ 3. Servidor responde con CommonApiResWrapper                    │
│    {                                                             │
│      "result": 0,  // 0 = éxito                                │
│      "k": "SECRET_KEY_FROM_SERVER",  // ⭐ Clave secreta       │
│      "msg": "{...CodeRemaining...}"                             │
│    }                                                             │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 v
┌─────────────────────────────────────────────────────────────────┐
│ 4. Verificación Local (Native)                                  │
│    S.c(activationCode, serverKey)                               │
│    ↓                                                             │
│    Java_tornaco_android_sec_net_S_c()                          │
│    ↓                                                             │
│    Algoritmo nativo en libtn.so:                                │
│    - Calcula hash del código                                    │
│    - Compara con serverKey                                      │
│    - Si no coincide: crash o exit                               │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 v
┌─────────────────────────────────────────────────────────────────┐
│ 5. Si verificación exitosa:                                     │
│    - Guarda CodeRemaining en caché                              │
│    - Actualiza isSubscribed = true                              │
│    - Guarda en ActivationDatabase                               │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Código Smali de Verificación

**Archivo:** `smali_classes2/lyiahf/vczjk/tq7.smali`

**Método:** `OooO00o(String activationCode, Continuation)`

```smali
# Obtener respuesta del servidor
invoke-virtual {p2}, Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;->getResult()I
move-result v0

# Si result == 0 (éxito)
if-nez v0, :cond_4

# Obtener clave secreta del servidor
invoke-virtual {p2}, Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;->getK()Ljava/lang/String;
move-result-object v0

# ⭐ LLAMADA A VERIFICACIÓN NATIVA
invoke-static {p1, v0}, Ltornaco/android/sec/net/S;->c(Ljava/lang/String;Ljava/lang/String;)V

# Si llega aquí, verificación exitosa
# Parsear CodeRemaining del msg
invoke-virtual {p2}, Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;->getMsg()Ljava/lang/String;
move-result-object p2
const-class v0, Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;
invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/nk3;->OooO0O0(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

# Guardar en caché estática
sput-object p2, Llyiahf/vczjk/uq7;->OooO0O0:Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;
```

### 3.3 Endpoint del Servidor

**Base URL:** `http://thanox.emui.tech/api/`

**Endpoints:**
```
GET  /verifyActivationCode?activationCode={code}
POST /bindActivationCode (body: DeviceCodeBinding)
GET  /verifyCodeBinding?uuid={uuid}&deviceId={deviceId}
GET  /getSubscriptionConfig2
```

---

## 4. Algoritmo de Verificación Estimado

### Hipótesis Basada en el Análisis

Dado que la función nativa recibe:
1. `activationCode` (del usuario)
2. `serverKey` (clave secreta del servidor)

El algoritmo probablemente es:

```cpp
void Java_tornaco_android_sec_net_S_c(
    JNIEnv* env,
    jclass clazz,
    jstring jActivationCode,
    jstring jServerKey
) {
    const char* activationCode = env->GetStringUTFChars(jActivationCode, 0);
    const char* serverKey = env->GetStringUTFChars(jServerKey, 0);
    
    // Algoritmo posible:
    // 1. Calcular hash del código
    std::string codeHash = SHA256(activationCode);
    
    // 2. Comparar con clave del servidor
    if (codeHash != serverKey) {
        // Verificación fallida - terminar proceso
        exit(1);  // o throw exception
    }
    
    // Si llega aquí, código válido
    env->ReleaseStringUTFChars(jActivationCode, activationCode);
    env->ReleaseStringUTFChars(jServerKey, serverKey);
}
```

**Otra posibilidad (HMAC):**
```cpp
std::string computedHMAC = HMAC_SHA256(activationCode, SECRET_SALT);
if (computedHMAC != serverKey) {
    exit(1);
}
```

---

## 5. Extracción del Algoritmo Real

### Métodos para Ingeniería Inversa Completa

#### 5.1 Análisis Estático (Recomendado)

**Herramientas:**
```bash
# Instalar Ghidra (descompilador)
wget https://github.com/NationalSecurityAgency/ghidra/releases/...
unzip ghidra_*.zip

# Analizar libtn.so
./ghidraRun
# File → Import File → libtn.so
# Analysis → Auto Analyze
# Buscar: Java_tornaco_android_sec_net_S_c
```

**IDA Pro (Comercial):**
- Mejor descompilador para ARM
- Soporte para JNI Bridge
- Puede generar pseudocódigo C

**Radare2 (Gratuito):**
```bash
r2 lib/arm64-v8a/libtn.so
aaa  # Analizar todo
afl | grep Java  # Listar funciones
pdf @ sym.Java_tornaco_android_sec_net_S_c  # Desensamblar
```

#### 5.2 Análisis Dinámico

**Frida (Hook en runtime):**
```javascript
// frida_hook.js
Java.perform(function() {
    var S = Java.use("tornaco.android.sec.net.S");
    
    S.c.implementation = function(code, key) {
        console.log("[*] S.c() called");
        console.log("    Code: " + code);
        console.log("    Key:  " + key);
        
        // Llamar función original
        this.c(code, key);
        
        console.log("[*] Verification passed!");
    };
});
```

**Ejecutar:**
```bash
frida -U -f com.tornaco.android.thanos -l frida_hook.js
```

**Xposed Hook:**
```java
findAndHookMethod(
    "tornaco.android.sec.net.S",
    lpparam.classLoader,
    "c",
    String.class,
    String.class,
    new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            String code = (String) param.args[0];
            String key = (String) param.args[1];
            XposedBridge.log("Code: " + code);
            XposedBridge.log("Key: " + key);
        }
    }
);
```

#### 5.3 Análisis de Red (Interceptar Tráfico)

**mitmproxy:**
```bash
# Instalar certificado en Android
mitmproxy --mode transparent

# En Android, configurar proxy a PC
# Interceptar requests a thanox.emui.tech
```

**Burp Suite:**
- Configurar proxy SSL
- Capturar request/response
- Analizar campo `k` (serverKey)

---

## 6. Bypass de Verificación Nativa

### Método 1: Parchar libtn.so

**Objetivo:** Hacer que `S.c()` siempre retorne éxito

```bash
# Descompilar con Ghidra
# Encontrar verificación
# Cambiar condicional para siempre pasar
# Recompilar y reemplazar
```

**Ejemplo de patch ARM64:**
```assembly
; Original (si hash != serverKey, exit)
CMP     X0, X1
B.NE    fail_exit

; Parchear a (siempre continuar)
CMP     X0, X1
B.EQ    continue  ; o NOP
```

### Método 2: Hook con Frida (Sin Modificar APK)

```javascript
Interceptor.attach(
    Module.findExportByName("libtn.so", "Java_tornaco_android_sec_net_S_c"),
    {
        onEnter: function(args) {
            console.log("[*] Native verification called");
            console.log("    Code: " + Memory.readUtf8String(args[2]));
            console.log("    Key:  " + Memory.readUtf8String(args[3]));
        },
        onLeave: function(retval) {
            console.log("[*] Verification result: " + retval);
            // Forzar éxito
            retval.replace(0);
        }
    }
);
```

### Método 3: Reemplazar Método Java

**En smali, cambiar `S.smali`:**
```smali
# Original:
.method public static native c(Ljava/lang/String;Ljava/lang/String;)V
.end method

# Cambiar a:
.method public static c(Ljava/lang/String;Ljava/lang/String;)V
    .locals 0
    
    # No hacer nada, siempre éxito
    return-void
.end method
```

### Método 4: Bypass del Servidor

**Si se puede modificar el servidor o usar servidor propio:**

```python
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/api/verifyActivationCode')
def verify():
    code = request.args.get('activationCode')
    
    # Siempre retornar éxito
    return jsonify({
        "result": 0,
        "k": "ANY_VALUE",  # No importa si bypass S.c()
        "msg": {
            "remainingHours": 876000,
            "remainingMillis": 876000 * 3600 * 1000
        }
    })
```

---

## 7. Generación de Códigos Válidos (Actualizado)

### Conocimiento Necesario

Para generar códigos que pasen la verificación nativa, necesitamos:

1. **Algoritmo exacto** usado en `libtn.so`
2. **Clave secreta** o **salt** para el hash
3. **Formato preciso** del código

### Estrategias de Ingeniería Inversa

#### A) Capturar Código Válido Real

```bash
# Comprar código legítimo
# Capturar con mitmproxy
# Ver campo "k" en respuesta

# Ejemplo de respuesta:
{
  "result": 0,
  "k": "A1B2C3D4E5F6...",  # ⭐ Este es el hash del código
  "msg": "{...}"
}

# Analizar relación entre código y k
```

#### B) Ingeniería Inversa de libtn.so

```bash
# Con Ghidra:
# 1. Abrir libtn.so
# 2. Encontrar Java_tornaco_android_sec_net_S_c
# 3. Descompilar a pseudocódigo C
# 4. Identificar:
#    - Función de hash usada
#    - Transformaciones del código
#    - Salt o clave hardcodeada
```

#### C) Análisis de Múltiples Códigos

```python
# Si se tienen varios códigos válidos:
codes = [
    ("AAAA-BBBB-CCCC-DDDD", "hash1"),
    ("EEEE-FFFF-GGGG-HHHH", "hash2"),
    ...
]

# Buscar patrón
for code, hash_value in codes:
    # Probar diferentes algoritmos
    if md5(code) == hash_value:
        print("Algorithm: MD5")
    elif sha256(code) == hash_value:
        print("Algorithm: SHA256")
    # etc...
```

---

## 8. Script Python Actualizado

### Generador con Soporte para Verificación Nativa

```python
import hashlib
import hmac

class AdvancedLicenseGenerator:
    """
    Generador mejorado con soporte para verificación nativa.
    NOTA: Requiere conocer el algoritmo exacto de libtn.so
    """
    
    # Algoritmo estimado (ajustar según ingeniería inversa)
    HASH_ALGORITHM = "sha256"  # o md5, sha1, etc.
    SECRET_SALT = b"UNKNOWN"   # Extraer de libtn.so
    
    def compute_server_key(self, activation_code: str) -> str:
        """
        Calcula la clave K que el servidor debe retornar.
        Este es el valor que libtn.so verificará.
        """
        if self.HASH_ALGORITHM == "sha256":
            h = hashlib.sha256()
        elif self.HASH_ALGORITHM == "md5":
            h = hashlib.md5()
        elif self.HASH_ALGORITHM == "sha1":
            h = hashlib.sha1()
        else:
            raise ValueError(f"Unknown algorithm: {self.HASH_ALGORITHM}")
        
        # Opción 1: Hash simple
        h.update(activation_code.encode())
        
        # Opción 2: HMAC (si usa salt)
        # h = hmac.new(self.SECRET_SALT, activation_code.encode(), hashlib.sha256)
        
        return h.hexdigest().upper()
    
    def generate_valid_pair(self):
        """
        Genera par (código, serverKey) que pasará verificación nativa.
        """
        code = self.generate_code()
        server_key = self.compute_server_key(code.code)
        
        return {
            "activationCode": code.code,
            "serverKey": server_key,
            "api_response": {
                "result": 0,
                "k": server_key,
                "msg": code.to_dict()
            }
        }
```

---

## 9. Recomendaciones Finales

### Para Investigación Educativa

1. **Prioridad Alta:**
   - Descompilar `libtn.so` con Ghidra
   - Identificar algoritmo exacto en `Java_tornaco_android_sec_net_S_c`
   - Extraer constantes/salts hardcodeadas

2. **Prioridad Media:**
   - Hook con Frida para capturar códigos reales
   - Analizar tráfico de red con mitmproxy
   - Recopilar múltiples pares (código, serverKey)

3. **Prioridad Baja:**
   - Parche de libtn.so para bypass
   - Implementar servidor mock
   - Modificar smali para skip verificación

### Para Uso Práctico (Bypass)

**Más Fácil → Más Difícil:**

1. ✅ **Hook con Frida** (sin modificar APK)
2. ✅ **Modificar smali** (eliminar llamada a S.c)
3. ⚠️  **Parchar libtn.so** (requiere conocimiento ARM)
4. ❌ **Servidor propio** (requiere infraestructura)

---

## 10. Archivos de Referencia

```
Bibliotecas Nativas:
├── lib/arm64-v8a/libtn.so       ← ⭐ Verificación nativa
├── lib/armeabi-v7a/libtn.so
├── lib/x86/libtn.so
└── lib/x86_64/libtn.so

Código Java/Smali:
├── smali_classes2/tornaco/android/sec/net/S.smali  ← Wrapper JNI
├── smali_classes2/lyiahf/vczjk/tq7.smali           ← Lógica de verificación
└── smali_classes2/lyiahf/vczjk/uq7.smali           ← Caché de códigos

APIs Identificadas:
└── http://thanox.emui.tech/api/
    ├── verifyActivationCode
    ├── bindActivationCode
    ├── verifyCodeBinding
    └── getSubscriptionConfig2
```

---

**Fecha:** Diciembre 2025  
**Estado:** Análisis Completo de Bibliotecas Nativas  
**Próximo Paso:** Descompilación de `libtn.so` con Ghidra
