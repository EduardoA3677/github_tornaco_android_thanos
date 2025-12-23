# Análisis del Sistema de Activación y Suscripción
## Thanos Android App

### Resumen Ejecutivo

Este documento detalla el análisis completo del sistema de activación y suscripción de la aplicación Android Thanos, incluyendo la ubicación del estado de suscripción inicial y los mecanismos de verificación de claves de activación.

---

## 1. Estado Inicial de Suscripción

### Ubicación del Estado
**Archivo:** `smali_classes2/lyiahf/vczjk/g99.smali`  
**Clase:** `SubscriptionState` (ofuscada como `Llyiahf/vczjk/g99`)

### Campo de Suscripción
```smali
.field public final OooO00o:Z
```
Este campo booleano representa `isSubscribed`. El estado se inicializa en el constructor:

```smali
.method public constructor <init>(ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;)V
    ...
    iput-boolean p1, p0, Llyiahf/vczjk/g99;->OooO00o:Z
    ...
.end method
```

**Parámetros del Constructor:**
- `p1`: boolean isSubscribed (estado de suscripción)
- `p2`: Llyiahf/vczjk/f99 source (fuente de la suscripción)
- `p3`: Llyiahf/vczjk/r7a subscriptionConfigState
- `p4`: Llyiahf/vczjk/r7a remainingState

### Método toString()
El método `toString()` confirma la estructura:
```smali
const-string v1, "SubscriptionState(isSubscribed="
...
iget-boolean v1, p0, Llyiahf/vczjk/g99;->OooO00o:Z
const-string v1, ", source="
const-string v1, ", subscriptionConfigState="
const-string v1, ", remainingState="
```

---

## 2. Clases de Configuración

### 2.1 SubscriptionConfig2
**Ubicación:** `smali_classes2/github/tornaco/android/thanos/support/subscribe/code/SubscriptionConfig2.smali`

**Campos:**
```smali
.field private final email:Ljava/lang/String;
.field private final flavors:Ljava/util/List; # Lista de Flavor
.field private final qq:Ljava/lang/String;
```

### 2.2 Flavor (Tipos de Suscripción)
**Ubicación:** `smali_classes2/github/tornaco/android/thanos/support/subscribe/code/Flavor.smali`

**Campos:**
```smali
.field private final text:Ljava/lang/String;         # Nombre del flavor
.field private final description:Ljava/lang/String;  # Descripción
.field private final priceUSD:F                      # Precio en USD
.field private final priceCNY:F                      # Precio en CNY
```

### 2.3 DeviceCodeBinding (Vinculación de Dispositivo)
**Ubicación:** `smali_classes2/github/tornaco/android/thanos/support/subscribe/code/DeviceCodeBinding.smali`

**Campos:**
```smali
.field private final uuid:Ljava/lang/String;         # UUID único
.field private final deviceId:Ljava/lang/String;     # ID del dispositivo
.field private final deviceModel:Ljava/lang/String;  # Modelo (Build.MODEL)
.field private final osName:Ljava/lang/String;       # OS Name (Build.ID)
.field private final osVersion:I                     # Versión SDK (Build.VERSION.SDK_INT)
```

### 2.4 CodeRemaining (Tiempo Restante)
**Ubicación:** `smali_classes2/github/tornaco/android/thanos/support/subscribe/code/CodeRemaining.smali`

**Campos:**
```smali
.field private final remainingHours:J    # Horas restantes
.field private final remainingMillis:J   # Milisegundos restantes
```

---

## 3. API de Verificación de Activación

### 3.1 Interface de Activación
**Ubicación:** `smali_classes2/lyiahf/vczjk/v01.smali`

**Métodos HTTP:**

#### a) Verificar Código de Activación
```smali
.method public abstract OooO00o(Ljava/lang/String;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Llyiahf/vczjk/rf7;
            value = "activationCode"
        .end annotation
    .end param
    .annotation runtime Llyiahf/vczjk/gg3;
        value = "verifyActivationCode"
    .end annotation
.end method
```
**Endpoint:** `verifyActivationCode`  
**Parámetro:** `activationCode` (String)  
**Retorno:** `CommonApiResWrapper`

#### b) Vincular Código de Activación
```smali
.method public abstract OooO0OO(Llyiahf/vczjk/cr7;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .param p1    # Llyiahf/vczjk/cr7;
        .annotation runtime Llyiahf/vczjk/zd0;
        .end annotation
    .end param
    .annotation runtime Llyiahf/vczjk/fh6;
        value = "bindActivationCode"
    .end annotation
.end method
```
**Endpoint:** `bindActivationCode` (POST)  
**Body:** Objeto `cr7` (probablemente DeviceCodeBinding)  
**Retorno:** `CommonApiResWrapper`

#### c) Obtener Configuración de Suscripción
```smali
.method public abstract OooO0O0(Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .annotation runtime Llyiahf/vczjk/gg3;
        value = "getSubscriptionConfig2"
    .end annotation
.end method
```
**Endpoint:** `getSubscriptionConfig2` (GET)  
**Retorno:** `CommonApiResWrapper` con `SubscriptionConfig2`

### 3.2 Verificación de Vinculación de Código
**Ubicación:** `smali_classes2/lyiahf/vczjk/cp.smali` y `smali_classes2/lyiahf/vczjk/dp7.smali`

```smali
.method public abstract OooO00o(Ljava/lang/String;Ljava/lang/String;)L...;
    .param p1    # Ljava/lang/String;
        .annotation runtime Llyiahf/vczjk/rf7;
            value = "uuid"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Llyiahf/vczjk/rf7;
            value = "deviceId"
        .end annotation
    .end param
    .annotation runtime Llyiahf/vczjk/gg3;
        value = "verifyCodeBinding"
    .end annotation
.end method
```
**Endpoint:** `verifyCodeBinding`  
**Parámetros:** `uuid`, `deviceId`  
**Retorno:** Estado de vinculación

---

## 4. Base de Datos Local

### ActivationDatabase
**Ubicación:** `smali_classes2/now/fortuitous/app/donate/data/local/ActivationDatabase.smali`

Esta es una base de datos Room (Android) que almacena información de activación localmente.

```smali
.class public abstract Lnow/fortuitous/app/donate/data/local/ActivationDatabase;
.super Llyiahf/vczjk/ru7;  # Extends RoomDatabase

.method public abstract OooO0O0()Llyiahf/vczjk/oO0OOo0o;
.end method
```

---

## 5. Proceso de Activación

### Flujo de Activación:

1. **Usuario ingresa código de activación**
2. **Llamada a API:** `verifyActivationCode(activationCode)`
   - Verifica si el código es válido
   - Retorna información del código si es válido
3. **Vinculación con dispositivo:** `bindActivationCode(DeviceCodeBinding)`
   - Envía información del dispositivo (UUID, deviceId, modelo, OS)
   - El servidor asocia el código con el dispositivo
4. **Verificación de vinculación:** `verifyCodeBinding(uuid, deviceId)`
   - Verifica que el dispositivo esté autorizado para usar el código
5. **Actualización de estado local:**
   - `isSubscribed` se actualiza a `true`
   - Se guarda en `ActivationDatabase`
   - Se actualizan `CodeRemaining` (tiempo restante)

### Diagrama de Flujo:
```
Usuario Ingresa Código
    |
    v
verifyActivationCode(code)
    |
    ├── Válido -> Obtener DeviceCodeBinding
    |             |
    |             v
    |        bindActivationCode(binding)
    |             |
    |             v
    |        verifyCodeBinding(uuid, deviceId)
    |             |
    |             v
    |        Actualizar isSubscribed = true
    |        Guardar en ActivationDatabase
    |
    └── Inválido -> Mostrar error
```

---

## 6. Modificación del Estado Inicial

### Opción 1: Modificar Constructor (Hardcode)
Para establecer siempre `isSubscribed = true`:

**Archivo:** `smali_classes2/lyiahf/vczjk/g99.smali`

Modificar el constructor para forzar `true`:
```smali
.method public constructor <init>(ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;)V
    ...
    # Cambiar de:
    # iput-boolean p1, p0, Llyiahf/vczjk/g99;->OooO00o:Z
    
    # A:
    const/4 p1, 0x1  # Forzar true
    iput-boolean p1, p0, Llyiahf/vczjk/g99;->OooO00o:Z
    ...
.end method
```

### Opción 2: Modificar Verificación de Base de Datos
**Archivo:** `smali_classes2/now/fortuitous/app/donate/data/local/ActivationDatabase_Impl.smali`

Modificar las consultas para siempre retornar estado activo.

### Opción 3: Bypass de Verificación API
Modificar las implementaciones de los métodos API para retornar respuestas exitosas sin hacer llamadas reales.

---

## 7. Generación de Códigos de Activación

### Información Necesaria:

Para generar códigos válidos, se necesita conocer:

1. **Algoritmo de generación** (no encontrado en el análisis del smali)
2. **Clave secreta/salt** (probablemente en servidor)
3. **Formato del código** (patrón)

### Posibles Enfoques:

#### A) Análisis de Códigos Existentes
Si se tienen códigos válidos, analizar el patrón:
- Longitud del código
- Caracteres permitidos
- Estructura (guiones, secciones, checksums)

#### B) Ingeniería Inversa del Servidor
El algoritmo real de generación probablemente está en el servidor, no en la APK.

#### C) Base de Datos Local
La base de datos `ActivationDatabase` podría ser modificada directamente para insertar códigos "válidos" localmente.

---

## 8. Próximos Pasos para Script Python

Para crear un script que genere licencias, se necesita:

### 8.1 Análisis Adicional Requerido:
- [ ] Descompilar y analizar el servidor (si es accesible)
- [ ] Interceptar tráfico de red durante activación real
- [ ] Analizar códigos de activación existentes (si disponibles)
- [ ] Buscar algoritmos de hash/encriptación en el smali
- [ ] Identificar formato exacto de DeviceCodeBinding

### 8.2 Información del Dispositivo:
El script debe generar o capturar:
```python
class DeviceInfo:
    uuid: str          # UUID único del dispositivo
    device_id: str     # Android ID
    device_model: str  # Build.MODEL
    os_name: str       # Build.ID
    os_version: int    # Build.VERSION.SDK_INT
```

### 8.3 Estructura del Código de Activación:
```python
class ActivationCode:
    code: str              # El código en sí
    flavor: str            # Tipo de suscripción
    remaining_hours: int   # Horas de validez
    expiry_date: datetime  # Fecha de expiración
```

---

## 9. Recomendaciones

### Para Bypass Local (Sin Generar Códigos):
1. **Modificar smali directamente:**
   - Cambiar `isSubscribed` a siempre retornar `true`
   - Modificar `CodeRemaining` para retornar tiempo infinito
   
2. **Modificar Base de Datos:**
   - Insertar entrada válida en `ActivationDatabase`
   - Bypass de verificaciones de tiempo

### Para Generación de Códigos Válidos:
1. **Análisis de Red Necesario:**
   - Capturar requests/responses durante activación real
   - Identificar formato exacto de API
   - Analizar estructura de respuestas exitosas

2. **Análisis de Servidor:**
   - Si el servidor es de código abierto o accesible
   - Revisar lógica de generación/validación

---

## 10. Conclusiones

1. **Estado de Suscripción:**
   - Definido en `Llyiahf/vczjk/g99;->OooO00o:Z`
   - Inicializado en constructor con valor del parámetro `p1`
   - Por defecto es `false` hasta activación exitosa

2. **Verificación de Activación:**
   - Proceso en 3 pasos: verificar código → vincular dispositivo → verificar vinculación
   - APIs: `verifyActivationCode`, `bindActivationCode`, `verifyCodeBinding`
   - Almacenamiento local en `ActivationDatabase`

3. **Información de Dispositivo:**
   - Vinculación basada en UUID + deviceId
   - Incluye modelo, OS, y versión SDK
   - Estructura definida en `DeviceCodeBinding`

4. **Generación de Códigos:**
   - **Algoritmo no presente en APK** (probablemente servidor)
   - Requiere análisis adicional de tráfico de red o servidor
   - Alternativa: modificación directa del estado local

---

## Archivos Clave del Análisis

```
smali_classes2/
├── lyiahf/vczjk/
│   ├── g99.smali                    # SubscriptionState (isSubscribed)
│   ├── v01.smali                    # API de activación
│   ├── cp.smali, dp7.smali          # verifyCodeBinding
│   └── cm4.smali                    # (referenciado)
├── github/tornaco/android/thanos/support/subscribe/
│   └── code/
│       ├── SubscriptionConfig2.smali  # Configuración
│       ├── Flavor.smali               # Tipos de suscripción
│       ├── DeviceCodeBinding.smali    # Vinculación dispositivo
│       └── CodeRemaining.smali        # Tiempo restante
└── now/fortuitous/app/donate/data/local/
    ├── ActivationDatabase.smali       # Base de datos Room
    └── ActivationDatabase_Impl.smali  # Implementación
```

---

**Fecha de Análisis:** Diciembre 2025  
**Versión APK:** (Basado en archivos smali descompilados)  
**Herramientas Utilizadas:** apktool, análisis manual de smali
