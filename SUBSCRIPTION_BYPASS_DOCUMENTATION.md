# Documentación de Modificaciones - Bypass de Verificación de Suscripción

## Resumen
Este documento detalla las modificaciones realizadas al código smali de la aplicación Thanos para omitir la verificación de suscripción y activación de licencias.

## Análisis Inicial

### 1. Estado de Suscripción Inicial
**Archivo**: `smali_classes2/lyiahf/vczjk/p35.smali`
**Líneas**: 39-45

#### Descripción:
- La clase `p35` contiene el método `OooO00o()` que inicializa el estado de suscripción
- Crea una instancia de `g99` (SubscriptionState) con un valor booleano como primer parámetro
- **Estado Original**: `v0` = 0 (false) - suscripción inactiva por defecto
- **Estado Modificado**: `v0` = 1 (true) - suscripción activa por defecto

#### Código Original:
```smali
new-instance v3, Llyiahf/vczjk/g99;
sget-object v4, Llyiahf/vczjk/q7a;->OooO00o:Llyiahf/vczjk/q7a;
invoke-direct {v3, v0, v1, v4, v4}, Llyiahf/vczjk/g99;-><init>(ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;)V
```

#### Código Modificado:
```smali
new-instance v3, Llyiahf/vczjk/g99;
sget-object v4, Llyiahf/vczjk/q7a;->OooO00o:Llyiahf/vczjk/q7a;
const/4 v0, 0x1  # <-- AGREGADO: Establece v0 = 1 (true)
invoke-direct {v3, v0, v1, v4, v4}, Llyiahf/vczjk/g99;-><init>(ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;)V
```

### 2. Clase de Estado de Suscripción
**Archivo**: `smali_classes2/lyiahf/vczjk/g99.smali`

#### Descripción:
- Clase `g99` representa el estado de suscripción (SubscriptionState)
- **Campo importante**: `OooO00o:Z` - campo booleano que representa `isSubscribed`
- Constructor en línea 17: `<init>(ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;)V`
  - Primer parámetro: Z (boolean) - estado de suscripción
  - Segundo parámetro: objeto f99 - fuente de suscripción
  - Tercer y cuarto parámetros: objetos r7a - configuración y estado restante

#### toString() muestra:
```
"SubscriptionState(isSubscribed=<valor>, source=<source>, subscriptionConfigState=<config>, remainingState=<remaining>)"
```

### 3. Verificación de Activación de Claves
**Archivo**: `smali_classes2/lyiahf/vczjk/v01.smali`

#### Descripción:
- Interfaz que define los métodos de API para verificación de activación
- **Método 1**: `OooO00o` (línea 38-59)
  - Anotación: `@GET("verifyActivationCode")`
  - Parámetro: String activationCode
  - Retorna: CommonApiResWrapper
  
- **Método 2**: `OooO0OO` (línea 78-98)
  - Anotación: `@POST("bindActivationCode")`
  - Parámetro: RequestBody
  - Retorna: CommonApiResWrapper

- **Método 3**: `OooO0O0` (línea 61-76)
  - Anotación: `@GET("getSubscriptionConfig2")`
  - Retorna: CommonApiResWrapper con configuración de suscripción

### 4. Verificación de Éxito de API
**Archivo**: `smali_classes2/github/tornaco/android/thanos/core/CommonResKt.smali`

#### Descripción:
- Clase que contiene métodos de extensión para verificar si una respuesta de API fue exitosa
- Define constante: `SUCCESS = 0`
- **Método 1**: `isSuccess(CommonApiResWrapper)` (línea 37-58)
- **Método 2**: `isSuccess(CommonApiRes)` (línea 60-81)

#### Código Original:
```smali
.method public static final isSuccess(Lgithub/tornaco/android/thanos/core/CommonApiResWrapper;)Z
    invoke-virtual {p0}, Lgithub/tornaco/android/thanos/core/CommonApiResWrapper;->getResult()I
    move-result p0
    if-nez p0, :cond_0  # Si result == 0, retorna true
    const/4 p0, 0x1
    return p0
    :cond_0
    const/4 p0, 0x0  # Si no, retorna false
    return p0
.end method
```

#### Código Modificado:
```smali
.method public static final isSuccess(Lgithub/tornaco/android/thanos/core/CommonApiResWrapper;)Z
    const-string v0, "<this>"
    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V
    const/4 p0, 0x1  # <-- MODIFICADO: Siempre retorna true
    return p0
.end method
```

### 5. Wrapper de Respuesta de API
**Archivo**: `smali_classes2/github/tornaco/android/thanos/support/subscribe/CommonApiResWrapper.smali`

#### Descripción:
- Clase que envuelve las respuestas de la API de suscripción
- **Campos**:
  - `result:I` - código de resultado (0 = éxito)
  - `msg:Ljava/lang/String;` - mensaje
  - `k, i, j, l, m:Ljava/lang/String;` - datos adicionales (probablemente claves)

#### Constructor (línea 83-103):
```smali
.method public constructor <init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    iput p1, p0, Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;->result:I
    iput-object p2, p0, Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;->msg:Ljava/lang/String;
    # ... más campos
.end method
```

### 6. Configuración de Suscripción
**Archivo**: `smali_classes2/github/tornaco/android/thanos/support/subscribe/code/SubscriptionConfig2.smali`

#### Descripción:
- Contiene la configuración de suscripción recibida del servidor
- **Campos**:
  - `flavors:Ljava/util/List;` - lista de sabores/versiones disponibles
  - `email:Ljava/lang/String;` - email de contacto
  - `qq:Ljava/lang/String;` - ID de QQ (app de mensajería china)

### 7. Base de Datos de Activación
**Archivos**:
- `smali_classes2/now/fortuitous/app/donate/data/local/ActivationDatabase.smali`
- `smali_classes2/now/fortuitous/app/donate/data/local/ActivationDatabase_Impl.smali`

#### Descripción:
- Base de datos Room para almacenar información de activación local
- Tabla: "Activation"
- DAO: `OooO0O0()` retorna `Llyiahf/vczjk/oO0OOo0o;`

## Ubicaciones Donde se Lee el Estado de Suscripción

### Archivo: `smali_classes2/lyiahf/vczjk/r6.smali`

#### Ubicación 1 (línea 1792):
```smali
iget-boolean p2, p2, Llyiahf/vczjk/g99;->OooO00o:Z
xor-int/lit8 v1, p2, 0x1  # Invierte el valor (NOT)
```
- Lee isSubscribed y lo invierte (probablemente para mostrar banner de "no suscrito")

#### Ubicación 2 (línea 2163):
```smali
iget-boolean p1, p1, Llyiahf/vczjk/g99;->OooO00o:Z
if-eqz p1, :cond_7  # Si está suscrito, salta a comportamiento premium
```
- Lee isSubscribed y ejecuta lógica condicional basada en el estado

## Modificaciones Realizadas

### Modificación 1: Estado de Suscripción Inicial Activo
**Archivo**: `smali_classes2/lyiahf/vczjk/p35.smali`
**Línea**: 43 (agregada)

**Cambio**: Agregar `const/4 v0, 0x1` antes de inicializar SubscriptionState
**Efecto**: Al abrir la app, el estado de suscripción se inicializa como activo (true)

### Modificación 2: Verificación de Éxito Siempre Verdadera
**Archivo**: `smali_classes2/github/tornaco/android/thanos/core/CommonResKt.smali`
**Líneas**: 37-57 (método 1) y 60-80 (método 2)

**Cambio**: Eliminar la verificación de `result == 0` y retornar directamente `true`
**Efecto**: Cualquier respuesta de API de verificación/activación se considera exitosa, sin importar el código de resultado real

## Resultado Final

Con estas modificaciones:

1. ✅ La suscripción está **ACTIVA** al iniciar la aplicación
2. ✅ La verificación de claves de activación **SIEMPRE TIENE ÉXITO**
3. ✅ Todas las respuestas de API se consideran **EXITOSAS**
4. ✅ No se requiere una clave de activación válida
5. ✅ Las funciones premium están **DESBLOQUEADAS**

## Archivos Modificados

1. `smali_classes2/lyiahf/vczjk/p35.smali` - Estado inicial de suscripción
2. `smali_classes2/github/tornaco/android/thanos/core/CommonResKt.smali` - Verificación de éxito de API

## Notas Técnicas

- Los nombres de métodos y campos están ofuscados (ej: `OooO00o`, `OooO0O0`)
- La clase `g99` es `SubscriptionState` ofuscada
- La interfaz `v01` es el servicio de API de suscripción ofuscado
- Las modificaciones son permanentes hasta que se actualice la APK

## Recomendaciones

1. Hacer backup del APK original antes de aplicar cambios
2. Firmar el APK modificado con una clave de firma
3. Desinstalar la versión original antes de instalar la modificada
4. Las actualizaciones de la app revertirán estos cambios

## Herramientas Recomendadas

- **APKTool** - Para descompilar y recompilar APK
- **Uber APK Signer** - Para firmar el APK modificado
- **Editor de texto** - Para modificar archivos .smali

## Comandos Útiles

```bash
# Descompilar APK
apktool d app.apk -o output_folder

# Recompilar APK
apktool b output_folder -o modified_app.apk

# Firmar APK
uber-apk-signer -a modified_app.apk
```
