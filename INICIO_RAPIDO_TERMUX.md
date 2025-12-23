# 🚀 Inicio Rápido - Termux

## Para Usuarios de Termux (Android)

### ✅ Instalación en 2 Pasos

```bash
# 1. Instalar Python
pkg install python git

# 2. Clonar repositorio (opcional) o copiar archivos
# Los scripts están listos para usar
```

### 🎯 Uso Más Rápido (Recomendado)

```bash
# Generador interactivo con auto-extracción
python interactive_license_generator.py
```

**El script detectará automáticamente:**
- ✅ Si estás en Termux
- ✅ Si tienes root
- ✅ Qué comandos puede ejecutar

**Te preguntará:**
```
🤖 Detectado: Termux en Android
   Root access: ✓ Disponible

💡 Puedo obtener la información automáticamente usando root.
   ¿Deseas extracción automática? (s/n) [s]:
```

**Responde "s" y listo!** Todos los valores se extraen automáticamente.

---

## 📱 Con Root (Recomendado)

### Requisitos
- Dispositivo rooteado (Magisk/SuperSU)
- Otorgar permisos root a Termux

### Comandos

```bash
# Método 1: Todo en uno
python interactive_license_generator.py
# Responder "s" cuando pregunte por extracción automática

# Método 2: Primero extraer info, luego generar
python get_device_info.py
python interactive_license_generator.py
# Copiar valores manualmente
```

### ¿Qué obtiene con root?
- ✅ Android ID (Device ID)
- ✅ Modelo del dispositivo
- ✅ Build ID
- ✅ API Level
- ✅ Fabricante
- ✅ Toda la información necesaria

---

## 📱 Sin Root

### Limitaciones
- ⚠️ Puede no obtener Android ID
- ⚠️ Algunos valores pueden no estar disponibles

### Comandos

```bash
python interactive_license_generator.py
# Cuando pregunte por extracción automática:
#   - Si dice "Root: ✗ No disponible"
#   - Responder "s" para intentar obtener lo que pueda
#   - O responder "n" para entrada manual completa
```

### Fallback
Si no puede obtener Android ID:
- El script genera uno aleatorio
- Puedes ingresar valores manualmente
- Puedes usar el serial number como alternativa

---

## 📊 Comandos Disponibles

| Comando | Descripción | Requiere Root |
|---------|-------------|---------------|
| `python interactive_license_generator.py` | **RECOMENDADO** - Generador con auto-extracción | No* |
| `python get_device_info.py` | Solo extrae información del dispositivo | No* |
| `python get_device_info_termux.py` | Versión especializada Termux | No* |
| `python advanced_license_generator.py` | Generación automática (sin config) | No |
| `python license_generator.py` | Generación rápida básica | No |

\* *Con root obtiene más información*

---

## 🎬 Ejemplo Completo

### Paso a Paso

```bash
# 1. Abrir Termux
termux

# 2. Navegar a la carpeta del proyecto
cd /path/to/github_tornaco_android_thanos

# 3. Ejecutar generador
python interactive_license_generator.py

# 4. Seguir instrucciones en pantalla
# Ejemplo de sesión:
```

```
======================================================================
   GENERADOR INTERACTIVO DE LICENCIAS - THANOS ANDROID
======================================================================

📱 INFORMACIÓN DEL DISPOSITIVO
----------------------------------------------------------------------

🤖 Detectado: Termux en Android
   Root access: ✓ Disponible

💡 Puedo obtener la información automáticamente usando root.
   ¿Deseas extracción automática? (s/n) [s]: s

🔍 EXTRAYENDO INFORMACIÓN AUTOMÁTICAMENTE...
----------------------------------------------------------------------
[*] Obteniendo Android ID...
[*] Obteniendo modelo del dispositivo...
[*] Obteniendo Build ID...
[*] Obteniendo API Level...

✓ Extracción completada

📋 INFORMACIÓN OBTENIDA:
----------------------------------------------------------------------
   Device ID:   9774d56d682e549c
   Modelo:      SM-G950F
   Build ID:    QP1A.190711.020
   API Level:   29
   Info:        samsung - samsung
   UUID:        d4c8e7f2-... (generado)

✓ Usando valores extraídos automáticamente

¿Deseas modificar algún valor? (s/n) [n]: n

🎫 TIPO DE SUSCRIPCIÓN
----------------------------------------------------------------------
   1. Mensual (30 días) - $2.99
   2. Anual (365 días) - $24.99
   3. Permanente (100 años) - $49.99

Selecciona opción [1]: 3

✓ Seleccionado: Permanente (100 años)

🔐 ALGORITMO DE HASH
----------------------------------------------------------------------
   1. SHA-256 (Recomendado)
   2. SHA-1
   3. MD5
   4. Keccak/SHA3-256

Selecciona algoritmo [1]: 1

✓ Algoritmo: SHA256

⚙️  OPCIONES AVANZADAS
----------------------------------------------------------------------
   ¿Usar salt/clave personalizada? (s/n) [n]: n

✓ Usando salt por defecto

✅ CÓDIGO GENERADO EXITOSAMENTE
======================================================================

📋 CÓDIGO DE ACTIVACIÓN:
   ABCD-1234-EFGH-5678-IJKL-9012

🔑 SERVER KEY (Campo 'k' de la API):
   abc123def456...

💾 GUARDADO EN ARCHIVO:
   /data/data/com.termux/files/home/license_lifetime_1234567890_custom.json
```

---

## ⚠️ Solución de Problemas

### Error: "Root access: ✗ No disponible"

**Causa:** Termux no tiene permisos root

**Solución:**
1. Asegurar que el dispositivo esté rooteado
2. Abrir Magisk Manager
3. Otorgar permisos root a Termux
4. Reiniciar Termux

**Alternativa:** Usar sin root (capacidades limitadas)

### Error: "Android ID no disponible"

**Causa:** Sin root, algunos dispositivos no exponen Android ID

**Soluciones:**
1. Usar root (recomendado)
2. Ingresar manualmente el Android ID
3. Usar el script para obtenerlo de otra app
4. Usar valores aleatorios (para testing)

### Permiso denegado al ejecutar `su`

**Causa:** No se otorgaron permisos en el prompt

**Solución:**
```bash
# Ejecutar manualmente
su -c "echo OK"
# Aceptar el prompt de permisos
# Reintentar el script
```

---

## 📚 Documentación Completa

Para más información, consulta:

- **`GUIA_COMPLETA_USO.md`** - Guía maestra completa
- **`GUIA_OBTENER_DEVICE_INFO.md`** - 5 métodos para obtener info
- **`RESUMEN_EJECUTIVO.md`** - Resumen del proyecto

---

## 💡 Tips y Trucos

### Tip 1: Guardar Info del Dispositivo

```bash
# Extraer y guardar en JSON
python get_device_info.py --json

# Resultado: device_info_20231223_153045.json
# Reutilizar valores en futuras ejecuciones
```

### Tip 2: Generar Múltiples Licencias

```bash
# Ejecutar varias veces el generador
for i in {1..5}; do
  python advanced_license_generator.py
done
```

### Tip 3: Verificar Permisos Root

```bash
# Probar manualmente
su -c "settings get secure android_id"

# Si funciona, el script también funcionará
```

---

## 🎉 ¡Listo!

El generador está optimizado para Termux y funciona perfectamente en Android.

**Disfruta generando licencias directamente desde tu dispositivo!** 📱✨

---

**Última actualización:** Diciembre 2025  
**Compatibilidad:** Termux, Android 5.0+  
**Root:** Recomendado pero no requerido
