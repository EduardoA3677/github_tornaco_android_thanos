#!/usr/bin/env python3
"""
Extractor de Información del Dispositivo - Versión Termux
==========================================================

Obtiene la información del dispositivo Android directamente desde Termux
usando comandos locales y root (su) cuando está disponible.

Requisitos:
- Termux instalado en Android
- (Opcional) Root access para información adicional

Uso:
    python get_device_info_termux.py
    python get_device_info_termux.py --json
    python get_device_info_termux.py --use-adb  # Forzar modo ADB

Modos de operación:
1. Termux local (default) - Usa comandos locales y su -c si hay root
2. ADB mode - Usa adb shell (cuando --use-adb es especificado)
"""

import subprocess
import sys
import json
import os
from datetime import datetime


class DeviceInfoExtractorTermux:
    """Extrae información del dispositivo - Compatible con Termux y ADB"""
    
    def __init__(self, use_adb=False):
        self.device_info = {}
        self.use_adb = use_adb
        self.has_root = False
        
        if not use_adb:
            self.has_root = self.check_root_access()
    
    def check_root_access(self):
        """Verifica si hay acceso root"""
        try:
            result = subprocess.run(
                ["su", "-c", "echo OK"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return "OK" in result.stdout
        except:
            return False
    
    def run_command(self, command, need_root=False):
        """
        Ejecuta comando según el modo (Termux local o ADB)
        
        Args:
            command: Comando a ejecutar (sin 'su -c' ni 'adb shell')
            need_root: Si requiere root en modo Termux
        """
        try:
            if self.use_adb:
                # Modo ADB
                cmd = ["adb", "shell"] + command.split()
            else:
                # Modo Termux local
                if need_root and self.has_root:
                    cmd = ["su", "-c", command]
                else:
                    cmd = command.split()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip().replace('\r', '')
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except FileNotFoundError as e:
            if self.use_adb:
                return "ADB_NOT_FOUND"
            return f"COMMAND_NOT_FOUND: {e}"
        except Exception as e:
            return f"ERROR: {e}"
    
    def get_android_id(self):
        """Obtiene ANDROID_ID usando diferentes métodos"""
        # Método 1: settings (funciona sin root)
        result = self.run_command("settings get secure android_id")
        if result and "ERROR" not in result and "null" not in result:
            return result
        
        # Método 2: content (alternativo)
        result = self.run_command("content query --uri content://settings/secure --where \"name='android_id'\"")
        if "value=" in result:
            # Parse: Row: 0 _id=X, name=android_id, value=XXXXX
            for part in result.split(","):
                if "value=" in part:
                    return part.split("=")[1].strip()
        
        # Método 3: getprop (puede no funcionar en todos los dispositivos)
        result = self.run_command("getprop ro.serialno")
        if result and "ERROR" not in result:
            return result
        
        return "UNAVAILABLE"
    
    def extract_info(self):
        """Extrae toda la información del dispositivo"""
        print("[*] Extrayendo información del dispositivo...")
        
        if not self.use_adb:
            print(f"[*] Modo: Termux Local (Root: {'✓' if self.has_root else '✗'})")
        else:
            print("[*] Modo: ADB Shell")
        
        # Android ID (Device ID)
        print("[*] Obteniendo Android ID...")
        self.device_info['android_id'] = self.get_android_id()
        
        # Información del dispositivo (getprop)
        print("[*] Obteniendo propiedades del sistema...")
        self.device_info['manufacturer'] = self.run_command("getprop ro.product.manufacturer")
        self.device_info['model'] = self.run_command("getprop ro.product.model")
        self.device_info['brand'] = self.run_command("getprop ro.product.brand")
        self.device_info['device'] = self.run_command("getprop ro.product.device")
        
        # Build information
        self.device_info['build_id'] = self.run_command("getprop ro.build.id")
        self.device_info['build_display'] = self.run_command("getprop ro.build.display.id")
        self.device_info['build_fingerprint'] = self.run_command("getprop ro.build.fingerprint")
        
        # Android version
        self.device_info['sdk_int'] = self.run_command("getprop ro.build.version.sdk")
        self.device_info['android_version'] = self.run_command("getprop ro.build.version.release")
        self.device_info['security_patch'] = self.run_command("getprop ro.build.version.security_patch")
        
        # Hardware
        self.device_info['board'] = self.run_command("getprop ro.product.board")
        self.device_info['hardware'] = self.run_command("getprop ro.hardware")
        
        # Serial number
        self.device_info['serial'] = self.run_command("getprop ro.serialno")
        
        # Información adicional de Termux
        if not self.use_adb:
            self.device_info['termux_version'] = self.run_command("termux-info")
            
            # Arquitectura
            self.device_info['arch'] = self.run_command("uname -m")
            
            # Hostname
            self.device_info['hostname'] = self.run_command("hostname")
        
        return self.device_info
    
    def display_results(self):
        """Muestra resultados formateados"""
        print("\n" + "=" * 70)
        print("  INFORMACIÓN DEL DISPOSITIVO ANDROID")
        if not self.use_adb:
            print("  Extraído desde: TERMUX LOCAL")
            print(f"  Root access: {'✓ Disponible' if self.has_root else '✗ No disponible'}")
        else:
            print("  Extraído desde: ADB SHELL")
        print("=" * 70)
        
        print("\n📱 IDENTIFICACIÓN:")
        print(f"   Android ID:     {self.device_info.get('android_id', 'N/A')}")
        print(f"   Fabricante:     {self.device_info.get('manufacturer', 'N/A')}")
        print(f"   Marca:          {self.device_info.get('brand', 'N/A')}")
        print(f"   Modelo:         {self.device_info.get('model', 'N/A')}")
        print(f"   Device:         {self.device_info.get('device', 'N/A')}")
        
        print("\n🏗️  BUILD INFORMATION:")
        print(f"   Build ID:       {self.device_info.get('build_id', 'N/A')}")
        print(f"   Build Display:  {self.device_info.get('build_display', 'N/A')}")
        
        print("\n🤖 ANDROID VERSION:")
        print(f"   API Level:      {self.device_info.get('sdk_int', 'N/A')}")
        print(f"   Android:        {self.device_info.get('android_version', 'N/A')}")
        print(f"   Security Patch: {self.device_info.get('security_patch', 'N/A')}")
        
        print("\n⚙️  HARDWARE:")
        print(f"   Board:          {self.device_info.get('board', 'N/A')}")
        print(f"   Hardware:       {self.device_info.get('hardware', 'N/A')}")
        
        if not self.use_adb:
            print("\n🖥️  TERMUX INFO:")
            print(f"   Arquitectura:   {self.device_info.get('arch', 'N/A')}")
            print(f"   Hostname:       {self.device_info.get('hostname', 'N/A')}")
        
        print("\n" + "=" * 70)
        print("  PARA EL GENERADOR INTERACTIVO DE LICENCIAS")
        print("=" * 70)
        print("\nCopia estos valores al ejecutar:")
        print("  python interactive_license_generator.py\n")
        
        android_id = self.device_info.get('android_id', 'N/A')
        if android_id == 'UNAVAILABLE':
            print("  ⚠️  ANDROID_ID no disponible. Usando alternativas:")
            print(f"  Device ID:   {self.device_info.get('serial', 'GENERATE_RANDOM')}")
        else:
            print(f"  Device ID:   {android_id}")
        
        print(f"  Modelo:      {self.device_info.get('model', 'N/A')}")
        print(f"  Build ID:    {self.device_info.get('build_id', 'N/A')}")
        print(f"  API Level:   {self.device_info.get('sdk_int', 'N/A')}")
        print()
    
    def export_json(self, filename=None):
        """Exporta información a JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"device_info_{timestamp}.json"
        
        # Añadir metadata
        export_data = {
            "extracted_at": datetime.now().isoformat(),
            "extraction_method": "termux_local" if not self.use_adb else "adb_shell",
            "root_access": self.has_root if not self.use_adb else None,
            "device_info": self.device_info,
            "for_license_generator": {
                "device_id": self.device_info.get('android_id', self.device_info.get('serial', '')),
                "device_model": self.device_info.get('model', ''),
                "os_name": self.device_info.get('build_id', ''),
                "os_version": int(self.device_info.get('sdk_int', 0)) if self.device_info.get('sdk_int', '0').isdigit() else 0
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Información exportada a: {filename}")
        return filename


def print_help():
    """Muestra ayuda del script"""
    print("""
Uso: python get_device_info_termux.py [opciones]

Opciones:
  --help, -h       Muestra esta ayuda
  --json           Exporta resultado a JSON
  --use-adb        Usa ADB en lugar de comandos locales de Termux
  
Modos de operación:
  1. Termux Local (default):
     - Ejecuta comandos directamente en el dispositivo
     - Usa 'su -c' para comandos que requieren root
     - No requiere PC ni cable USB
     
  2. ADB Mode (--use-adb):
     - Usa 'adb shell' desde PC
     - Requiere USB debugging habilitado
     - Compatible con script original

Ejemplos:
  # Desde Termux en el dispositivo
  python get_device_info_termux.py
  
  # Exportar a JSON
  python get_device_info_termux.py --json
  
  # Usar ADB desde PC
  python get_device_info_termux.py --use-adb
  
Requisitos Termux:
  pkg install python
  pkg install termux-api (opcional, para funciones adicionales)
  
Para root:
  - Dispositivo rooteado
  - Magisk o SuperSU instalado
  - Otorgar permisos root a Termux
""")


def main():
    """Función principal"""
    # Verificar argumentos
    if '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(0)
    
    output_json = '--json' in sys.argv
    use_adb = '--use-adb' in sys.argv
    
    print("\n" + "=" * 70)
    print("  EXTRACTOR DE INFORMACIÓN DEL DISPOSITIVO")
    if not use_adb:
        print("  Modo: TERMUX LOCAL")
        print("  Compatible con Android sin PC")
    else:
        print("  Modo: ADB SHELL")
        print("  Requiere PC y USB debugging")
    print("=" * 70)
    print()
    
    # Crear extractor
    extractor = DeviceInfoExtractorTermux(use_adb=use_adb)
    
    # Si es modo ADB, verificar conexión
    if use_adb:
        print("[*] Verificando conexión ADB...")
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if "device" not in result.stdout:
                print("\n❌ ERROR: No se detectó dispositivo Android via ADB\n")
                print("Asegúrate de:")
                print("  1. Tener ADB instalado")
                print("  2. USB Debugging habilitado")
                print("  3. Dispositivo conectado por USB")
                print("\nO usa modo Termux local sin --use-adb")
                sys.exit(1)
            print("✓ Dispositivo Android detectado via ADB\n")
        except FileNotFoundError:
            print("\n❌ ERROR: ADB no encontrado\n")
            print("Instala ADB o usa modo Termux local sin --use-adb")
            sys.exit(1)
    
    # Extraer información
    try:
        extractor.extract_info()
        
        # Mostrar resultados
        extractor.display_results()
        
        # Exportar a JSON si se solicitó
        if output_json:
            extractor.export_json()
        
        # Sugerencias
        print("\n💡 PRÓXIMOS PASOS:")
        if not use_adb:
            print("   1. Copia los valores mostrados arriba")
            print("   2. Ejecuta: python interactive_license_generator.py")
            print("   3. Ingresa los valores cuando se soliciten")
            print("\n   💡 TIP: Si Android ID no está disponible, el generador")
            print("            puede crear uno aleatorio o usar el serial number")
        else:
            print("   Ejecuta: python interactive_license_generator.py")
            print("   E ingresa los valores mostrados arriba")
        print()
        
    except KeyboardInterrupt:
        print("\n\n❌ Extracción cancelada por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error durante extracción: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
