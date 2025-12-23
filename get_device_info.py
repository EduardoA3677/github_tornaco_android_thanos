#!/usr/bin/env python3
"""
Extractor Automático de Información del Dispositivo
===================================================

Auto-detecta si está en Termux o PC y usa el método apropiado:
- En Termux: Usa comandos locales y 'su -c' si hay root
- En PC: Usa 'adb shell'

Requisitos Termux:
- Python instalado (pkg install python)
- (Opcional) Root access para más información

Requisitos PC:
- ADB instalado y en PATH
- USB Debugging habilitado
- Dispositivo conectado

Uso:
    python3 get_device_info.py
    python3 get_device_info.py --json       # Salida en JSON
    python3 get_device_info.py --force-adb  # Forzar modo ADB
"""

import subprocess
import sys
import json
import os
from datetime import datetime


class DeviceInfoExtractor:
    """Extrae información del dispositivo - Auto-detecta Termux o ADB"""
    
    def __init__(self, force_adb=False):
        self.device_info = {}
        self.is_termux = self._detect_termux() and not force_adb
        self.has_root = False
        
        if self.is_termux:
            self.has_root = self._check_root_access()
    
    def _detect_termux(self):
        """Detecta si el script está ejecutándose en Termux"""
        # Verificar variables de entorno de Termux
        if os.environ.get('TERMUX_VERSION'):
            return True
        
        # Verificar si existe el directorio de Termux
        if os.path.exists('/data/data/com.termux'):
            return True
        
        # Verificar si PREFIX apunta a Termux
        prefix = os.environ.get('PREFIX', '')
        if 'com.termux' in prefix:
            return True
        
        return False
    
    def _check_root_access(self):
        """Verifica si hay acceso root (solo en Termux)"""
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
        Ejecuta comando según el entorno (Termux o ADB)
        
        Args:
            command: Comando a ejecutar
            need_root: Si requiere root en modo Termux
        """
        try:
            if self.is_termux:
                # Modo Termux: ejecutar localmente
                if need_root and self.has_root:
                    cmd = ["su", "-c", command]
                else:
                    cmd = command.split()
            else:
                # Modo ADB: ejecutar via adb shell
                cmd = ["adb", "shell"] + command.split()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip().replace('\r', '')
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except FileNotFoundError:
            return "COMMAND_NOT_FOUND"
        except Exception as e:
            return f"ERROR: {e}"
    
    def run_adb(self, command):
        """Alias para compatibilidad con código antiguo"""
        return self.run_command(command)
    
    def check_adb_connection(self):
        """Verifica si hay dispositivo conectado (solo modo ADB)"""
        if self.is_termux:
            return True  # En Termux siempre está "conectado"
        
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=5
            )
            lines = result.stdout.strip().split('\n')
            devices = [l for l in lines[1:] if l.strip().endswith('device')]
            return len(devices) > 0
        except:
            return False
    
    def get_android_id(self):
        """Obtiene ANDROID_ID usando diferentes métodos"""
        # Método 1: settings (funciona sin root)
        result = self.run_command("settings get secure android_id")
        if result and "ERROR" not in result and "null" not in result and len(result) > 5:
            return result
        
        # Método 2: content query (alternativo)
        if self.is_termux:
            result = self.run_command("content query --uri content://settings/secure --where \"name='android_id'\"")
            if "value=" in result:
                for part in result.split(","):
                    if "value=" in part:
                        return part.split("=")[1].strip()
        
        # Método 3: getprop como fallback
        result = self.run_command("getprop ro.serialno")
        if result and "ERROR" not in result and len(result) > 5:
            return result
        
        return "UNAVAILABLE"
    
    def extract_info(self):
        """Extrae toda la información del dispositivo"""
        print("[*] Extrayendo información del dispositivo...")
        
        if self.is_termux:
            print(f"[*] Modo: Termux Local (Root: {'✓' if self.has_root else '✗'})")
        else:
            print("[*] Modo: ADB Shell")
        
        # Android ID (Device ID)
        print("[*] Obteniendo Android ID...")
        self.device_info['android_id'] = self.get_android_id()
        
        # Información del dispositivo
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
        
        # Serial number (puede estar restringido)
        self.device_info['serial'] = self.run_command("getprop ro.serialno")
        
        # Info adicional en Termux
        if self.is_termux:
            self.device_info['arch'] = self.run_command("uname -m")
            self.device_info['hostname'] = self.run_command("hostname")
        
        return self.device_info
    
    def display_results(self):
        """Muestra resultados formateados"""
        print("\n" + "=" * 70)
        print("  INFORMACIÓN DEL DISPOSITIVO ANDROID")
        if self.is_termux:
            print("  Método: TERMUX LOCAL")
            print(f"  Root: {'✓ Disponible' if self.has_root else '✗ No disponible'}")
        else:
            print("  Método: ADB SHELL")
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
        
        print("\n" + "=" * 70)
        print("  PARA EL GENERADOR INTERACTIVO DE LICENCIAS")
        print("=" * 70)
        print("\nCopia estos valores al ejecutar:")
        print("  python3 interactive_license_generator.py\n")
        
        print(f"  Device ID:   {self.device_info.get('android_id', 'N/A')}")
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
            "device_info": self.device_info,
            "for_license_generator": {
                "device_id": self.device_info.get('android_id', ''),
                "device_model": self.device_info.get('model', ''),
                "os_name": self.device_info.get('build_id', ''),
                "os_version": int(self.device_info.get('sdk_int', 0)) if self.device_info.get('sdk_int', '0').isdigit() else 0
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Información exportada a: {filename}")
        return filename


def main():
    """Función principal"""
    print("\n" + "=" * 70)
    print("  EXTRACTOR DE INFORMACIÓN DEL DISPOSITIVO")
    print("  Para uso con Generador de Licencias Thanos Android")
    print("=" * 70)
    print()
    
    # Verificar argumentos
    output_json = '--json' in sys.argv
    
    # Crear extractor
    extractor = DeviceInfoExtractor()
    
    # Verificar conexión ADB
    print("[*] Verificando conexión ADB...")
    if not extractor.check_adb_connection():
        print("\n❌ ERROR: No se detectó ningún dispositivo Android\n")
        print("Asegúrate de:")
        print("  1. Tener ADB instalado (https://developer.android.com/studio/command-line/adb)")
        print("  2. USB Debugging habilitado en el dispositivo")
        print("  3. Dispositivo conectado por USB")
        print("  4. Haber aceptado el prompt de USB Debugging")
        print("\nPara verificar conexión: adb devices")
        print()
        sys.exit(1)
    
    print("✓ Dispositivo Android detectado\n")
    
    # Extraer información
    try:
        extractor.extract_info()
        
        # Mostrar resultados
        extractor.display_results()
        
        # Exportar a JSON si se solicitó
        if output_json:
            extractor.export_json()
        
        # Sugerencia
        print("\n💡 SIGUIENTE PASO:")
        print("   Ejecuta: python3 interactive_license_generator.py")
        print("   E ingresa los valores mostrados arriba\n")
        
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
