#!/usr/bin/env python3
"""
Extractor Automático de Información del Dispositivo
===================================================

Obtiene la información del dispositivo Android conectado via ADB
para usarla con el generador de licencias.

Requisitos:
- ADB instalado y en PATH
- USB Debugging habilitado
- Dispositivo conectado

Uso:
    python3 get_device_info.py
    python3 get_device_info.py --json  # Salida en JSON
"""

import subprocess
import sys
import json
from datetime import datetime


class DeviceInfoExtractor:
    """Extrae información del dispositivo via ADB"""
    
    def __init__(self):
        self.device_info = {}
    
    def run_adb(self, command):
        """Ejecuta comando ADB y retorna output limpio"""
        try:
            result = subprocess.run(
                ["adb", "shell"] + command.split(),
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip().replace('\r', '')
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except FileNotFoundError:
            return "ADB_NOT_FOUND"
        except Exception as e:
            return f"ERROR: {e}"
    
    def check_adb_connection(self):
        """Verifica si hay dispositivo conectado"""
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=5
            )
            lines = result.stdout.strip().split('\n')
            # Buscar dispositivos (líneas que terminan en "device")
            devices = [l for l in lines[1:] if l.strip().endswith('device')]
            return len(devices) > 0
        except:
            return False
    
    def extract_info(self):
        """Extrae toda la información del dispositivo"""
        print("[*] Extrayendo información del dispositivo...")
        
        # Android ID (Device ID)
        self.device_info['android_id'] = self.run_adb("settings get secure android_id")
        
        # Información del dispositivo
        self.device_info['manufacturer'] = self.run_adb("getprop ro.product.manufacturer")
        self.device_info['model'] = self.run_adb("getprop ro.product.model")
        self.device_info['brand'] = self.run_adb("getprop ro.product.brand")
        self.device_info['device'] = self.run_adb("getprop ro.product.device")
        
        # Build information
        self.device_info['build_id'] = self.run_adb("getprop ro.build.id")
        self.device_info['build_display'] = self.run_adb("getprop ro.build.display.id")
        self.device_info['build_fingerprint'] = self.run_adb("getprop ro.build.fingerprint")
        
        # Android version
        self.device_info['sdk_int'] = self.run_adb("getprop ro.build.version.sdk")
        self.device_info['android_version'] = self.run_adb("getprop ro.build.version.release")
        self.device_info['security_patch'] = self.run_adb("getprop ro.build.version.security_patch")
        
        # Hardware
        self.device_info['board'] = self.run_adb("getprop ro.product.board")
        self.device_info['hardware'] = self.run_adb("getprop ro.hardware")
        
        # Serial number (puede estar restringido)
        self.device_info['serial'] = self.run_adb("getprop ro.serialno")
        
        return self.device_info
    
    def display_results(self):
        """Muestra resultados formateados"""
        print("\n" + "=" * 70)
        print("  INFORMACIÓN DEL DISPOSITIVO ANDROID")
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
