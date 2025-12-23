#!/usr/bin/env python3
"""
Generador Interactivo de Licencias - Thanos Android
====================================================

Permite configurar todos los parámetros del dispositivo manualmente
para generar licencias personalizadas exactas.

Uso:
    python3 interactive_license_generator.py

Características:
- Configuración manual de UUID
- Configuración de Device ID (ANDROID_ID)
- Modelo de dispositivo personalizado
- Múltiples algoritmos de hash
- Generación de archivos JSON y respuestas API

Autor: Ingeniería Inversa Educativa
"""

import sys
import os
import json
import hashlib
import hmac
import uuid as uuid_lib
import subprocess
from datetime import datetime, timedelta
from typing import Dict, Optional


class InteractiveLicenseGenerator:
    """Generador interactivo con configuración personalizada"""
    
    FLAVORS = {
        "1": {"name": "monthly", "desc": "Mensual (30 días)", "days": 30, "price": "$2.99"},
        "2": {"name": "yearly", "desc": "Anual (365 días)", "days": 365, "price": "$24.99"},
        "3": {"name": "lifetime", "desc": "Permanente (100 años)", "days": 36500, "price": "$49.99"},
    }
    
    ALGORITHMS = {
        "1": ("sha256", "SHA-256 (Recomendado)"),
        "2": ("sha1", "SHA-1"),
        "3": ("md5", "MD5"),
        "4": ("keccak", "Keccak/SHA3-256"),
    }
    
    def __init__(self):
        self.config = {
            'uuid': '',
            'device_id': '',
            'device_model': '',
            'os_name': '',
            'os_version': 0,
            'flavor': '',
            'algorithm': 'sha256',
            'custom_salt': ''
        }
        self.is_termux = self._detect_termux()
        self.has_root = False
        
        if self.is_termux:
            self.has_root = self._check_root_access()
    
    def _detect_termux(self):
        """Detecta si está ejecutándose en Termux"""
        if os.environ.get('TERMUX_VERSION'):
            return True
        if os.path.exists('/data/data/com.termux'):
            return True
        prefix = os.environ.get('PREFIX', '')
        if 'com.termux' in prefix:
            return True
        return False
    
    def _check_root_access(self):
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
    
    def _run_command(self, command):
        """Ejecuta comando con su -c si hay root, sino normal"""
        try:
            if self.has_root:
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
        except Exception as e:
            return f"ERROR: {e}"
    
    def _get_android_id_auto(self):
        """Obtiene Android ID automáticamente"""
        # Método 1: settings
        result = self._run_command("settings get secure android_id")
        if result and "ERROR" not in result and "null" not in result and len(result) > 5:
            return result
        
        # Método 2: content query
        result = self._run_command("content query --uri content://settings/secure --where \"name='android_id'\"")
        if "value=" in result:
            for part in result.split(","):
                if "value=" in part:
                    return part.split("=")[1].strip()
        
        # Método 3: getprop
        result = self._run_command("getprop ro.serialno")
        if result and "ERROR" not in result and len(result) > 5:
            return result
        
        return None
    
    def _auto_extract_device_info(self):
        """Extrae automáticamente información del dispositivo"""
        print("\n🔍 EXTRAYENDO INFORMACIÓN AUTOMÁTICAMENTE...")
        print("-" * 70)
        
        info = {}
        
        # Android ID
        print("[*] Obteniendo Android ID...")
        info['android_id'] = self._get_android_id_auto()
        
        # Modelo
        print("[*] Obteniendo modelo del dispositivo...")
        info['model'] = self._run_command("getprop ro.product.model")
        
        # Build ID
        print("[*] Obteniendo Build ID...")
        info['build_id'] = self._run_command("getprop ro.build.id")
        
        # API Level
        print("[*] Obteniendo API Level...")
        info['sdk_int'] = self._run_command("getprop ro.build.version.sdk")
        
        # Manufacturer y brand (info adicional)
        info['manufacturer'] = self._run_command("getprop ro.product.manufacturer")
        info['brand'] = self._run_command("getprop ro.product.brand")
        
        print("\n✓ Extracción completada")
        return info
    
    def print_header(self):
        """Muestra encabezado del generador"""
        print("\n" + "=" * 70)
        print("   GENERADOR INTERACTIVO DE LICENCIAS - THANOS ANDROID")
        print("=" * 70)
        print()
    
    def get_device_info(self):
        """Solicita información del dispositivo"""
        print("\n📱 INFORMACIÓN DEL DISPOSITIVO")
        print("-" * 70)
        
        # Detectar si está en Termux con root
        auto_extract = False
        if self.is_termux:
            print(f"\n🤖 Detectado: Termux en Android")
            print(f"   Root access: {'✓ Disponible' if self.has_root else '✗ No disponible'}")
            
            if self.has_root:
                print("\n💡 Puedo obtener la información automáticamente usando root.")
                choice = input("   ¿Deseas extracción automática? (s/n) [s]: ").strip().lower()
                auto_extract = choice != 'n' and choice != 'no'
            else:
                print("\n💡 Sin root, puedo intentar obtener algunos valores.")
                choice = input("   ¿Intentar extracción automática? (s/n) [n]: ").strip().lower()
                auto_extract = choice == 's' or choice == 'si'
        
        # Extracción automática
        if auto_extract:
            auto_info = self._auto_extract_device_info()
            
            print("\n📋 INFORMACIÓN OBTENIDA:")
            print("-" * 70)
            
            if auto_info.get('android_id'):
                print(f"   Device ID:   {auto_info['android_id']}")
                self.config['device_id'] = auto_info['android_id']
            else:
                print("   Device ID:   ⚠️  No disponible (se generará aleatorio)")
                self.config['device_id'] = self._generate_device_id()
            
            if auto_info.get('model'):
                print(f"   Modelo:      {auto_info['model']}")
                self.config['device_model'] = auto_info['model']
            
            if auto_info.get('build_id'):
                print(f"   Build ID:    {auto_info['build_id']}")
                self.config['os_name'] = auto_info['build_id']
            
            if auto_info.get('sdk_int'):
                print(f"   API Level:   {auto_info['sdk_int']}")
                try:
                    self.config['os_version'] = int(auto_info['sdk_int'])
                except:
                    self.config['os_version'] = 29
            
            if auto_info.get('manufacturer') and auto_info.get('brand'):
                print(f"   Info:        {auto_info['manufacturer']} - {auto_info['brand']}")
            
            print("\n✓ Usando valores extraídos automáticamente")
            
            # UUID siempre aleatorio
            self.config['uuid'] = str(uuid_lib.uuid4())
            print(f"   UUID:        {self.config['uuid']} (generado)")
            
            # Preguntar si desea editar algo
            print("\n¿Deseas modificar algún valor? (s/n) [n]: ", end="")
            if input().strip().lower() in ['s', 'si']:
                self._manual_input_device_info()
            
            return
        
        # Entrada manual
        print("\n⌨️  ENTRADA MANUAL DE VALORES")
        self._manual_input_device_info()
    
    def _manual_input_device_info(self):
        """Entrada manual de información del dispositivo"""
    def _manual_input_device_info(self):
        """Entrada manual de información del dispositivo"""
        print()
        
        # UUID
        if not self.config.get('uuid'):
            print("1. UUID del dispositivo:")
            print("   El UUID se genera automáticamente o puedes usar uno específico.")
            choice = input("   ¿Usar UUID aleatorio? (s/n) [s]: ").strip().lower()
            
            if choice == 'n' or choice == 'no':
                uuid_input = input("   Ingresa UUID (formato: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx): ").strip()
                try:
                    uuid_lib.UUID(uuid_input)
                    self.config['uuid'] = uuid_input
                except ValueError:
                    print("   ⚠️  UUID inválido, usando uno aleatorio")
                    self.config['uuid'] = str(uuid_lib.uuid4())
            else:
                self.config['uuid'] = str(uuid_lib.uuid4())
            
            print(f"   ✓ UUID: {self.config['uuid']}")
        
        # Device ID (ANDROID_ID)
        if not self.config.get('device_id'):
            print("\n2. Device ID (ANDROID_ID):")
            print("   Típicamente es un número hexadecimal de 16 caracteres")
            print("   Ejemplo: 9774d56d682e549c")
            choice = input("   ¿Usar Device ID aleatorio? (s/n) [s]: ").strip().lower()
            
            if choice == 'n' or choice == 'no':
                device_id = input("   Ingresa Device ID: ").strip()
                if device_id:
                    self.config['device_id'] = device_id
                else:
                    self.config['device_id'] = self._generate_device_id()
            else:
                self.config['device_id'] = self._generate_device_id()
            
            print(f"   ✓ Device ID: {self.config['device_id']}")
        else:
            # Ya tiene valor de extracción automática
            print(f"\n2. Device ID: {self.config['device_id']}")
            change = input("   ¿Cambiar? (s/n) [n]: ").strip().lower()
            if change in ['s', 'si']:
                device_id = input("   Nuevo Device ID: ").strip()
                if device_id:
                    self.config['device_id'] = device_id
        
        # Modelo del dispositivo
        if not self.config.get('device_model'):
            print("\n3. Modelo del dispositivo:")
            print("   Ejemplos: SM-G950F (Galaxy S8), Pixel 6, OnePlus 9 Pro")
            model = input("   Ingresa modelo [SM-G950F]: ").strip()
            self.config['device_model'] = model if model else "SM-G950F"
        else:
            print(f"\n3. Modelo: {self.config['device_model']}")
            change = input("   ¿Cambiar? (s/n) [n]: ").strip().lower()
            if change in ['s', 'si']:
                model = input("   Nuevo modelo: ").strip()
                if model:
                    self.config['device_model'] = model
        
        print(f"   ✓ Modelo: {self.config['device_model']}")
        
        # OS Name (Build ID)
        if not self.config.get('os_name'):
            print("\n4. Build ID del sistema:")
            print("   Ejemplo: QP1A.190711.020 (Android 10)")
            os_name = input("   Ingresa Build ID [QP1A.190711.020]: ").strip()
            self.config['os_name'] = os_name if os_name else "QP1A.190711.020"
        else:
            print(f"\n4. Build ID: {self.config['os_name']}")
            change = input("   ¿Cambiar? (s/n) [n]: ").strip().lower()
            if change in ['s', 'si']:
                os_name = input("   Nuevo Build ID: ").strip()
                if os_name:
                    self.config['os_name'] = os_name
        
        print(f"   ✓ Build ID: {self.config['os_name']}")
        
        # OS Version (SDK INT)
        if not self.config.get('os_version') or self.config['os_version'] == 0:
            print("\n5. Versión de Android (API Level):")
            print("   Android 10 = 29, Android 11 = 30, Android 12 = 31, etc.")
            try:
                os_version = input("   Ingresa API Level [29]: ").strip()
                self.config['os_version'] = int(os_version) if os_version else 29
            except ValueError:
                self.config['os_version'] = 29
        else:
            print(f"\n5. API Level: {self.config['os_version']}")
            change = input("   ¿Cambiar? (s/n) [n]: ").strip().lower()
            if change in ['s', 'si']:
                try:
                    os_version = input("   Nuevo API Level: ").strip()
                    if os_version:
                        self.config['os_version'] = int(os_version)
                except ValueError:
                    print("   ⚠️  Valor inválido, manteniendo actual")
        
        print(f"   ✓ API Level: {self.config['os_version']}")
    
    def _generate_device_id(self):
        """Genera un Device ID hexadecimal aleatorio de 16 caracteres"""
        import random
        import string
        return ''.join(random.choices(string.hexdigits.lower(), k=16))
    
    def select_flavor(self):
        """Selecciona tipo de suscripción"""
        print("\n🎫 TIPO DE SUSCRIPCIÓN")
        print("-" * 70)
        
        for key, flavor in self.FLAVORS.items():
            print(f"   {key}. {flavor['desc']} - {flavor['price']}")
        
        choice = input("\nSelecciona opción [1]: ").strip()
        if choice not in self.FLAVORS:
            choice = "1"
        
        self.config['flavor'] = self.FLAVORS[choice]['name']
        self.config['duration_days'] = self.FLAVORS[choice]['days']
        print(f"   ✓ Seleccionado: {self.FLAVORS[choice]['desc']}")
    
    def select_algorithm(self):
        """Selecciona algoritmo de hash"""
        print("\n🔐 ALGORITMO DE HASH")
        print("-" * 70)
        print("   El algoritmo correcto depende del servidor real.")
        print("   SHA-256 es el más probable basado en análisis.\n")
        
        for key, (algo, desc) in self.ALGORITHMS.items():
            print(f"   {key}. {desc}")
        
        choice = input("\nSelecciona algoritmo [1]: ").strip()
        if choice in self.ALGORITHMS:
            self.config['algorithm'] = self.ALGORITHMS[choice][0]
        else:
            self.config['algorithm'] = 'sha256'
        
        print(f"   ✓ Algoritmo: {self.config['algorithm'].upper()}")
    
    def advanced_options(self):
        """Opciones avanzadas"""
        print("\n⚙️  OPCIONES AVANZADAS")
        print("-" * 70)
        
        choice = input("   ¿Usar salt/clave personalizada? (s/n) [n]: ").strip().lower()
        if choice == 's' or choice == 'si':
            salt = input("   Ingresa salt personalizado: ").strip()
            self.config['custom_salt'] = salt
            print(f"   ✓ Salt: {salt}")
        else:
            print("   ✓ Usando salt por defecto")
    
    def generate_code(self):
        """Genera el código de activación"""
        print("\n🔨 GENERANDO CÓDIGO DE ACTIVACIÓN...")
        print("-" * 70)
        
        # Generar código base
        timestamp = int(datetime.now().timestamp())
        flavor_code = self.config['flavor'][0].upper()
        
        payload = f"{flavor_code}{self.config['duration_days']:04d}{timestamp}"
        if self.config['custom_salt']:
            payload += self.config['custom_salt']
        
        # Hash del payload
        h = hashlib.sha256(payload.encode())
        code_base = h.hexdigest().upper()[:20]  # 20 chars = 5 secciones de 4
        
        # Checksum
        checksum_h = hmac.new(
            b"THANOX-C++",
            code_base.encode(),
            hashlib.sha256
        )
        checksum = checksum_h.hexdigest().upper()[:4]
        
        # Código completo
        full_code = code_base + checksum
        formatted_code = '-'.join([full_code[i:i+4] for i in range(0, 24, 4)])
        
        return formatted_code
    
    def compute_server_key(self, activation_code):
        """Calcula la clave que el servidor debe retornar"""
        clean_code = activation_code.replace('-', '').lower()
        
        if self.config['algorithm'] == 'sha256':
            h = hashlib.sha256()
        elif self.config['algorithm'] == 'sha1':
            h = hashlib.sha1()
        elif self.config['algorithm'] == 'md5':
            h = hashlib.md5()
        elif self.config['algorithm'] == 'keccak':
            h = hashlib.sha3_256()
        else:
            h = hashlib.sha256()
        
        h.update(clean_code.encode())
        return h.hexdigest()
    
    def display_results(self, activation_code, server_key):
        """Muestra resultados"""
        print("\n✅ CÓDIGO GENERADO EXITOSAMENTE")
        print("=" * 70)
        
        now = datetime.now()
        expires = now + timedelta(days=self.config['duration_days'])
        
        print(f"\n📋 CÓDIGO DE ACTIVACIÓN:")
        print(f"   {activation_code}")
        print(f"\n🔑 SERVER KEY (Campo 'k' de la API):")
        print(f"   {server_key}")
        
        print(f"\n📱 INFORMACIÓN DEL DISPOSITIVO:")
        print(f"   UUID:        {self.config['uuid']}")
        print(f"   Device ID:   {self.config['device_id']}")
        print(f"   Modelo:      {self.config['device_model']}")
        print(f"   Build ID:    {self.config['os_name']}")
        print(f"   API Level:   {self.config['os_version']}")
        
        print(f"\n⏰ DURACIÓN:")
        print(f"   Días:        {self.config['duration_days']}")
        print(f"   Expira:      {expires.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\n🔐 ALGORITMO:")
        print(f"   Hash:        {self.config['algorithm'].upper()}")
    
    def generate_api_response(self, activation_code, server_key):
        """Genera respuesta de API completa"""
        now = datetime.now()
        
        return {
            "activationCode": {
                "code": activation_code,
                "serverKey": server_key,
                "flavor": self.config['flavor'],
                "durationDays": self.config['duration_days'],
                "createdAt": now.isoformat(),
                "expiresAt": (now + timedelta(days=self.config['duration_days'])).isoformat(),
                "algorithm": self.config['algorithm']
            },
            "deviceInfo": {
                "uuid": self.config['uuid'],
                "deviceId": self.config['device_id'],
                "deviceModel": self.config['device_model'],
                "osName": self.config['os_name'],
                "osVersion": self.config['os_version']
            },
            "apiResponse": {
                "result": 0,
                "k": server_key,
                "msg": json.dumps({
                    "remainingHours": self.config['duration_days'] * 24,
                    "remainingMillis": self.config['duration_days'] * 24 * 3600 * 1000
                })
            }
        }
    
    def save_to_file(self, data, activation_code):
        """Guarda resultados en archivo JSON"""
        timestamp = int(datetime.now().timestamp())
        filename = f"license_{self.config['flavor']}_{timestamp}_custom.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 GUARDADO EN ARCHIVO:")
        print(f"   {os.path.abspath(filename)}")
        
        return filename
    
    def run(self):
        """Ejecuta el generador interactivo"""
        self.print_header()
        
        print("Este generador te permite crear códigos de activación personalizados")
        print("configurando manualmente todos los parámetros del dispositivo.\n")
        
        # Pasos
        self.get_device_info()
        self.select_flavor()
        self.select_algorithm()
        self.advanced_options()
        
        # Generar
        activation_code = self.generate_code()
        server_key = self.compute_server_key(activation_code)
        
        # Mostrar
        self.display_results(activation_code, server_key)
        
        # Guardar
        data = self.generate_api_response(activation_code, server_key)
        filename = self.save_to_file(data, activation_code)
        
        # Finalizar
        print("\n" + "=" * 70)
        print("✨ GENERACIÓN COMPLETADA")
        print("=" * 70)
        print("\nNOTAS:")
        print("  • El código fue generado con tus parámetros específicos")
        print("  • La server key se calculó con el algoritmo seleccionado")
        print("  • Puedes usar estos valores para configurar tu servidor")
        print("  • Consulta GUIA_OBTENER_DEVICE_INFO.md para extraer datos reales\n")


def main():
    """Función principal"""
    try:
        generator = InteractiveLicenseGenerator()
        generator.run()
    except KeyboardInterrupt:
        print("\n\n❌ Operación cancelada por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
