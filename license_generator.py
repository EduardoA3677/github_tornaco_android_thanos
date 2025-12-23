#!/usr/bin/env python3
"""
Generador de Licencias de Activación - Thanos Android
========================================================

Este script genera códigos de activación para la aplicación Thanos Android
basándose en el análisis del sistema de activación.

ADVERTENCIA: Este script es solo para propósitos educativos y de investigación.
El algoritmo real de generación está en el servidor y no fue completamente
determinado del análisis del smali.

Autor: Análisis de Reverse Engineering
Fecha: Diciembre 2025
"""

import hashlib
import hmac
import uuid
import random
import string
import json
from datetime import datetime, timedelta
from typing import Dict, Optional
from dataclasses import dataclass, asdict


@dataclass
class DeviceInfo:
    """Información del dispositivo para vinculación"""
    uuid: str
    device_id: str
    device_model: str
    os_name: str
    os_version: int

    @classmethod
    def generate_sample(cls):
        """Genera información de dispositivo de muestra"""
        return cls(
            uuid=str(uuid.uuid4()),
            device_id=''.join(random.choices(string.hexdigits.lower(), k=16)),
            device_model="SM-G950F",  # Samsung Galaxy S8
            os_name="QP1A.190711.020",
            os_version=29  # Android 10
        )


@dataclass
class Flavor:
    """Tipo de suscripción"""
    text: str
    description: str
    price_usd: float
    price_cny: float


@dataclass
class ActivationCode:
    """Código de activación generado"""
    code: str
    flavor: str
    duration_days: int
    created_at: datetime
    expires_at: datetime
    device_binding: Optional[DeviceInfo] = None

    def to_dict(self):
        """Convierte a diccionario para serialización"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['expires_at'] = self.expires_at.isoformat()
        return data


class LicenseGenerator:
    """Generador de códigos de licencia"""
    
    # Flavors disponibles (basado en análisis)
    FLAVORS = {
        "monthly": Flavor("Monthly", "Suscripción Mensual", 2.99, 19.99),
        "yearly": Flavor("Yearly", "Suscripción Anual", 24.99, 168.00),
        "lifetime": Flavor("Lifetime", "Licencia Permanente", 49.99, 328.00),
    }
    
    # Configuración
    CODE_LENGTH = 24  # Longitud estimada del código
    CODE_SECTIONS = 6  # Número de secciones
    SECTION_LENGTH = 4  # Caracteres por sección
    
    # Clave secreta (NOTA: Esta es una aproximación, la real está en el servidor)
    SECRET_KEY = b"THANOS_ACTIVATION_KEY_2023"
    
    def __init__(self, secret_key: Optional[bytes] = None):
        """
        Inicializa el generador
        
        Args:
            secret_key: Clave secreta para HMAC (opcional)
        """
        self.secret_key = secret_key or self.SECRET_KEY
    
    def _generate_base_code(self, flavor: str, duration_days: int) -> str:
        """
        Genera la parte base del código
        
        Args:
            flavor: Tipo de suscripción
            duration_days: Duración en días
            
        Returns:
            Código base sin checksum
        """
        # Crear payload con información del código
        timestamp = int(datetime.now().timestamp())
        payload = f"{flavor}{duration_days}{timestamp}"
        
        # Generar hash
        hash_obj = hashlib.sha256(payload.encode())
        hash_hex = hash_obj.hexdigest().upper()
        
        # Tomar los primeros N caracteres
        base_length = (self.CODE_SECTIONS - 1) * self.SECTION_LENGTH
        base_code = hash_hex[:base_length]
        
        return base_code
    
    def _calculate_checksum(self, base_code: str) -> str:
        """
        Calcula checksum para el código
        
        Args:
            base_code: Código base
            
        Returns:
            Checksum de 4 caracteres
        """
        # Usar HMAC para generar checksum
        hmac_obj = hmac.new(
            self.secret_key,
            base_code.encode(),
            hashlib.sha256
        )
        checksum = hmac_obj.hexdigest().upper()[:self.SECTION_LENGTH]
        return checksum
    
    def _format_code(self, code_string: str) -> str:
        """
        Formatea el código en secciones separadas por guiones
        
        Args:
            code_string: Código sin formato
            
        Returns:
            Código formateado (ej: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX)
        """
        sections = [
            code_string[i:i+self.SECTION_LENGTH]
            for i in range(0, len(code_string), self.SECTION_LENGTH)
        ]
        return '-'.join(sections)
    
    def generate_code(
        self,
        flavor: str = "monthly",
        duration_days: Optional[int] = None
    ) -> ActivationCode:
        """
        Genera un código de activación
        
        Args:
            flavor: Tipo de suscripción (monthly, yearly, lifetime)
            duration_days: Duración en días (opcional, se calcula según flavor)
            
        Returns:
            ActivationCode generado
        """
        if flavor not in self.FLAVORS:
            raise ValueError(f"Flavor inválido: {flavor}. Opciones: {list(self.FLAVORS.keys())}")
        
        # Determinar duración
        if duration_days is None:
            duration_map = {
                "monthly": 30,
                "yearly": 365,
                "lifetime": 365 * 100  # 100 años para "permanente"
            }
            duration_days = duration_map[flavor]
        
        # Generar código base
        base_code = self._generate_base_code(flavor, duration_days)
        
        # Calcular checksum
        checksum = self._calculate_checksum(base_code)
        
        # Código completo
        full_code = base_code + checksum
        formatted_code = self._format_code(full_code)
        
        # Crear objeto ActivationCode
        now = datetime.now()
        expires_at = now + timedelta(days=duration_days)
        
        activation_code = ActivationCode(
            code=formatted_code,
            flavor=flavor,
            duration_days=duration_days,
            created_at=now,
            expires_at=expires_at
        )
        
        return activation_code
    
    def bind_device(
        self,
        activation_code: ActivationCode,
        device_info: DeviceInfo
    ) -> Dict:
        """
        Vincula un código de activación con un dispositivo
        
        Args:
            activation_code: Código de activación
            device_info: Información del dispositivo
            
        Returns:
            Diccionario con resultado de vinculación
        """
        activation_code.device_binding = device_info
        
        # Crear estructura de vinculación (simula API response)
        binding_data = {
            "success": True,
            "code": activation_code.code,
            "device": {
                "uuid": device_info.uuid,
                "deviceId": device_info.device_id,
                "deviceModel": device_info.device_model,
                "osName": device_info.os_name,
                "osVersion": device_info.os_version
            },
            "subscription": {
                "isSubscribed": True,
                "flavor": activation_code.flavor,
                "remainingHours": activation_code.duration_days * 24,
                "remainingMillis": activation_code.duration_days * 24 * 3600 * 1000,
                "expiresAt": activation_code.expires_at.isoformat()
            }
        }
        
        return binding_data
    
    def verify_code(self, code: str) -> bool:
        """
        Verifica si un código es válido (checksum)
        
        Args:
            code: Código a verificar
            
        Returns:
            True si el checksum es válido
        """
        # Remover guiones
        clean_code = code.replace('-', '')
        
        if len(clean_code) != self.CODE_LENGTH:
            return False
        
        # Separar base y checksum
        base_code = clean_code[:-self.SECTION_LENGTH]
        provided_checksum = clean_code[-self.SECTION_LENGTH:]
        
        # Calcular checksum esperado
        expected_checksum = self._calculate_checksum(base_code)
        
        return provided_checksum == expected_checksum


def main():
    """Función principal para demostración"""
    print("=" * 70)
    print("Generador de Licencias de Activación - Thanos Android")
    print("=" * 70)
    print()
    
    generator = LicenseGenerator()
    
    # Generar códigos para cada flavor
    for flavor_key, flavor_obj in generator.FLAVORS.items():
        print(f"\n{flavor_obj.text} ({flavor_obj.description})")
        print(f"Precio: ${flavor_obj.price_usd} USD / ¥{flavor_obj.price_cny} CNY")
        print("-" * 70)
        
        # Generar código
        code = generator.generate_code(flavor=flavor_key)
        
        print(f"Código Generado: {code.code}")
        print(f"Duración: {code.duration_days} días")
        print(f"Creado: {code.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Expira: {code.expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Verificar código
        is_valid = generator.verify_code(code.code)
        print(f"Verificación Checksum: {'✓ Válido' if is_valid else '✗ Inválido'}")
        
        # Generar información de dispositivo
        device = DeviceInfo.generate_sample()
        print(f"\nDispositivo de Prueba:")
        print(f"  UUID: {device.uuid}")
        print(f"  Device ID: {device.device_id}")
        print(f"  Modelo: {device.device_model}")
        print(f"  OS: {device.os_name} (API {device.os_version})")
        
        # Vincular con dispositivo
        binding = generator.bind_device(code, device)
        print(f"\nVinculación:")
        print(f"  Estado: {'✓ Exitosa' if binding['success'] else '✗ Fallida'}")
        print(f"  isSubscribed: {binding['subscription']['isSubscribed']}")
        print(f"  Horas Restantes: {binding['subscription']['remainingHours']:,}")
        
        # Guardar a JSON
        filename = f"activation_{flavor_key}_{int(code.created_at.timestamp())}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({
                'activation_code': code.to_dict(),
                'binding': binding
            }, f, indent=2, ensure_ascii=False)
        print(f"\nGuardado en: {filename}")
    
    print("\n" + "=" * 70)
    print("\nNOTAS IMPORTANTES:")
    print("1. Los códigos generados usan un algoritmo estimado")
    print("2. El servidor real usa una clave secreta diferente")
    print("3. Para uso en producción, se requiere análisis del servidor")
    print("4. Este script es solo para propósitos educativos")
    print("=" * 70)


if __name__ == "__main__":
    main()
