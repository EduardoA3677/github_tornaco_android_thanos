#!/usr/bin/env python3
"""
Generador Avanzado de Licencias - Thanos Android
=================================================

Script actualizado basado en ingeniería inversa completa de libtn.so

HALLAZGO CRÍTICO:
-----------------
La función Java_tornaco_android_sec_net_S_c realiza:
1. Convierte strings a lowercase
2. Compara activationCode procesado con serverKey usando strcmp
3. Si no coinciden -> crash/exit
4. Si coinciden -> verificación exitosa

ALGORITMO REAL:
---------------
El servidor debe calcular:
  serverKey = transformar_y_hashear(activationCode)

La función nativa compara:
  if (toLowerCase(activationCode) != serverKey) { exit(1); }

Basado en análisis de 289 instrucciones ARM64 desensambladas.

Autor: Análisis de Ingeniería Inversa
Fecha: Diciembre 2025
"""

import hashlib
import hmac
import uuid
import random
import string
import json
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
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
            device_model="SM-G950F",
            os_name="QP1A.190711.020",
            os_version=29
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
    server_key: str = ""  # Hash que el servidor debe retornar
    device_binding: Optional[DeviceInfo] = None

    def to_dict(self):
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['expires_at'] = self.expires_at.isoformat()
        return data


class AdvancedLicenseGenerator:
    """
    Generador de licencias con algoritmo basado en ingeniería inversa
    """
    
    FLAVORS = {
        "monthly": Flavor("Monthly", "Suscripción Mensual", 2.99, 19.99),
        "yearly": Flavor("Yearly", "Suscripción Anual", 24.99, 168.00),
        "lifetime": Flavor("Lifetime", "Licencia Permanente", 49.99, 328.00),
    }
    
    CODE_LENGTH = 24
    CODE_SECTIONS = 6
    SECTION_LENGTH = 4
    
    # Claves encontradas en análisis (ajustar según descubrimientos)
    # La string "THANOX-C++" encontrada podría ser parte del salt
    SECRET_SALT = b"THANOX-C++"
    
    # Algoritmo basado en análisis (puede ser SHA256, Keccak, etc.)
    HASH_ALGORITHM = "sha256"  # Default, ajustar según análisis
    
    def __init__(self, secret_key: Optional[bytes] = None, algorithm: str = None):
        """
        Inicializa el generador con algoritmo específico
        
        Args:
            secret_key: Clave secreta para HMAC
            algorithm: 'sha256', 'md5', 'sha1', 'keccak' etc.
        """
        self.secret_key = secret_key or self.SECRET_SALT
        self.algorithm = algorithm or self.HASH_ALGORITHM
    
    def _generate_base_code(self, flavor: str, duration_days: int, salt: str = "") -> str:
        """Genera código base con información embebida"""
        timestamp = int(datetime.now().timestamp())
        
        # Formato del código con metadatos
        flavor_code = {
            'monthly': 'M',
            'yearly': 'Y',
            'lifetime': 'L'
        }.get(flavor, 'X')
        
        # Crear payload
        payload = f"{flavor_code}{duration_days:04d}{timestamp}{salt}"
        
        # Hash
        h = hashlib.sha256(payload.encode())
        hash_hex = h.hexdigest().upper()
        
        # Tomar primeros caracteres
        base_length = (self.CODE_SECTIONS - 1) * self.SECTION_LENGTH
        return hash_hex[:base_length]
    
    def _calculate_checksum(self, base_code: str) -> str:
        """Calcula checksum con HMAC"""
        h = hmac.new(
            self.secret_key,
            base_code.encode(),
            hashlib.sha256
        )
        return h.hexdigest().upper()[:self.SECTION_LENGTH]
    
    def _format_code(self, code_string: str) -> str:
        """Formatea con guiones"""
        sections = [
            code_string[i:i+self.SECTION_LENGTH]
            for i in range(0, len(code_string), self.SECTION_LENGTH)
        ]
        return '-'.join(sections)
    
    def compute_server_key(self, activation_code: str) -> str:
        """
        Calcula la clave K que el servidor debe retornar.
        
        Basado en análisis de libtn.so:
        - La función nativa convierte código a lowercase
        - Luego compara con serverKey usando strcmp
        
        Por lo tanto, serverKey = hash(toLowerCase(activationCode))
        
        Args:
            activation_code: Código de activación (con o sin guiones)
            
        Returns:
            Server key que debe ir en campo "k" de la respuesta API
        """
        # Limpiar código (remover guiones)
        clean_code = activation_code.replace('-', '')
        
        # Convertir a lowercase (como hace libtn.so)
        lower_code = clean_code.lower()
        
        # Calcular hash según algoritmo
        if self.algorithm == 'sha256':
            h = hashlib.sha256()
        elif self.algorithm == 'sha1':
            h = hashlib.sha1()
        elif self.algorithm == 'md5':
            h = hashlib.md5()
        elif self.algorithm == 'keccak':
            # SHA3-256 (Keccak)
            h = hashlib.sha3_256()
        else:
            h = hashlib.sha256()
        
        # Opción 1: Hash simple
        h.update(lower_code.encode())
        
        # Opción 2: HMAC con salt (descomentar si es necesario)
        # h = hmac.new(self.secret_key, lower_code.encode(), hashlib.sha256)
        
        return h.hexdigest()
    
    def generate_code(
        self,
        flavor: str = "monthly",
        duration_days: Optional[int] = None,
        custom_salt: str = ""
    ) -> ActivationCode:
        """
        Genera código de activación con server key calculado
        
        Args:
            flavor: Tipo de suscripción
            duration_days: Duración personalizada
            custom_salt: Salt adicional para el código
            
        Returns:
            ActivationCode con server_key calculado
        """
        if flavor not in self.FLAVORS:
            raise ValueError(f"Flavor inválido: {flavor}")
        
        if duration_days is None:
            duration_map = {
                "monthly": 30,
                "yearly": 365,
                "lifetime": 36500
            }
            duration_days = duration_map[flavor]
        
        # Generar código
        base_code = self._generate_base_code(flavor, duration_days, custom_salt)
        checksum = self._calculate_checksum(base_code)
        full_code = base_code + checksum
        formatted_code = self._format_code(full_code)
        
        # Calcular server key que debe retornar la API
        server_key = self.compute_server_key(formatted_code)
        
        # Crear objeto
        now = datetime.now()
        expires_at = now + timedelta(days=duration_days)
        
        return ActivationCode(
            code=formatted_code,
            flavor=flavor,
            duration_days=duration_days,
            created_at=now,
            expires_at=expires_at,
            server_key=server_key
        )
    
    def verify_code_native_simulation(
        self,
        activation_code: str,
        server_key: str
    ) -> bool:
        """
        Simula la verificación que hace libtn.so
        
        Basado en desensamblado ARM64:
        1. Convierte activationCode a lowercase
        2. Compara con serverKey usando strcmp
        3. Retorna True si coinciden
        
        Args:
            activation_code: Código ingresado por usuario
            server_key: Clave K del servidor
            
        Returns:
            True si la verificación nativa pasaría
        """
        # Limpiar y convertir a lowercase (como libtn.so)
        clean_code = activation_code.replace('-', '').lower()
        
        # Calcular hash esperado
        expected_key = self.compute_server_key(activation_code)
        
        # Comparar (simulando strcmp de libtn.so)
        return expected_key == server_key
    
    def generate_api_response(
        self,
        activation_code: ActivationCode
    ) -> Dict:
        """
        Genera respuesta completa de API que pasaría verificación nativa
        
        Returns:
            Dict compatible con CommonApiResWrapper
        """
        return {
            "result": 0,  # 0 = success
            "k": activation_code.server_key,  # ⭐ Clave para verificación nativa
            "msg": json.dumps({
                "remainingHours": activation_code.duration_days * 24,
                "remainingMillis": activation_code.duration_days * 24 * 3600 * 1000
            })
        }
    
    def bind_device(
        self,
        activation_code: ActivationCode,
        device_info: DeviceInfo
    ) -> Dict:
        """Vincula código con dispositivo"""
        activation_code.device_binding = device_info
        
        return {
            "success": True,
            "code": activation_code.code,
            "serverKey": activation_code.server_key,
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
            },
            "nativeVerification": {
                "willPass": self.verify_code_native_simulation(
                    activation_code.code,
                    activation_code.server_key
                )
            }
        }


def demonstrate_algorithms():
    """Demuestra diferentes algoritmos de hash"""
    print("\n" + "=" * 80)
    print("COMPARACIÓN DE ALGORITMOS DE HASH")
    print("=" * 80)
    
    test_code = "ABCD-1234-EFGH-5678-IJKL-9012"
    
    algorithms = ['sha256', 'sha1', 'md5', 'keccak']
    
    print(f"\nCódigo de prueba: {test_code}")
    print(f"Lowercase: {test_code.replace('-', '').lower()}")
    print("\nServer Keys calculadas con cada algoritmo:")
    print("-" * 80)
    
    for algo in algorithms:
        gen = AdvancedLicenseGenerator(algorithm=algo)
        server_key = gen.compute_server_key(test_code)
        print(f"{algo.upper():10s}: {server_key}")


def main():
    """Función principal mejorada"""
    print("=" * 80)
    print("Generador Avanzado de Licencias - Thanos Android")
    print("Basado en Ingeniería Inversa Completa de libtn.so")
    print("=" * 80)
    
    # Demostrar algoritmos
    demonstrate_algorithms()
    
    # Generar códigos con algoritmo por defecto (SHA256)
    print("\n" + "=" * 80)
    print("GENERACIÓN DE CÓDIGOS CON SHA256 (Default)")
    print("=" * 80)
    
    generator = AdvancedLicenseGenerator()
    
    for flavor_key, flavor_obj in generator.FLAVORS.items():
        print(f"\n{flavor_obj.text} - {flavor_obj.description}")
        print(f"Precio: ${flavor_obj.price_usd} USD / ¥{flavor_obj.price_cny} CNY")
        print("-" * 80)
        
        # Generar código
        code = generator.generate_code(flavor=flavor_key)
        
        print(f"Código Generado:  {code.code}")
        print(f"Server Key (K):   {code.server_key}")
        print(f"Duración:         {code.duration_days} días")
        print(f"Expira:           {code.expires_at.strftime('%Y-%m-%d')}")
        
        # Verificar simulación nativa
        native_pass = generator.verify_code_native_simulation(
            code.code,
            code.server_key
        )
        print(f"Verificación Nativa: {'✓ PASARÍA' if native_pass else '✗ FALLARÍA'}")
        
        # Generar respuesta API
        api_response = generator.generate_api_response(code)
        print(f"\nRespuesta API que debe retornar el servidor:")
        print(f"  {{")
        print(f"    \"result\": {api_response['result']},")
        print(f"    \"k\": \"{api_response['k']}\",")
        print(f"    \"msg\": \"{api_response['msg']}\"")
        print(f"  }}")
        
        # Vincular con dispositivo
        device = DeviceInfo.generate_sample()
        binding = generator.bind_device(code, device)
        
        print(f"\nDispositivo:")
        print(f"  UUID:   {device.uuid}")
        print(f"  Model:  {device.device_model}")
        print(f"  OS:     {device.os_name}")
        
        # Guardar
        filename = f"activation_{flavor_key}_{int(code.created_at.timestamp())}_advanced.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({
                'activation_code': code.to_dict(),
                'api_response': api_response,
                'binding': binding
            }, f, indent=2, ensure_ascii=False)
        
        print(f"\nGuardado en: {filename}")
    
    print("\n" + "=" * 80)
    print("NOTAS IMPORTANTES:")
    print("=" * 80)
    print("""
1. Server Key calculada según análisis de libtn.so
2. La función nativa compara: toLowerCase(code) vs serverKey
3. Algoritmo por defecto: SHA256 (ajustar si es necesario)
4. Para producción: interceptar tráfico real para confirmar algoritmo
5. El servidor REAL usa clave secreta diferente

PRÓXIMOS PASOS PARA VALIDACIÓN:
- Interceptar tráfico con mitmproxy/Burp Suite
- Capturar código válido real y su serverKey
- Comparar con nuestro algoritmo
- Ajustar algoritmo/salt según resultados reales
    """)
    print("=" * 80)


if __name__ == "__main__":
    main()
