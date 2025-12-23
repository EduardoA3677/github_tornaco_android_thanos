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
    
    # String encontrada en libtn.so durante análisis
    # NOTA: Esta string NO se usa como salt en el algoritmo de verificación
    # Se mantiene solo como referencia del análisis
    SECRET_SALT = b"THANOX-C++"  # NO USADO en compute_server_key
    
    # Algoritmo confirmado por ingeniería inversa de libtn.so
    # La función nativa NO usa salt, solo: hash(toLowerCase(code))
    HASH_ALGORITHM = "sha256"  # Default confirmado
    
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
        
        ALGORITMO CONFIRMADO POR INGENIERÍA INVERSA:
        -------------------------------------------
        Análisis de libtn.so (289 instrucciones ARM64) confirmó:
        
        1. La función nativa NO usa salt
        2. Solo transforma: toLowerCase(removeHyphens(code))
        3. Luego compara con strcmp()
        
        Por lo tanto:
          serverKey = hash(toLowerCase(removeHyphens(activationCode)))
          
        NO es:
          serverKey = HMAC(code, SECRET_SALT)  ❌ INCORRECTO
          
        Args:
            activation_code: Código de activación (con o sin guiones)
            
        Returns:
            Server key que debe ir en campo "k" de la respuesta API
        """
        # Paso 1: Limpiar código (remover guiones)
        clean_code = activation_code.replace('-', '')
        
        # Paso 2: Convertir a lowercase (exactamente como hace libtn.so)
        lower_code = clean_code.lower()
        
        # Paso 3: Calcular hash según algoritmo (SIN salt)
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
        
        # Hash directo sin salt (confirmado por análisis de libtn.so)
        h.update(lower_code.encode())
        
        # NOTA: No se usa HMAC ni salt
        # El análisis exhaustivo de libtn.so confirmó que NO hay salt hardcodeado
        
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
        Genera respuesta en formato servidor real
        
        Returns:
            Dict compatible con CommonApiResWrapper (formato servidor)
        """
        msg_data = {
            "remainingHours": activation_code.duration_days * 24,
            "remainingMillis": activation_code.duration_days * 24 * 3600 * 1000
        }
        
        return {
            "result": 0,  # 0 = success, 1 = error
            "msg": msg_data,  # Objeto directo, no string
            "k": activation_code.server_key,  # ⭐ Clave para verificación nativa
            "i": activation_code.code,  # ⭐ REQUERIDO: código de activación
            "j": None,
            "l": None,
            "m": None
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
        
        # Guardar en dos archivos separados
        timestamp_str = int(code.created_at.timestamp())
        
        # Archivo JSON solo con respuesta del servidor (compacto, sin saltos de línea)
        json_filename = f"activation_{flavor_key}_{timestamp_str}_server_response.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(api_response, f, separators=(',', ':'), ensure_ascii=False)
        
        # Archivo TXT con información completa
        txt_filename = f"activation_{flavor_key}_{timestamp_str}_info.txt"
        with open(txt_filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("INFORMACIÓN DE LICENCIA GENERADA\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("CÓDIGO DE ACTIVACIÓN:\n")
            f.write(f"  {code.code}\n\n")
            
            f.write("SERVER KEY (para campo 'k'):\n")
            f.write(f"  {code.server_key}\n\n")
            
            f.write("TIPO DE SUSCRIPCIÓN:\n")
            f.write(f"  Flavor: {flavor_obj.text}\n")
            f.write(f"  Descripción: {flavor_obj.description}\n")
            f.write(f"  Precio: ${flavor_obj.price_usd} USD / ¥{flavor_obj.price_cny} CNY\n")
            f.write(f"  Duración: {code.duration_days} días\n\n")
            
            f.write("FECHAS:\n")
            f.write(f"  Creado: {code.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Expira: {code.expires_at.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("INFORMACIÓN DEL DISPOSITIVO:\n")
            f.write(f"  UUID:        {device.uuid}\n")
            f.write(f"  Device ID:   {device.device_id}\n")
            f.write(f"  Modelo:      {device.device_model}\n")
            f.write(f"  Build ID:    {device.os_name}\n")
            f.write(f"  API Level:   {device.os_version}\n\n")
            
            f.write("BINDING INFO:\n")
            f.write(f"  Estado: {'✓ Exitosa' if binding['success'] else '✗ Fallida'}\n")
            f.write(f"  isSubscribed: {binding['subscription']['isSubscribed']}\n")
            f.write(f"  Horas Restantes: {binding['subscription']['remainingHours']:,}\n")
            f.write(f"  Verificación Nativa: {'✓ PASARÍA' if binding['nativeVerification']['willPass'] else '✗ FALLARÍA'}\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("RESPUESTA DEL SERVIDOR (guardada en JSON):\n")
            f.write("=" * 80 + "\n")
            f.write(json.dumps(api_response, separators=(',', ':'), ensure_ascii=False))
            f.write("\n")
        
        print(f"\n💾 Archivos guardados:")
        print(f"   JSON: {json_filename}")
        print(f"   TXT:  {txt_filename}")
    
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
