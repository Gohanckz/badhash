import hashlib
import argparse
import sys
import zlib  # Importar zlib para CRC32
from termcolor import colored
from Crypto.Hash import SHA512, SHA224, RIPEMD160, MD2, MD4
from gmssl import sm3, func
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def get_hash_algorithms():
    available_algos = set(hashlib.algorithms_available)
    # Agregar CRC32 a la lista de algoritmos soportados
    additional_algos = {
        'sha512_256', 'sha512_224', 'ripemd160', 'sm3', 'md5-sha1', 'md2', 'md4', 
        'bcrypt', 'scrypt', 'crc32'
    }
    # Filtrar aquí cualquier algoritmo que sepas que no está soportado o no deseas usar
    unsupported_algos = {'shake_128', 'shake_256'}
    return (available_algos | additional_algos) - unsupported_algos

def hash_string(algo, input_string):
    try:
        if algo == 'crc32':
            # Calcular el CRC32
            return '%08X' % (zlib.crc32(input_string.encode()) & 0xFFFFFFFF)
        elif algo == 'md5-sha1':
            # Implementación manual de md5-sha1
            md5_part = hashlib.md5(input_string.encode()).digest()
            sha1_part = hashlib.sha1(input_string.encode()).digest()
            return (md5_part + sha1_part).hex()
        elif algo == 'bcrypt':
            # Usar bcrypt para hashear la contraseña
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(input_string.encode(), salt).decode()
        elif algo == 'scrypt':
            # Usar scrypt para hashear la contraseña
            kdf = Scrypt(salt=b'some_salt', length=32, n=2**14, r=8, p=1)
            return kdf.derive(input_string.encode()).hex()
        elif algo in ['md2', 'md4']:
            # Utilizar pycryptodome para md2 y md4
            hash_obj = MD2.new() if algo == 'md2' else MD4.new()
            hash_obj.update(input_string.encode())
            return hash_obj.hexdigest()
        elif algo == 'ripemd160':
            hash_obj = RIPEMD160.new()
            hash_obj.update(input_string.encode())
            return hash_obj.hexdigest()
        elif algo == 'sm3':
            return sm3.sm3_hash(func.bytes_to_list(input_string.encode()))
        elif algo in ['sha512_256', 'sha512_224']:
            # Utilizar SHA512 con truncamiento para sha512_256 y sha512_224
            hash_obj = SHA512.new(truncate=algo[-3:])
            hash_obj.update(input_string.encode())
            return hash_obj.hexdigest()
        else:
            hash_obj = getattr(hashlib, algo)()
            hash_obj.update(input_string.encode())
            return hash_obj.hexdigest()
    except AttributeError:
        print(f"Algoritmo {algo} no disponible en esta versión de hashlib ni en las bibliotecas adicionales.")
        return None

def main(args):
    dictionary_path = args.dictionary
    target_hash = args.target

    hash_algorithms = get_hash_algorithms()
    
    try:
        with open(dictionary_path, "r") as file:
            for line in file:
                password = line.strip()
                print(colored(f"Testing: {password}", "green"))
                
                for algo in hash_algorithms:
                    hashed = hash_string(algo, password)
                    if hashed is None:
                        continue  # Salta este algoritmo si no está disponible
                        
                    print(f"{algo}: {hashed}")
                    
                    if hashed == target_hash:
                        print(colored(f"[+] PWNED! : Algoritmo: {algo}, Hash: {hashed}, String: {password}", "red"))
                        return
    except FileNotFoundError:
        print(f"El archivo {dictionary_path} no fue encontrado.")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Busca coincidencias de hash en un diccionario de contraseñas.")
    parser.add_argument("-d", "--dictionary", required=True, help="Archivo de diccionario de contraseñas.")
    parser.add_argument("-t", "--target", required=True, help="El hash objetivo a buscar.")
    
    args = parser.parse_args()
    main(args)
