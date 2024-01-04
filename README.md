# badhash

Detecta hashes de manera dinámica!

Soporta los siguientes algoritmos:
| MD5 | SHA-1 |SHA-224 | SHA-256 | SHA-384 |
--| --| --| --|--|
| SHA-512 | SHA3-224 | SHA3-256 | SHA3-384 | SHA3-512 |
| SHA512-224 | SHA512-256 | BCrypt | SCrypt | CRC32 |
| MD2 | MD4 | BLAKE2s | BLAKE2b | SM3 |
| RIPEMD-160 | MD5-SHA1 | | | |



## Descripción

La herramienta es un script de Python que busca coincidencias de hash en un diccionario de contraseñas usando varios algoritmos de hash. Soporta métodos criptográficos seguros y funciones especializadas para el hash de contraseñas y la verificación de integridad. Diseñada para verificar la seguridad de las contraseñas y entender la generación y comparación de hashes, la herramienta es flexible y ampliable para diferentes necesidades de cifrado.

## Instalación:

~~~
Git clone https://github.com/Gohanckz/badhash.git
cd badhash
pip install -r requirements.txt
~~~

## Uso:

~~~ bash
python badhash.py -d <passwords_list.txt> -t "<hash>"
~~~
