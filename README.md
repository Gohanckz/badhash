# badhash

Detecta hashes de manera dinámica!

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
