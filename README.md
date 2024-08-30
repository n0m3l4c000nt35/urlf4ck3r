# 🕸️ URLf4ck3r 🕵️‍♂️

URLf4ck3r es una herramienta de reconocimiento diseñada para escanear y extraer URLs del código fuente de sitios web.

### 🚀 Características principales

- 🔍 Escaneo recursivo de URLs
- 🌐 Detección de subdominios
- ✍️ Detección de palabras sensibles en los comentarios
- 🔗 Clasificación de URLs absolutas y relativas
- 💠 Detección de archivos JavaScript
- 🎨 Salida colorida para una fácil lectura
- ⏱️ Interrumpible en cualquier momento

## 📋 Requisitos

- Python 3.x
- Bibliotecas: `requests`, `beautifulsoup4`, `pwntools`

## 🛠️ Instalación

1. Cloná este repositorio:

```
git clone https://github.com/n0m3l4c000nt35/urlf4ck3r.git
```

2. Instalá las dependencias:

```
pip install -r requirements.txt
```

3. Hacé el script ejecutable:

```
chmod +x urlf4ck3r.py
```

4. Para ejecutar el script desde cualquier ubicación:

- Mové el script a un directorio que esté en el PATH, por ejemplo:
  ```
  sudo mv urlf4ck3r.py /usr/bin/urlf4ck3r
  ```
- O añadí el directorio del script al PATH editando el archivo `.bashrc` o `.zshrc`:
  ```
  echo 'export PATH=$PATH:/ruta/al/directorio/de/urlf4ck3r' >> ~/.bashrc
  source ~/.bashrc
  ```

## 💻 Uso

Si seguiste el paso 4 de la instalación, podés ejecutar el script desde cualquier ubicación simplemente con:

```
urlf4ck3r -u <URL> -o output.txt
```

De lo contrario, desde el directorio del script:

```
./urlf4ck3r.py -u <URL> -o output
```

Ejemplo:

```
urlf4ck3r -u https://ejemplo.com -o output.txt
```

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Si tenés ideas para mejorar URLf4ck3r, no dudés en abrir un issue o enviar un pull request.

Si te salta algún error avisá no seas 💩.

Peace out! ☮️

## 👨‍💻 Autor

Creado con 🤪 & ❤️ por [n0m3l4c000nt35](https://github.com/n0m3l4c000nt35) 🇦🇷

¿Te gusta **urlf4ck3r**? ¡Deja una ⭐ en el repo y compartilo!
