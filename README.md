# 🕸️ URLf4ck3r

## 🕵️‍♂️ Peor escaner del mundo ⚠️ NO LO USES si no lo vas a usar 👍

URLf4ck3r es una herramienta de reconocimiento diseñada para escanear y extraer URLs del código fuente de sitios web.

### 🚀 Características principales

- 🔍 Escaneo recursivo de URLs
- 🌐 Detección de subdominios
- 🔗 Clasificación de URLs absolutas y relativas
- 🎨 Salida colorida para una fácil lectura
- ⏱️ Interrumpible en cualquier momento

## 📋 Requisitos

- Python 3.x
- Bibliotecas: `requests`, `beautifulsoup4`, `pwntools`

## 🛠️ Instalación

1. Cloná este repositorio:

```
git clone https://github.com/tu-usuario/urlf4ck3r.git
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
urlf4ck3r -u <URL>
```

De lo contrario, desde el directorio del script:

```
./urlf4ck3r.py -u <URL>
```

Ejemplo:

```
urlf4ck3r -u https://ejemplo.com
```

## 🖥️ Salida

URLf4ck3r proporciona una salida detallada y colorida:

- 🟢 **Subdomains**: Subdominios encontrados durante el escaneo.
- 🔵 **Absolute URLs**: URLs que aparecen con su ruta absoluta dentro del código fuente de la URL que se está escaneando.
- 🟡 **Relative URLs**: URLs que se obtienen a partir de la ruta relativa a la URL que está siendo escaneada dentro del código fuente que se está escaneando.
- 🟣 **Visited URLs**: Lista de URLs que dinámicamente se va formando mientras se analiza la URL principal.
- 🔴 **URLs pendientes de visitar**: Lista de URLs que quedaron pendientes de escanear.

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Si tenés ideas para mejorar URLf4ck3r, no dudés en abrir un issue o enviar un pull request.
Si te salta algún error avisá no seas 💩.
Peace out! ☮️

## 📜 Licencia

Este proyecto está bajo licencia **VLLC** 🦁.

## 👨‍💻 Autor

Creado con 🤪 & ❤️ por [n0m3l4c000nt35](https://github.com/n0m3l4c000nt35) 🇦🇷

---

¿Te gusta **urlf4ck3r**? ¡Deja una ⭐ en el repositorio y compartilo!
