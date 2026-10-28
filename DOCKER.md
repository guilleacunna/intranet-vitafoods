# Levantar la intranet con Docker

## Requisitos

- Docker Desktop instalado y en ejecución.
- El archivo local `.env`, con la configuración de Entra ID y las variables `PROXY_TARGET_*`.
- El catálogo `data/services.json` si se quiere mostrar el catálogo local existente.

`.env` y los archivos JSON de `data` no se incluyen en la imagen ni en Git. Compose monta `data` para conservar los cambios del catálogo en el equipo anfitrión.

## Demo local

Desde la carpeta del proyecto:

```powershell
docker compose up --build -d
docker compose ps
docker compose logs -f intranet
```

Abrir [http://localhost:3000](http://localhost:3000). Para detener la demo:

```powershell
docker compose down
```

La aplicación inicia con Entra ID según el `.env`. Para el inicio de sesión local, `ENTRA_ID_REDIRECT_URI` debe ser `http://localhost:3000/auth/callback` y esa misma URI debe estar registrada en Entra ID. Al reiniciar el contenedor, inicia sesión de nuevo; las sesiones y la caché MSAL no se conservan entre reinicios.

Compose publica el puerto 3000 del contenedor solo en `127.0.0.1` del equipo y configura `TRUST_PROXY=0`, ya que esta demo no está detrás de un proxy inverso. Se puede cambiar el puerto del equipo con `HOST_PORT`, por ejemplo `HOST_PORT=8080`, pero el redirect URI de Entra debe continuar coincidiendo con el host y puerto desde el que se inicia sesión.

## Presentación desde otros equipos

La configuración anterior está pensada para probar desde el mismo equipo. No expongas directamente el puerto a Internet. Para acceder desde otros equipos y mantener Entra ID, se necesita un hostname accesible para los asistentes, HTTPS con un certificado confiable y registrar en Entra la URI de callback exacta de ese hostname. También debe confirmarse que el host Docker puede alcanzar los destinos internos configurados en `PROXY_TARGET_*`.
