Subdomain & Sensitive Docs Scanner – Tampermonkey Script

Este proyecto es un script avanzado para Tampermonkey que permite realizar un escaneo rápido de:

✔ Subdominios y toda su información técnica
✔ Documentos sensibles expuestos en Google
✔ Tecnologías internas, puertos abiertos, SSL, DNS y más

Está diseñado para tareas de OSINT, superficie de ataque, recolección pasiva y auditorías de exposición pública.

🚀 Características principales
🔍 Escaneo de Subdominios

Obtención de WHOIS, ASN y registros DNS.

Enumeración de subdominios vía crt.sh + búsqueda masiva en Google.

Verificación de estado (activo/inactivo).

Detección de IP asociada.

Análisis SSL (SSL Labs + crt.sh).

Puertos abiertos vía Shodan + nombres de servicio (IANA).

Identificación de tecnologías internas.

Extracción de correos administrativos si están expuestos.

📄 Búsqueda de Documentos Sensibles

Generación automática de dorks personalizados.

Scraping controlado de hasta 100 resultados por dork.

Clasificación entre documentos normales y sensibles.

Exportación de resultados en TXT.

📦 Instalación
1. Instalar un lector de scripts tipo Tampermonkey

Puedes usar cualquiera de estos:

Tampermonkey (recomendado)

Violentmonkey

Greasemonkey

🔗 Disponible para Chrome, Edge, Firefox, Opera y otros.

2. Activar el modo desarrollador en la extensión

Esto permite importar scripts personalizados.

Tampermonkey → Dashboard → Utilities → Import → Enable Developer Mode

3. Importar el script

Descarga el archivo .js o copia el contenido.

En Tampermonkey, selecciona "Create a new script".

Pega el contenido del script.

Guarda (Ctrl+S) y asegúrate de que esté habilitado.

4. Consultar un dominio

Para usar el escáner:

Accede a cualquier página donde se ejecute el script.

Ingresa el dominio deseado usando un dork en el formato:

site:example.com


Selecciona la función deseada:

Escanear subdominios

Buscar documentos sensibles

Espera a que el script recolecte y muestre los resultados.

🖥️ Vista previa de la herramienta

<img width="524" height="225" alt="ddd" src="https://github.com/user-attachments/assets/50b1353b-ec48-465b-9912-e0acf5dfe370" />

▶️ Uso

Accede a cualquier página donde quieras ejecutar el scanner.

Se mostrará la interfaz del script en la parte superior.

Ingresa el dominio objetivo.

Selecciona:

Escanear subdominios, o

Buscar documentos sensibles

Espera a que el script recolecte y muestre los resultados.

⚠️ Disclaimer

Este script está diseñado únicamente para fines educativos y auditorías autorizadas.
Toda la información recolectada es 100% OSINT (fuentes públicas).
El uso indebido es responsabilidad exclusiva del usuario.

