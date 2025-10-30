# Visión General del Sistema Criptográfico

Este documento detalla la implementación criptográfica del proyecto "Spy Agency Web". El propósito de la aplicación es permitir a agentes gestionar misiones secretas de forma segura. Su estructura interna se basa en un backend (Python/FastAPI) que maneja toda la lógica de negocio y criptográfica, y un frontend con el que interactúa el usuario. El sistema está diseñado para garantizar la confidencialidad, integridad y autenticidad de los datos.

## 1. Autenticación y Gestión de Contraseñas

La autenticación se realiza en dos fases: un inicio de sesión inicial con credenciales y la posterior validación de un token de sesión para las siguientes peticiones.

### 1.1. Gestión de Contraseñas

- **Algoritmo:** Las contraseñas de los usuarios se hashean utilizando **Argon2**. Fue elegido por su alta resistencia a ataques de fuerza bruta, especialmente aquellos que utilizan hardware especializado como GPUs, gracias a su diseño intensivo en memoria.
- **Proceso:** Cuando un usuario se registra, su contraseña en texto plano se pasa a la función `get_password_hash`. Solo el hash resultante se almacena en la base de datos.
- **Verificación:** Durante el login, la contraseña proporcionada se compara con el hash almacenado mediante `verify_password`, una función segura que previene ataques de temporización.

### 1.2. Generación de Claves a partir de Contraseñas

No se generan claves de cifrado _directamente_ de la contraseña. En su lugar, la contraseña del usuario se utiliza para **cifrar y proteger la clave privada RSA del usuario**, que se genera de forma independiente. De este modo, la clave privada solo puede ser descifrada por quien conozca la contraseña, añadiendo una capa fundamental de seguridad.

## 2. Cifrado Simétrico y Asimétrico (Esquema Híbrido)

El sistema utiliza un **esquema de cifrado híbrido** para proteger el contenido de las misiones, aprovechando las ventajas de ambos tipos de cifrado.

- **Cifrado Simétrico:** Se utiliza para cifrar el contenido de las misiones, que puede ser voluminoso.

  - **Algoritmo:** **AES-256-GCM**. Fue seleccionado por ser un estándar de la industria que ofrece no solo confidencialidad sino también **autenticación de datos (integridad)** en una sola operación (ver sección 3), lo que lo hace muy eficiente y seguro.
  - **Gestión de Claves:** Para cada misión se genera una clave AES de 256 bits única y de un solo uso. Esta clave se usa para cifrar el contenido y luego es "envuelta" (cifrada) usando cifrado asimétrico.

- **Cifrado Asimétrico:** Se utiliza para la gestión y distribución segura de las claves simétricas (el problema del intercambio de claves).
  - **Algoritmo:** **RSA de 2048 bits** con padding **OAEP (Optimal Asymmetric Encryption Padding)**. RSA es un estándar robusto para el cifrado asimétrico, y OAEP es el esquema de relleno recomendado actualmente, ya que previene ataques criptoanalíticos modernos.
  - **Gestión de Claves:** Cada usuario tiene su propio par de claves RSA. La clave pública se usa para cifrar la clave AES de una misión para ese usuario. La clave privada (custodiada como se describe en 1.2) se usa para descifrar dicha clave AES, dando así acceso al contenido de la misión.

## 3. Códigos de Autenticación de Mensajes (MAC) y Cifrado Autenticado

El sistema garantiza la integridad y autenticidad de los datos en dos puntos clave:

1.  **Tokens de Sesión (JWT):**

    - **Algoritmo:** Los tokens se firman usando **HS256 (HMAC-SHA256)**, que es un tipo de MAC.
    - **Propósito:** La firma HMAC garantiza que el token no ha sido modificado por un actor malicioso (integridad) y que fue emitido por nuestro servidor, que es el único que conoce la `SECRET_KEY` (autenticidad). La clave es una cadena secreta única del servidor.

2.  **Contenido de las Misiones (Cifrado Autenticado):**
    - **Algoritmo:** Como se mencionó, se utiliza **AES-256-GCM**. GCM (Galois/Counter Mode) es un modo de **cifrado autenticado**.
    - **Ventajas:** Esto es superior a usar cifrado y MAC por separado. En una única operación, AES-GCM proporciona:
      - **Confidencialidad:** El contenido es ilegible sin la clave.
      - **Integridad y Autenticidad:** Genera una etiqueta de autenticación (un MAC) sobre el contenido cifrado. Si el contenido es alterado en la base de datos, el proceso de descifrado fallará, alertando al sistema de una posible manipulación.

## 4. Pruebas de Calidad de Código

Tras una búsqueda en el repositorio (`glob(pattern="**/*test*.py")`), **no se han encontrado archivos de pruebas automatizadas** para el código del backend. Para garantizar la calidad y la correcta implementación de los flujos criptográficos, sería fundamental añadir una suite de tests unitarios y de integración que verifiquen, como mínimo:

- La correcta creación y verificación de hashes de contraseña.
- La generación y cifrado/descifrado de claves privadas.
- El flujo completo de creación, cifrado, descifrado y compartición de misiones.
- Los casos de error (ej. contraseña incorrecta, intento de acceso no autorizado, datos corruptos).
