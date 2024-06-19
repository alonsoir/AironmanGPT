# Etapa de construcción
FROM python:3.12.4-slim-bullseye AS builder

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar el archivo .env al contenedor. Sé que no es lo mejor, pero me daba muchos problemas si no está al arrancar.
COPY .env .env

# Usar el archivo .env para configurar las variables de entorno
ENV OPENAI_API_KEY=${OPENAI_API_KEY}

# Agregar el archivo .env a .bashrc para asegurarse de que las variables de entorno estén disponibles en el entorno interactivo
RUN echo "source /app/.env" >> /etc/bash.bashrc

# Actualizar lista de paquetes e instalar dependencias
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    curl \
    nmap \
    wireshark-common \
    wireshark && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configurar Wireshark para instalación no interactiva
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    dpkg-reconfigure -f noninteractive wireshark-common && \
    usermod -aG wireshark root

# Crear un usuario no root y establecer directorios
RUN useradd --create-home appuser && \
    mkdir -p /home/appuser/app /home/appuser/.cache/pypoetry && \
    chown -R appuser:appuser /home/appuser

USER appuser

# Establecer el directorio de trabajo y el entorno del usuario
WORKDIR /home/appuser/app

# Instalar Poetry usando curl en el directorio del usuario
RUN curl -sSL https://install.python-poetry.org | python3 - && \
    /home/appuser/.local/bin/poetry config virtualenvs.in-project true && \
    /home/appuser/.local/bin/poetry config cache-dir /home/appuser/.cache/pypoetry

# Añadir Poetry al PATH del usuario
ENV PATH="/home/appuser/.local/bin:$PATH"

# Copiar los archivos de configuración de dependencias
COPY --chown=appuser:appuser pyproject.toml poetry.lock ./

# Instalar las dependencias sin las de desarrollo
RUN poetry install --no-root --no-dev

# Copiar los archivos de la aplicación
COPY --chown=appuser:appuser ./tools/tshark_nmap.py ./tools/tools.py ./tools/nmap_recognition.py ./tools/
COPY --chown=appuser:appuser cli.py dehashed_api.py DarkAgent.py darkgpt.py functions.py main.py /home/appuser/app/

# Establecer el punto de entrada para poetry run
ENTRYPOINT ["poetry", "run", "python3", "main.py"]
