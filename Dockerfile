# Usar la imagen base de Python
FROM python:3.12.4-slim-bullseye AS builder

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar el archivo .env al contenedor
COPY .env .env

# Usar el archivo .env para configurar las variables de entorno
ARG OPENAI_API_KEY
ENV OPENAI_API_KEY=${OPENAI_API_KEY}

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
    tshark \
    ngrep \
    tcpdump \
    net-tools \
    libcap2-bin \
    sudo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configurar Wireshark para instalación no interactiva
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    dpkg-reconfigure -f noninteractive wireshark-common && \
    usermod -aG wireshark root

# Establecer el setuid en dumpcap para permitir la captura de paquetes sin privilegios
RUN chmod +x /usr/bin/dumpcap && \
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Asignar las capacidades necesarias a Nmap
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

# Crear un usuario no root y establecer directorios
RUN useradd --create-home appuser && \
    mkdir -p /home/appuser/app /home/appuser/app/prompts /home/appuser/app/logs /home/appuser/app/pcap /home/appuser/app/nmap /home/appuser/.cache/pypoetry && \
    chown -R appuser:appuser /home/appuser

# Añadir el usuario al grupo wireshark
RUN usermod -aG wireshark appuser

# Permitir que el usuario appuser use sudo sin contraseña (opcional, pero útil para pruebas)
RUN echo "appuser ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Cambiar al usuario no root
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
COPY --chown=appuser:appuser ./prompts/agent_prompt.txt /home/appuser/app/prompts/agent_prompt.txt
COPY --chown=appuser:appuser ./prompts/router_prompt.txt /home/appuser/app/prompts/router_prompt.txt

# Establecer el punto de entrada para poetry run
ENTRYPOINT ["poetry", "run", "python3", "main.py"]
