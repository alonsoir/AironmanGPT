#!/bin/bash

# Reemplaza 'example.com' con tu dominio objetivo
domain="as.com"

# Encuentra subdominios
echo "[*] Buscando subdominios para $domain..."
subfinder -d $domain -o subdomains.txt

# Verifica los subdominios con httpx
echo "[*] Verificando subdominios encontrados..."
/Users/aironman/.go/bin/httpx -l subdomains.txt -o live_subdomains.txt

echo "[*] Proceso completado. Subdominios vivos guardados en live_subdomains.txt"
