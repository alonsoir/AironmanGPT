#!/bin/sh.bak
# Lista de comandos permitidos
ALLOWED_COMMANDS="ls nmap tshark curl msfconsole poetry"

# Comando que se intenta ejecutar
COMMAND=$1

# Verifica si el comando está en la lista de comandos permitidos
for ALLOWED in $ALLOWED_COMMANDS; do
    if [ "$COMMAND" = "$ALLOWED" ]; then
        shift
        exec "$COMMAND" "$@"
    fi
done

echo "Error: Command not allowed."
exit 1
