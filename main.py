# Importación de módulos necesarios
from DarkAgent import DarkGPT
from cli import ConversationalShell

# Banner de inicio para la aplicación, mostrando un diseño ASCII con el creador
banner = r"""
     _   _    ______     _____ ____  
    | | / \  |  _ \ \   / /_ _/ ___| 
 _  | |/ _ \ | |_) \ \ / / | |\___ \ 
| |_| / ___ \|  _ < \ V /  | | ___) |
 \___/_/   \_\_| \_\ \_/  |___|____/ 

hecho por: @alonso_isidoro
"""
# Imprimir el banner para dar la bienvenida al usuario
print(banner)


# Definición de la función principal
def main():
    # Creación de una instancia de DarkGPT
    darkgpt = DarkGPT()
    # Creación de una instancia de ConversationalShell pasando la instancia de DarkGPT
    conversational_shell = ConversationalShell(darkgpt)
    # Inicio de la shell conversacional
    conversational_shell.Start()


# Punto de entrada principal para ejecutar la aplicación
if __name__ == "__main__":
    main()
