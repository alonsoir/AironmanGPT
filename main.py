# Importación de módulos necesarios
import os

from DarkAgent import DarkGPT
from cli import ConversationalShell
from dotenv import load_dotenv
from openai import OpenAI

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


def test_openai_api():
    api_key = os.getenv("OPENAI_API_KEY")
    model_name_test = os.getenv("GPT_MODEL_NAME_TEST")
    model_name = os.getenv("GPT_MODEL_NAME")
    if not api_key:
        print("API key is missing.")
        return

    print(f"Using OpenAI API key: {api_key} and {model_name_test} model as a test.")
    try:
        client = OpenAI(api_key=api_key)

        response = client.completions.create(
            model=model_name_test, prompt="This is a test."
        )
        print("Connection to OpenAI API successful!")
        print("Response:", response)
    except Exception as e:
        print(f"Error connecting to OpenAI API: {e}")


# Definición de la función principal
def main():
    test_openai_api()
    # Creación de una instancia de DarkGPT
    darkgpt = DarkGPT()
    # Creación de una instancia de ConversationalShell pasando la instancia de DarkGPT
    conversational_shell = ConversationalShell(darkgpt)
    # Inicio de la shell conversacional
    conversational_shell.Start()


# Punto de entrada principal para ejecutar la aplicación
if __name__ == "__main__":
    load_dotenv()

    main()
