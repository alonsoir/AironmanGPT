# Importación de módulos necesarios
import os
from premai import Prem
from DarkAgent import DarkGPT
from cli import ConversationalShell
from dotenv import load_dotenv
from openai import OpenAI
from loguru import logger

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
logger.info(banner)

def test_openai_api(api_key, model_name, model_name_test):
    logger.debug("API key is present.")
    logger.debug(
        f"I will to try to use the model {model_name} and {model_name_test} model as a test."
    )
    try:
        client = OpenAI(api_key=api_key)

        response = client.completions.create(
            model=model_name_test, prompt="This is a test."
        )
        logger.debug("Connection to OpenAI API successful!")
        logger.debug("Response:", response.model)
    except Exception as e:
        logger.error(
            "Error connecting to OpenAI API. Probably the API key is missing or invalid."
        )
        logger.error(
            "Check the.env file and try again. https://platform.openai.com/api-keys"
        )

def test_api():
    api_key = os.getenv("OPENAI_API_KEY")
    model_name_test = os.getenv("GPT_MODEL_NAME_TEST")
    model_name = os.getenv("GPT_MODEL_NAME")
    default_engine = os.getenv("DEFAULT_ENGINE")
    logger.debug(f"default_engine is {default_engine}")
    premai_api_key = os.getenv("PREMAI_API_KEY")
    premai_project_id = os.getenv("PREMAI_PROJECT_ID")
    messages_premai = [{"role": "user", "content": "This is a test."}]

    model_name_premai = os.getenv("PREMAI_MODEL")
    premai_system_prompt = os.getenv("PREMAI_SYSTEM_PROMPT")
    premai_session_id = os.getenv("PREMAI_SESSION_ID")
    premai_temperature = float(os.getenv("PREMAI_TEMPERATURE"))
    if default_engine == "openai-api":
        test_openai_api(api_key, model_name, model_name_test)
    if default_engine == "premai-api":
        test_premai_api(messages_premai, model_name_premai, premai_api_key, premai_project_id, premai_session_id,
                        premai_system_prompt, premai_temperature)
    if default_engine == "zeroday-api":
        pass


def test_premai_api(messages_premai, model_name_premai, premai_api_key, premai_project_id, premai_session_id,
                    premai_system_prompt, premai_temperature):
    logger.info(f"Using {model_name_premai}")
    client_premai = Prem(premai_api_key)
    message = client_premai.chat.completions.create(
        project_id=premai_project_id,
        messages=messages_premai,
        model=model_name_premai,
        system_prompt=premai_system_prompt,
        session_id=premai_session_id,
        temperature=premai_temperature,
    )
    logger.debug(f"Response: {message.choices[0].message.content} {message.additional_properties['status_code']}")
    logger.debug(f"{message.additional_properties['status_code'] == 200} Connection to PREMAI API successful!")


# Definición de la función principal
def main():
    test_api()
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
