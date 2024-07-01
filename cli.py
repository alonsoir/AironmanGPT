import os
import re
import subprocess
from loguru import logger
from datetime import date


class ConversationalShell:
    """
    Clase ConversationalShell que gestiona la interacción con el usuario y procesa los comandos de entrada.
    """

    def __init__(self, darkgpt):
        """
        Inicializa la clase con un objeto DarkGPT y un historial de comandos vacío.

        :param darkgpt: Instancia de la clase DarkGPT para procesar las entradas del usuario.
        """
        self.history = {}  # Historial de comandos del usuario.
        self.darkgpt = darkgpt  # Instancia de DarkGPT para procesamiento de GPT.
        self.name_session = f"./logs/session-{date.today()}.log"

    def Start(self):
        """
        Inicia el bucle principal de la shell conversacional, procesando comandos del usuario.
        """
        # Mensaje de bienvenida al usuario.
        initial_message = (
            "Welcome to Jarvis, an experiment to demonstrate the use of different specific tools as "
            "autonomous \n Langchain agents for pentesting.\n Type 'exit' to finish, 'clear' to clear the "
            "screen.\nIntroduce the target you want to scan, and Jarvis will try to find the right tool "
            "for you."
        )
        logger.start(self.name_session)

        patron_command = r"^command=(.*)"
        patron_target = r"^target=(.*)"
        allowed_bash_commands = ["ls", "whoami", "nmap", "tshark", "msfconsole"]  # Lista de comandos permitidos en bash
        self.darkgpt.initialize_agent_prompt()
        logger.info(initial_message)
        logger.info(f"lista de comandos permitidos: {allowed_bash_commands}")

        try:
            while True:
                logger.info(
                    "Type 'exit' to finish, 'clear' to clear the screen.\n"
                    "'command=some command'\n"
                    "target='ip-target/range target'\n"
                    "some command\n"
                )
                logger.info(
                    f"A file named {self.name_session} has been created with the logs of the session.\n"
                )
                user_input = input(
                    "> ").strip()  # Solicita entrada del usuario y elimina espacios en blanco al inicio y final

                if user_input.lower() == "exit":
                    # Termina la sesión si el usuario escribe 'exit'.
                    logger.info(
                        f"Session ended. check the log file for details. {self.name_session}"
                    )
                    break

                if user_input.lower() == "clear":
                    # Limpia la pantalla si el usuario escribe 'clear'.
                    os.system("cls" if os.name == "nt" else "clear")
                    continue

                # Verificar si el usuario ingresó un comando específico permitido en bash
                if any(user_input.startswith(cmd) for cmd in allowed_bash_commands):
                    logger.info(f"Ejecutando comando en bash: {user_input}")
                    os.system(user_input)
                    continue

                # Verificar si el usuario ingresó un comando para enviar al LLM
                match_command = re.match(patron_command, user_input)
                if match_command:
                    comando_llm = match_command.group(1).strip()
                    logger.info(f"Enviando comando al LLM: {comando_llm}")
                    self.ProcessCommand(comando_llm, send_output=True)
                    continue

                # Verificar si el usuario ingresó un target para procesar
                match_target = re.match(patron_target, user_input)
                if match_target:
                    target = match_target.group(1).strip()
                    if target.lower() == "localhost" or target == "127.0.0.1":
                        logger.info("Target es localhost")
                        comando = "curl -s ifconfig.me | sed 's/%$//'"
                        logger.info(f"Ejecutando comando: {comando}")
                        try:
                            # Ejecutar el comando usando subprocess
                            resultado = subprocess.run(
                                comando, shell=True, capture_output=True, text=True
                            )

                            logger.info(
                                resultado.stdout
                                if resultado.returncode == 0
                                else resultado.stderr
                            )
                            self.ProcessInput(resultado.stdout)
                        except Exception as e:
                            logger.error(f"Error al ejecutar el comando: {str(e)}")
                            #self.ProcessInput(target)
                    else:
                        logger.info(f"Target es: {target}")
                        self.ProcessInput(target)
                    continue

                # Si no se cumple ninguna de las condiciones anteriores, procesar como entrada normal al LLM
                logger.info(f"Quieres decirme algo en lenguaje natural? perfecto... {user_input}")
                responses = self.darkgpt.invoke_model_with_chunks(user_input)
                logger.info(f"mi respuesta es {responses}")

        except KeyboardInterrupt as k:
            # Maneja la interrupción por teclado para terminar la sesión.
            logger.error(f"\nSession terminated by the user. {k}")
            pass

    def ProcessCommand(self, command, send_output=True):
        """
        Procesa el comando del usuario y envia la salida al llm.
        """
        try:
            logger.info(f"Ejecutando comando: {command}")
            # Ejecutar el comando usando subprocess
            resultado = subprocess.run(
                command, shell=True, capture_output=True, text=True
            )
            logger.info(
                resultado.stdout if resultado.returncode == 0 else resultado.stderr
            )
            if resultado.returncode == 0 and send_output:
                def handle_chunk(chunk_content):
                    """
                    Función interna para manejar los fragmentos de contenido devueltos por DarkGPT.

                    :param chunk_content: Contenido devuelto por DarkGPT.
                    """
                    logger.info(chunk_content)

                # Actualiza el historial con la entrada del usuario.
                self.history.update({"USER": command})
                self.history.update({"USER": resultado.stdout})
                historial_json = [
                    self.history
                ]  # Prepara el historial para ser procesado por DarkGPT.
                # Igual tengo que hacer split de cada historial antes de enviar al llm...
                logger.info(f"historial_json has {len(historial_json)} tokens...")
                # Llama a DarkGPT para procesar la entrada y manejar la salida con la función handle_chunk.
                self.darkgpt.GPT_with_command_output(
                    historial_json, callback=handle_chunk
                )

                # Añade la entrada del usuario al historial JSON.
                historial_json.append({"USER": command})
                logger.info("Done!")
        except Exception as e:
            logger.error(f"Error al ejecutar el comando: {str(e)}")

    def ProcessInput(self, user_input):
        """
        Procesa la entrada del usuario, enviándola a DarkGPT y manejando la salida.

        :param user_input: Entrada del usuario como cadena de texto.
        """

        def handle_chunk(chunk_content):
            """
            Función interna para manejar los fragmentos de contenido devueltos por DarkGPT.

            :param chunk_content: Contenido devuelto por DarkGPT.
            """
            logger.info(chunk_content)

        # Actualiza el historial con la entrada del usuario.
        self.history.update({"USER": user_input})
        historial_json = [
            self.history
        ]  # Prepara el historial para ser procesado por DarkGPT.
        logger.info(f"historial_json has {len(historial_json)} tokens...")
        # Llama a DarkGPT para procesar la entrada y manejar la salida con la función handle_chunk.
        self.darkgpt.GPT_with_function_output(historial_json, callback=handle_chunk)

        # Añade la entrada del usuario al historial JSON.
        historial_json.append({"USER": user_input})
        logger.info("Done!")

        # Cuanto historial puedo mantener???
