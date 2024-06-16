import os
import re
import subprocess


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

    def Start(self):
        """
        Inicia el bucle principal de la shell conversacional, procesando comandos del usuario.
        """
        # Mensaje de bienvenida al usuario.
        print(
            "Welcome to Jarvis, an experiment to demonstrate the use of different specific tools as autonomous "
            "Langchain agents for pentesting.\n"
            "Type 'exit' to finish, 'clear' to clear the screen.\n"
            "Introduce the target you want to scan, and Jarvis will try to find the right tool for you."
        )
        patron_command = r"command=(.*)"
        patron_target = r"target=(.*)"

        try:
            while True:
                print(
                    "Type 'exit' to finish, 'clear' to clear the screen.\n"
                    "'command=some command' target='ip-target/range target'\n"
                )

                user_input = input("> ")  # Solicita entrada del usuario.

                if user_input.lower() == "exit":
                    # Termina la sesión si el usuario escribe 'exit'.
                    print("Session ended.")
                    break

                if user_input.lower() == "clear":
                    # Limpia la pantalla si el usuario escribe 'clear'.
                    os.system("cls" if os.name == "nt" else "clear")
                    continue

                coincidencia_patron_command = re.search(patron_command, user_input.lower())
                coincidencia_patron_target = re.search(patron_target, user_input.lower())

                if coincidencia_patron_command:
                    # Extraer el comando
                    comando = coincidencia_patron_command.group(1).strip()
                    print(f"Ejecutando comando: {comando}")
                    self.ProcessCommand(comando)

                if coincidencia_patron_target:
                    # Extraer el target
                    target = coincidencia_patron_target.group(1).strip()
                    if target.lower() == "localhost" or target == "127.0.0.1":
                        print("Target es localhost")
                        comando = "curl -s ifconfig.me | sed 's/%$//'"
                        try:
                            # Ejecutar el comando usando subprocess
                            resultado = subprocess.run(comando, shell=True, capture_output=True, text=True)
                            print(resultado.stdout if resultado.returncode == 0 else resultado.stderr)
                            self.ProcessInput(resultado.stdout)
                        except Exception as e:
                            print(f"Error al ejecutar el comando: {str(e)}")
                            self.ProcessInput(target)
                    else:
                        print(f"Target es: {target}")
                        self.ProcessInput(target)

        except KeyboardInterrupt:
            # Maneja la interrupción por teclado para terminar la sesión.
            print("\nSession terminated by the user.")

    def ProcessCommand(self, command):
        """
        Procesa el comando del usuario y envia la salida al llm.
        """
        try:
            # Ejecutar el comando usando subprocess
            resultado = subprocess.run(command, shell=True, capture_output=True, text=True)
            print(resultado.stdout if resultado.returncode == 0 else resultado.stderr)
            if resultado.returncode == 0:
                def handle_chunk(chunk_content):
                    """
                    Función interna para manejar los fragmentos de contenido devueltos por DarkGPT.

                    :param chunk_content: Contenido devuelto por DarkGPT.
                    """
                    print(chunk_content, end="")

                # Actualiza el historial con la entrada del usuario.
                self.history.update({"USER": command})
                self.history.update({"USER": resultado.stdout})
                historial_json = [
                    self.history
                ]  # Prepara el historial para ser procesado por DarkGPT.

                # Llama a DarkGPT para procesar la entrada y manejar la salida con la función handle_chunk.
                self.darkgpt.GPT_with_command_output(historial_json, callback=handle_chunk)

                # Añade la entrada del usuario al historial JSON.
                historial_json.append({"USER": command})
                print("Done!")
        except Exception as e:
            print(f"Error al ejecutar el comando: {str(e)}")
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
            print(chunk_content, end="")

        # Actualiza el historial con la entrada del usuario.
        self.history.update({"USER": user_input})
        historial_json = [
            self.history
        ]  # Prepara el historial para ser procesado por DarkGPT.

        # Llama a DarkGPT para procesar la entrada y manejar la salida con la función handle_chunk.
        self.darkgpt.GPT_with_function_output(historial_json, callback=handle_chunk)

        # Añade la entrada del usuario al historial JSON.
        historial_json.append({"USER": user_input})
        print("Done!")

        # Cuanto historial puedo mantener???
