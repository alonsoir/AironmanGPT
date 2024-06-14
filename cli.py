import os


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
            "Welcome to Jarvis an experiment to try to demonstrate the use of different specific tools as autonomous "
            "Langchain agents for pentesting. \n"
            "Type 'exit' to finish, 'clear' to clear the screen.\n"
            "Introduce the target you want to scan, and Jarvis will try to find the right tool for you."
        )

        try:
            while True:
                print("Type 'exit' to finish, 'clear' to clear the screen.\n")
                print("target? ")
                user_input = input("> ")  # Solicita entrada del usuario.
                if user_input.lower() == "exit":
                    # Termina la sesión si el usuario escribe 'exit'.
                    print("Session ended.")
                    break
                elif user_input.lower() == "clear":
                    # Limpia la pantalla si el usuario escribe 'clear'.
                    os.system("cls" if os.name == "nt" else "clear")
                else:
                    # Procesa la entrada del usuario.
                    self.ProcessInput(user_input)
        except KeyboardInterrupt:
            # Maneja la interrupción por teclado para terminar la sesión.
            print("\nSession terminated by the user.")

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
