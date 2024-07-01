import json
import os
import time
from datetime import date
from json import JSONDecodeError

import tiktoken
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from loguru import logger
from openai import (
    Client,
    APIResponseValidationError,
    APIStatusError,
    APIConnectionError,
    APITimeoutError,
    BadRequestError,
    AuthenticationError,
    PermissionDeniedError,
    NotFoundError,
)
from premai import Prem
from premai.models.response_choice import ResponseChoice
from dehashed_api import consultar_dominio_dehashed
from functions import Leak_Function
from tools.tools import timer, str_to_bool
from tools.tshark_nmap import NetworkScanner
from tools.metasploit import Metasploit

name_session = f"session-{date.today()}.log"
logger.start(name_session)

# Definición de los prompts que se utilizarán para generar las respuestas del modelo.

file_path_agent_prompt = "./prompts/metasploit_reconn_agent_prompt.txt"
with open(file_path_agent_prompt, "r", encoding="utf-8") as file_agent:
    MSReconnAgentPrompt = file_agent.read()

file_path_agent_prompt = "./prompts/metasploit_ports_systems_services_agent_prompt.txt"
with open(file_path_agent_prompt, "r", encoding="utf-8") as file_agent:
    MSPortsSystemServicesAgentPrompt = file_agent.read()

file_path_agent_prompt = "./prompts/metasploit_ports_services_vulns_agent_prompt.txt"
with open(file_path_agent_prompt, "r", encoding="utf-8") as file_agent:
    MSPortsServicesVulnsAgentPrompt = file_agent.read()


file_path_agent_prompt = "./prompts/initialize_agent_prompt.txt"
with open(file_path_agent_prompt, "r", encoding="utf-8") as file_agent:
    AgentPrompt = file_agent.read()

file_path_router_prompt = "./prompts/router_prompt.txt"
with open(file_path_router_prompt, "r", encoding="utf-8") as file_router:
    RouterPrompt = file_router.read()

file_path_agent_prompt = "./prompts/recoinassance_agent_prompt.txt"
with open(file_path_agent_prompt, "r", encoding="utf-8") as file_agent:
    RecoinassancePrompt = file_agent.read()

file_path_agent_prompt = "./prompts/ports_services_vulnerabilities_agent_prompt.txt"
with open(file_path_agent_prompt, "r", encoding="utf-8") as file_agent:
    PortsServicesVulnerabilitiesPrompt = file_agent.read()

file_path_agent_prompt = "./prompts/ports_system_services_agent_prompt.txt"
with open(file_path_agent_prompt, "r", encoding="utf-8") as file_agent:
    PortsSystemServicesPrompt = file_agent.read()

# Clase principal DarkGPT que encapsula la funcionalidad del modelo GPT y la interacción con la API de OpenAI.
def chunk_message(content, max_tokens):
    encoding = os.getenv("TIKTOKEN_ENCODING")
    logger.warning(f"tokenizer uses this encoding: {encoding}")
    tokenizer = tiktoken.get_encoding(
        encoding
    )  # Asegúrate de usar el tokenizador adecuado para tu modelo
    tokens = tokenizer.encode(content)
    chunks = []

    start = 0
    len_tokens = len(tokens)
    logger.info(f"len_tokens: {len_tokens}")

    while start < len_tokens:
        end = start + max_tokens
        if end < len_tokens:
            # Ajustar el final para no cortar palabras
            while end > start and not tokenizer.decode([tokens[end - 1]]).isspace():
                end -= 1
            if end == start:
                end = (
                    start + max_tokens
                )  # No se encontró espacio en blanco, forzar corte
        chunk_tokens = tokens[start:end]
        chunk_text = tokenizer.decode(chunk_tokens)
        if len(chunk_text) > max_tokens:
            logger.warning(f"Chunk text length exceeds max tokens: {len(chunk_text)}")
            # Dividir el texto en una longitud aceptable
            split_index = chunk_text.rfind(" ", 0, max_tokens)
            if split_index == -1:
                split_index = max_tokens
            chunk_text = chunk_text[:split_index]
        logger.info(f"chunk_tokens: {len(chunk_tokens)} start: {start} end: {end}")
        logger.info(f"chunk_text: {len(chunk_text)} start: {start} end: {end}")
        chunks.append(chunk_text)
        start = end

    return chunks


class DarkGPT:
    # Método inicializador de la clase.
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.openai_model_name = os.getenv("GPT_MODEL_NAME")
        interface_tshark = os.getenv("INTERFACE_TSHARK")
        nmap_output_file = os.getenv("NMAP_OUTPUT_FILE")
        pcap_output_file = os.getenv("PCAP_OUTPUT_FILE")
        target_network = os.getenv("TARGET_NETWORK")
        initial_wait_time = int(os.getenv("INITIAL_WAIT", "5"))
        capture_duration = int(os.getenv("CAPTURE_DURATION", "30"))
        self.temperature = int(os.getenv("TEMPERATURE", "1"))
        self.max_tokens = int(os.getenv("MAX_TOKENS", "30000"))
        self.timeout = int(os.getenv("TIMEOUT", "2"))
        self.max_retries = int(os.getenv("MAX_RETRIES", "2"))
        self.default_engine = os.getenv("DEFAULT_ENGINE")

        logger.info(f"interface_tshark is {interface_tshark}")
        logger.info(f"nmap_output_file is {nmap_output_file}")
        logger.info(f"pcap_output_file is {pcap_output_file}")
        logger.info(f"target_network is {target_network}")
        logger.info(f"initial_wait_time is {initial_wait_time}")
        logger.info(f"capture_duration is {capture_duration}")
        logger.info(f"temperature is {self.temperature}")
        logger.info(f"max_tokens is {self.max_tokens}")
        logger.info(f"timeout is {self.timeout}")
        logger.info(f"max_retries is {self.max_retries}")

        self.model_chat_openai = ChatOpenAI(
            model=self.openai_model_name,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            timeout=self.timeout,
            max_retries=self.max_retries,
            api_key=self.api_key,
        )
        self.interface = interface_tshark  # Reemplazar con tu interfaz de red adecuada (por ejemplo, en0, en1, etc.)
        self.target_network = target_network
        self.nmap_output_file = nmap_output_file
        self.pcap_output_file = pcap_output_file

        # Parámetros de tiempo
        self.initial_wait = initial_wait_time  # Tiempo de espera inicial antes de iniciar la siguiente acción

        self.capture_duration = (
            capture_duration  # Duración de la captura de tráfico en segundos
        )

        self.scanner = NetworkScanner(
            self.interface,
            self.target_network,
            self.nmap_output_file,
            self.pcap_output_file,
            self.initial_wait,
            self.capture_duration,
        )
        self.metasploit = Metasploit()

        self.functions = (
            Leak_Function  # Funciones personalizadas para que el modelo las utilice.
        )
        self.openai_client = (
            Client()
        )  # Configuración del cliente OpenAI con la clave API.
        premai_api_key = os.getenv("PREMAI_API_KEY")
        self.client_premai = Prem(premai_api_key)
        self.premai_project_id = os.getenv("PREMAI_PROJECT_ID")
        # mythalion-13b # remm-slerp-l2-13b
        self.model_name_premai = os.getenv("PREMAI_MODEL")
        self.premai_system_prompt = os.getenv("PREMAI_SYSTEM_PROMPT")
        self.premai_session_id = os.getenv("PREMAI_SESSION_ID")
        self.premai_temperature = float(os.getenv("PREMAI_TEMPERATURE"))
        logger.warning(f"ATTENTION, using by default {self.default_engine} engine.")
        if {self.default_engine} == "premai-api":
            logger.info(
                f"Using PREMAI API key: {premai_api_key}\n{self.model_name_premai}\n{self.premai_session_id}"
                f"\n{self.premai_temperature}\nself.premai_project_id\n."
            )
        if {self.default_engine} == "openai-api":
            logger.info(
                f"Using OpenAI API key: {self.api_key} and {self.openai_model_name} model in class DarkGPT."
            )
        if {self.default_engine} == "zeroday-api":
            logger.info("NOT IMPLEMENTED YET. Using by default OpenAI API.")
            self.default_engine = "openai-api"

    @timer
    # Método para ejecutar una llamada a función y procesar su salida.
    def execute_function_call(self, message):
        # Función interna para generar mensajes basados en el prompt y el mensaje del usuario.
        def mensajes(mensaje):
            lista_mensajes = [
                {"role": "system", "content": RouterPrompt},
                {"role": "user", "content": mensaje},
            ]
            return lista_mensajes

        # Genera una respuesta determinista para la llamada a función.
        functions_prompts = mensajes(message)

        response = self.openai_client.chat.completions.create(
            model=self.openai_model_name,
            temperature=self.temperature,
            messages=functions_prompts,
            functions=self.functions,
        )

        # Procesamiento previo de la salida para convertirla de JSON a un formato manejable.
        try:
            preprocessed_output = json.loads(
                response.choices[0].message.function_call.arguments
            )
            # Procesamiento de la salida utilizando la función personalizada consultar_dominio_dehashed.
            processed_output = consultar_dominio_dehashed(preprocessed_output)
            logger.info(f"Processed output: {processed_output}")
        except JSONDecodeError as e:
            processed_output = f"No encontrado {e}"
            pass
        except Exception as e1:
            processed_output = f"No encontrado {e1}"
            pass
        return str(processed_output)

    # Método para ejecutar una llamada a función y procesar su salida.
    @timer
    def execute_function_call_recoinassance(self, message):
        # Función interna para generar mensajes basados en el prompt y el mensaje del usuario.
        def mensajes(mensaje):
            lista_mensajes = [
                {"role": "system", "content": RouterPrompt},
                {"role": "user", "content": mensaje},
            ]
            return lista_mensajes

        functions_prompts = mensajes(message)
        target_ip_range = functions_prompts[1].get("content")
        query = f"Utiliza NmapTool para escanear el dominio {functions_prompts[1].get('content')}"
        logger.info(query)
        capture = os.getenv("USE_TSHARK")
        bool_capture = str_to_bool(capture)
        uso_tshark = f"USO DE WIRESHARK? {bool_capture}"
        dispatch_nmap_recoinassance = (
            f"RECOINASSANCE-{uso_tshark}\n"
            + self.scanner.capture_then_dispatch_nmap_reconnaissance(
                bool_capture, target_ip_range
            )
            + "\n"
        )
        processed_output = dispatch_nmap_recoinassance
        logger.warning(f"processed_output has {len(processed_output)} tokens.")
        logger.info(processed_output)
        return str(processed_output)

    def invoke_model_with_chunks(self, historial_json):
        """
        Invoca el modelo con el historial de mensajes.
        """
        if type(historial_json) is str or len(historial_json)> 0 and type(historial_json[0]) is str:
            content = historial_json
        if len(historial_json)> 0 and type(historial_json[0]) is SystemMessage:
            content = historial_json[0].content[0]['content']
        if len(historial_json)> 0 and type(historial_json[0]) is HumanMessage:
            content = historial_json[0]["content"]
        if len(historial_json)> 0 and type(historial_json[0]) is dict:
            content = historial_json[0]["content"]

        max_tokens_limit = (
            self.max_tokens - 1000
        )  # Reduce ligeramente para dar margen de seguridad
        logger.info(f"Sending message to llm...")
        logger.info(f"length of content: {len(content)}")
        logger.info(f"max tokens: {max_tokens_limit}")
        chunks = chunk_message(content, max_tokens_limit)

        responses = []
        try:
            logger.info(f"There are {len(chunks)} chunks. ")
            for chunk in chunks:
                logger.info(f"length of chunk: {len(chunk)}")
                message = self.invoke_with_retry(chunk)
                if type(message) is str:
                    responses.append(message)
                if type(message) is list:
                    responses.extend(message)
                if type(message) is dict:
                    for msg in message:
                        responses.append(msg.message.content)
                    responses.append(message)
        except Exception as e:
            logger.error(f"Error invoking doing chunks: {e}")
            pass
        return responses

    def invoke_with_retry(self, chunk, retries=3, wait_time=5):
        messages_premai = [{"role": "user", "content": chunk}]
        logger.info(f"Using: {self.default_engine}")

        def handle_exception(e, attempt):
            logger.warning(
                f"Request timed out. Attempt {attempt + 1} of {retries}. Retrying in {wait_time} seconds..."
            )
            logger.warning(e)
            time.sleep(wait_time)

        for attempt in range(retries):
            try:
                if self.default_engine == "premai-api":
                    message = self.client_premai.chat.completions.create(
                        project_id=self.premai_project_id,
                        messages=messages_premai,
                        model=self.model_name_premai,
                        system_prompt=self.premai_system_prompt,
                        session_id=self.premai_session_id,
                        temperature=self.premai_temperature,
                    )
                    # message.choices[0].message.content es un string, pero el mensaje puede ser mayor, por lo que
                    # hay que coger el dictionary message.choicesy extraer el contenido.
                    return message.choices
                elif self.default_engine == "openai-api":
                    try:
                        message = self.model_chat_openai.invoke(
                            [HumanMessage(content=chunk)]
                        )
                        return message
                    except (
                        APIResponseValidationError,
                        BadRequestError,
                        AuthenticationError,
                        PermissionDeniedError,
                        NotFoundError,
                        APIStatusError,
                        APITimeoutError,
                        APIConnectionError,
                    ) as e:
                        handle_exception(e, attempt)
            except Exception as premai_exception:
                logger.error(type(premai_exception))
                handle_exception(premai_exception, attempt)

        raise Exception("Max retries exceeded. Request failed.")

    @timer
    def execute_function_call_nmap_ports_systems_services(self, message):
        # Función interna para generar mensajes basados en el prompt y el mensaje del usuario.
        def mensajes(mensaje):
            lista_mensajes = [
                {"role": "system", "content": RouterPrompt},
                {"role": "user", "content": mensaje},
            ]
            return lista_mensajes

        functions_prompts = mensajes(message)
        target_ip_range = functions_prompts[1].get("content")
        query = f"Utiliza NmapTool para escanear el dominio {target_ip_range}"
        logger.debug(query)
        capture = os.getenv("USE_TSHARK")
        bool_capture = str_to_bool(capture)
        logger.info(f"capture packets with tshark {bool_capture}")
        uso_tshark = f"USO DE WIRESHARK? {bool_capture}"
        dispatch_nmap_ports_systems_services_output = (
            f"PORTS_SYSTEMS_SERVICES {uso_tshark}\n"
            + self.scanner.capture_then_dispatch_nmap_ports_systems_services(
                bool_capture, target_ip_range
            )
            + "\n"
        )

        processed_output = dispatch_nmap_ports_systems_services_output
        logger.warning(f"processed_output has {len(processed_output)} tokens.")

        logger.info(processed_output)
        return str(processed_output)

    @timer
    def execute_function_call_nmap_ports_services_vulnerabilities(self, message):
        # Función interna para generar mensajes basados en el prompt y el mensaje del usuario.
        def mensajes(mensaje):
            lista_mensajes = [
                {"role": "system", "content": RouterPrompt},
                {"role": "user", "content": mensaje},
            ]
            return lista_mensajes

        functions_prompts = mensajes(message)
        target_ip_range = functions_prompts[1].get("content")
        query = f"Utiliza NmapTool para escanear el dominio {target_ip_range}"
        logger.debug(query)
        capture = os.getenv("USE_TSHARK")
        bool_capture = str_to_bool(capture)
        uso_tshark = f"USO DE WIRESHARK? {bool_capture}"
        dispatch_nmap_ports_services_vulnerabilities_output = (
            f"PORTS_SERVICES_VULNERABILITIES {uso_tshark}\n"
            + self.scanner.capture_then_dispatch_nmap_ports_services_vulnerabilities(
                bool_capture, target_ip_range
            )
            + "\n"
        )
        processed_output = dispatch_nmap_ports_services_vulnerabilities_output
        logger.warning(f"processed_output has {len(processed_output)} tokens.")

        logger.info(processed_output)
        return str(processed_output)

    # Método para formatear el historial de mensajes incluyendo la salida de una llamada a función.
    @timer
    def process_history_with_function_output(
        self, messages: list, function_output: str
    ):
        history_json = (
            []
        )  # Lista inicial vacía para contener los mensajes formateados y la salida de la función.
        # Agrega la salida de la función al historial.
        history_json.append({"role": "system", "content": json.dumps(function_output)})
        for message in messages:
            # Formatea los mensajes basándose en el rol.
            if "USER" in message:
                message_formatted = {"role": "user", "content": message["USER"]}
                user_json = json.dumps(message_formatted)
                history_json.append(message_formatted)
                logger.info(f"USER: {user_json}\n")
            elif "ASISTENTE" in message:
                message_formatted = {
                    "role": "assistant",
                    "content": message["ASISTENTE"],
                }
                history_json.append(message_formatted)
                logger.info(f"ASISTENTE: {message_formatted}\n")

        return history_json

    # Método para generar respuestas utilizando el modelo GPT con la salida de la función incluida en el historial.
    @timer
    def GPT_with_function_output(self, historial: dict, callback=None):
        # Ejecuta la llamada a la función y obtiene su salida.
        self.process_nmap_reconnaissance(historial)
        self.process_nmap_ports_services_vulnerabilities(historial)
        self.process_nmap_ports_systems_services(historial)

        self.process_metasploit_reconnaissance(historial)
        self.process_metasploit_ports_services_vulnerabilities(historial)
        self.process_metasploit_ports_systems_services(historial)

    def initialize_agent_prompt(self, callback=None):
        logger.warning("Initialize agent prompt")
        """
        Inicializa la conversacion con el prompt, que tenga un contexto inicial que se lanza una vez al iniciar la
        conversacion. No quiero tener que mandar esto cada vez que mando una nueva salida de alguna herramienta.
        """
        history_json = (
            []
        )  # Lista inicial vacía para contener los mensajes formateados y la salida de la función.
        # Agrega la salida de la función al historial.
        history_json.append({"role": "system", "content": AgentPrompt})
        logger.info(f"AgentPrompt: {history_json}\n")
        messages = self.invoke_model_with_chunks([SystemMessage(content=history_json)])

        for message in messages:
            try:
                logger.info(message)
            except Exception as e:
                logger.error(e)
                pass  # Ignora los errores en el procesamiento de fragmentos.
    def initialize_metasploit_recoinassance_agent_prompt(self, callback=None):
        logger.warning("Initialize initialize_recoinassance_agent_prompt")
        """
        Inicializa la conversacion con el prompt, que tenga un contexto inicial que se lanza una vez al iniciar la
        conversacion. No quiero tener que mandar esto cada vez que mando una nueva salida de alguna herramienta.
        """
        history_json = (
            []
        )  # Lista inicial vacía para contener los mensajes formateados y la salida de la función.
        # Agrega la salida de la función al historial.
        history_json.append({"role": "system", "content": MSReconnAgentPrompt})
        logger.info(f"AgentPrompt: {history_json}\n")
        messages = self.invoke_model_with_chunks([SystemMessage(content=history_json)])

        for message in messages:
            try:
                logger.info(message)
            except Exception as e:
                logger.error(e)
                pass  # Ignora los errores en el procesamiento de fragmentos.

    def initialize_recoinassance_agent_prompt(self, callback=None):
        logger.warning("Initialize initialize_recoinassance_agent_prompt")
        """
        Inicializa la conversacion con el prompt, que tenga un contexto inicial que se lanza una vez al iniciar la
        conversacion. No quiero tener que mandar esto cada vez que mando una nueva salida de alguna herramienta.
        """
        history_json = (
            []
        )  # Lista inicial vacía para contener los mensajes formateados y la salida de la función.
        # Agrega la salida de la función al historial.
        history_json.append({"role": "system", "content": RecoinassancePrompt})
        logger.info(f"AgentPrompt: {history_json}\n")
        messages = self.invoke_model_with_chunks([SystemMessage(content=history_json)])

        for message in messages:
            try:
                logger.info(message)
            except Exception as e:
                logger.error(e)
                pass  # Ignora los errores en el procesamiento de fragmentos.
    def initialize_ports_services_vulns_agent_prompt(self, callback=None):
        logger.warning("Initialize initialize_ports_services_vulns_agent_prompt")
        """
        Inicializa la conversacion con el prompt, que tenga un contexto inicial que se lanza una vez al iniciar la
        conversacion. No quiero tener que mandar esto cada vez que mando una nueva salida de alguna herramienta.
        """
        history_json = (
            []
        )  # Lista inicial vacía para contener los mensajes formateados y la salida de la función.
        # Agrega la salida de la función al historial.
        history_json.append({"role": "system", "content": PortsServicesVulnerabilitiesPrompt})
        logger.info(f"AgentPrompt: {history_json}\n")
        messages = self.invoke_model_with_chunks([SystemMessage(content=history_json)])

        for message in messages:
            try:
                logger.info(message)
            except Exception as e:
                logger.error(e)
                pass  # Ignora los errores en el procesamiento de fragmentos.
    def initialize_ports_systems_services_agent_prompt(self, callback=None):
        logger.warning("Initialize initialize_ports_systems_services_agent_prompt")
        """
        Inicializa la conversacion con el prompt, que tenga un contexto inicial que se lanza una vez al iniciar la
        conversacion. No quiero tener que mandar esto cada vez que mando una nueva salida de alguna herramienta.
        """
        history_json = (
            []
        )  # Lista inicial vacía para contener los mensajes formateados y la salida de la función.
        # Agrega la salida de la función al historial.
        history_json.append({"role": "system", "content": PortsSystemServicesPrompt})
        logger.info(f"AgentPrompt: {history_json}\n")
        messages = self.invoke_model_with_chunks([SystemMessage(content=history_json)])

        for message in messages:
            try:
                logger.info(message)
            except Exception as e:
                logger.error(e)
                pass  # Ignora los errores en el procesamiento de fragmentos.

    @timer
    def GPT_with_command_output(self, historial, callback=None):
        output_command = historial[-1].get("USER")

        historial_json = self.process_history_with_function_output(
            historial, output_command
        )

        message = self.model_chat_openai.invoke(
            [HumanMessage(content=historial_json[0]["content"])]
        )

        # Itera a través de los fragmentos de respuesta e imprime el contenido.
        for chunk in message:
            try:
                logger.info(chunk[1])
            except Exception as e:
                logger.error(e)
                pass  # Ignora los errores en el procesamiento de fragmentos.

    def process_metasploit_ports_services_vulnerabilities(self, historial):
        pass

    def process_metasploit_ports_systems_services(self, historial):
        pass
    def process_metasploit_reconnaissance(self, historial):
        """
        voy a ejecutar metasploit con la salida xml que ha generado process_nmap_reconnaissance
        """
        target_ip_range = historial[-1].get("USER")
        self.initialize_metasploit_recoinassance_agent_prompt()

        function_output = self.metasploit.run_msf_recon()

        historial_json = self.process_history_with_function_output(
            historial, function_output
        )
        message = self.invoke_model_with_chunks(historial_json)

        # Itera a través de los fragmentos de respuesta e imprime el contenido.
        for chunk in message:
            try:
                if (type(chunk) == ResponseChoice):
                    logger.info(chunk.message.content)
                if (type(chunk) == dict and len(chunk) > 0):
                    logger.info(chunk[1]["content"])
                if type(chunk) == str:
                    logger.info(chunk)
            except Exception as e:
                logger.warning(f"La excepcion es de tipo {type(e)}")
                logger.error(e)
                pass  # Ignora los errores en el procesamiento de fragmentos.

    # Ejecuta la llamada a la función y obtiene su salida.
    @timer
    def process_nmap_reconnaissance(self, historial):
        """
        Ejecuta la llamada a nmap para hacer un reconocimiento inicial, puede que se ejecute a la vez wireshark.
        Proporcionaremos la salida de la funcion al llm para que nos de su opinión. Antes de invocar a la funcion,
        vamos a inicializar al llm para que sepa lo que viene.
        """
        target_ip_range = historial[-1].get("USER")
        self.initialize_recoinassance_agent_prompt()
        # Crea una instancia de la clase NmapTool
        function_output = self.execute_function_call_recoinassance(target_ip_range)

        historial_json = self.process_history_with_function_output(
            historial, function_output
        )
        message = self.invoke_model_with_chunks(historial_json)

        # Itera a través de los fragmentos de respuesta e imprime el contenido.
        for chunk in message:
            try:
                if (type(chunk) == ResponseChoice):
                    logger.info(chunk.message.content)
                if (type(chunk) == dict and len(chunk) > 0):
                    logger.info(chunk[1]["content"])
                if type(chunk) == str:
                    logger.info(chunk)
            except Exception as e:
                logger.warning(f"La excepcion es de tipo {type(e)}")
                logger.error(e)
                pass  # Ignora los errores en el procesamiento de fragmentos.

    @timer
    def process_nmap_ports_systems_services(self, historial):
        target_ip_range = historial[-1].get("USER")
        self.initialize_ports_systems_services_agent_prompt()
        # Crea una instancia de la clase NmapTool
        function_output = self.execute_function_call_nmap_ports_systems_services(
            target_ip_range
        )

        historial_json = self.process_history_with_function_output(
            historial, function_output
        )

        message = self.invoke_model_with_chunks(historial_json)

        # Itera a través de los fragmentos de respuesta e imprime el contenido.
        for chunk in message:
            try:
                if (type(chunk) == ResponseChoice):
                    logger.info(chunk.message.content)
                if (type(chunk) == dict and len(chunk) > 0):
                    logger.info(chunk[1]["content"])
                if type(chunk) == str:
                    logger.info(chunk)
            except Exception as e:
                logger.warning(f"La excepcion es de tipo {type(e)}")
                logger.error(e)
                pass  # Ignora los errores en el procesamiento de fragmentos.

    @timer
    def process_nmap_ports_services_vulnerabilities(self, historial):
        target_ip_range = historial[-1].get("USER")
        self.initialize_ports_services_vulns_agent_prompt()
        # Crea una instancia de la clase NmapTool
        function_output = (
            self.execute_function_call_nmap_ports_services_vulnerabilities(
                target_ip_range
            )
        )

        historial_json = self.process_history_with_function_output(
            historial, function_output
        )

        message = self.invoke_model_with_chunks(historial_json)

        # Itera a través de los fragmentos de respuesta e imprime el contenido.
        for chunk in message:
            try:
                if (type(chunk) == ResponseChoice):
                    logger.info(chunk.message.content)
                if (type(chunk) == dict and len(chunk) > 0):
                    logger.info(chunk[1]["content"])
                if type(chunk) == str:
                    logger.info(chunk)
            except Exception as e:
                logger.warning(f"La excepcion es de tipo {type(e)}")
                logger.error(e)
                pass  # Ignora los errores en el procesamiento de fragmentos.

    @timer
    def process_deHashed_Call(self, historial):
        function_output = self.execute_function_call(historial[-1].get("USER", ""))
        historial_json = self.process_history_with_function_output(
            historial, function_output
        )
        # Genera una respuesta del modelo.
        respuesta = self.openai_client.chat.completions.create(
            model=self.model_name,
            temperature=self.temperature,
            messages=historial_json,
            stream=True,
        )
        # Itera a través de los fragmentos de respuesta e imprime el contenido.
        for chunk in respuesta:
            try:
                logger.info(chunk.choices[0].delta.content or "\n", end="")
            except Exception as e:
                logger.warning("La excepcion es de tipo {}".format(type(e)))
                logger.error(e)
                pass  # Ignora los errores en el procesamiento de fragmentos.
