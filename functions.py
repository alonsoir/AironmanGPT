Leak_Function = (
    [
        {
            "name": "dehashed-search",
            "description": "You will use this whenever the query is related to any type of action related to the investigation of persons or entities of any kind.",
            "parameters": {
                "type": "object",
                "properties": {
                    "mail": {
                        "type": "string",
                        "description": "The mail/domain to search, if not full mail is provided, take the domain",
                    },
                    "nickname": {
                        "type": "string",
                        "description": "The nickname to search",
                    },
                },
                "required": [
                    "mail",
                    "nickname",
                ],  # Puedes añadir los parametros que quieras
            },
        },
    ],
)
"""
Identificación del objetivo: Nmap
Reconocimiento: Nmap, Netdiscover
Enumeración de puertos: Nmap, Netdiscover
Escaneo de vulnerabilidades: Nmap, OpenVAS, Metasploit, Nessus
Exploitación de vulnerabilidades: Metasploit, Cobalt Strike
Escalado de privilegios: Metasploit, Cobalt Strike
Reconocimiento de sistema: Nmap, Netdiscover, Nessus, OpenVAS
Análisis de actividad: Sysmon, Splunk, ELK
Conexión lateral: Cobalt Strike, Metasploit
Carga útil: Cobalt Strike, Metasploit
"""
Target_Identification_Reconnaissance = (
    [
        {
            "name": "nmap",
            "description": "Nmap is a network security scanning program used to identify and map devices on a network. "
            "In the different phases of OSINT, Nmap can be used as follows:"
            "Reconnaissance: In this phase, "
            "the agent should use Nmap to identify and map devices on the network. "
            "This includes port scanning, service version analysis, and operating system recognition. "
            "The agent should run Nmap in different scanning modes, such as quick discovery mode, "
            "full scan mode, and specific port scan mode, "
            "to get an overview of the network and its devices."
            "Analysis: Once the network and its devices have been identified, the agent should use Nmap to "
            "analyze the scan results. This includes analyzing versions of services and operating systems, "
            "searching for known vulnerabilities, and identifying non-standard services. "
            "The agent should also use additional scanning tools, such as Nessus or Metasploit, "
            "to obtain more information about the identified vulnerabilities."
            "Exploitation: In this phase, the agent should use Nmap to exploit the identified "
            "vulnerabilities in the devices on the network. "
            "This may include executing brute force attacks, executing code injection attacks."
            "You will use this tool whenever the query is related to any type of action related to the "
            "identification of targets or entities of any kind.",
            "parameters": {
                "type": "object",
                "properties": {
                    "script_args": {
                        "type": "string",
                        "description": "Arguments to pass to the script",
                    },
                    "file_Reconnaissance.nmap": {
                        "type": "string",
                        "description": "The generated nmap generated file",
                    },
                    "TARGET_IP_RANGE": {
                        "type": "string",
                        "description": "ip range to scan",
                    },
                },
                "required": [
                    "file_Reconnaissance.nmap",
                    "TARGET_IP_RANGE",
                ],  # Puedes añadir los parametros que quieras
            },
        },
    ],
)
