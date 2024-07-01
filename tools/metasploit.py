import subprocess
import sys
import time

from loguru import logger

from tools.tools import timer

class Metasploit:

    def __init__(self):
        self.metasploit_cmd = "/opt/metasploit-framework/bin/msfconsole"

    @timer
    def run_bash_command(self, command):
        try:
            logger.info(f"Ejecutando comando: {command}")
            resultado = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            return resultado.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Error en la ejecución del comando: {e}")
            return f"Error en la ejecución del comando: {e}"
        except FileNotFoundError as e:
            logger.error(f"Comando no encontrado: {e}")
            return f"Comando no encontrado: {e}"

    @timer
    def run_msf_recon(self):
        command = f"{self.metasploit_cmd} -q -x 'db_import ./nmap/file_nmap_reconnaissance.xml; hosts; services; vulns; exit'"
        output = self.run_bash_command(command)
        return output

    @timer
    def run_msf_ports_systems_services(self):
        command = f"{self.metasploit_cmd} -q -x 'db_import ./nmap/file_nmap_ports_systems_services.xml; hosts; services; vulns; exit'"
        output = self.run_bash_command(command)
        return output

    @timer
    def run_msf_ports_services_vulns(self):
        command = f"{self.metasploit_cmd} -q -x 'db_import ./nmap/file_nmap_ports_services_vulnerabilities.xml; hosts; services; vulns; exit'"
        output = self.run_bash_command(command)
        return output
