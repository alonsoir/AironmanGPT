import subprocess
import sys
import time

from functools import wraps

from tools.tools import timer


class NetworkScanner:
    def __init__(self, interface, target_network, nmap_output_file, pcap_output_file, initial_wait=5,
                 capture_duration=30):
        self.interface = interface
        self.target_network = target_network
        self.nmap_output_file = nmap_output_file
        self.pcap_output_file = pcap_output_file
        self.initial_wait = initial_wait
        self.capture_duration = capture_duration
        self.wireshark_process = None

    def run_nmap_scan(self):
        # Ejecutar un escaneo de Nmap para descubrir dispositivos y servicios en la red objetivo
        nmap_cmd = f"nmap -sV -oX {self.nmap_output_file} {self.target_network}"
        subprocess.run(nmap_cmd, shell=True)

    def start_wireshark_capture(self, filter_expression=""):
        # Iniciar la captura de tráfico en tiempo real con Wireshark
        wireshark_cmd = f"tshark -i {self.interface} -w {self.pcap_output_file} {filter_expression}"
        self.wireshark_process = subprocess.Popen(wireshark_cmd, shell=True)

    def stop_wireshark_capture(self):
        # Detener la captura de tráfico en tiempo real
        if self.wireshark_process:
            self.wireshark_process.terminate()
            self.wireshark_process = None

    @timer
    def run_bash_command(self, command):
        try:
            resultado = subprocess.run(command, shell=True, capture_output=True, text=True)
            return resultado.stdout
        except Exception as e:
            return str(e)

    @timer
    def run_python_command(self, comando):
        import subprocess

        subprocess.run([sys.executable, "-c", comando])

    @timer
    def dispatch_tool(self, tool, params):
        if tool == "bash":
            return self.run_bash_command(params)
        elif tool == "python":
            return self.run_python_command(params)
        else:
            return "Herramienta no reconocida"

    @timer
    def capture_then_scan(self):
        # Iniciar Wireshark, luego ejecutar Nmap
        print("Iniciando captura de tráfico en tiempo real con Wireshark...")
        self.start_wireshark_capture()

        # Esperar un momento para asegurarse de que Wireshark ha comenzado la captura
        time.sleep(self.initial_wait)

        print(f"Ejecutando escaneo de Nmap en {self.target_network}...")
        self.run_nmap_scan()
        print("Escaneo de Nmap completado. Resultados guardados en", self.nmap_output_file)

        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.capture_duration)

        print("Deteniendo captura de tráfico en tiempo real...")
        self.stop_wireshark_capture()
        print("Captura de tráfico en tiempo real detenida. Archivo guardado como", self.pcap_output_file)

    @timer
    def capture_then_dispatch_nmap_reconnaissance(self, target_ip_range):
        # Iniciar Wireshark, luego ejecutar Nmap
        print("Iniciando capture_then_dispatch_nmap_reconnaissance...")
        self.pcap_output_file = "./tools/file_wireshark_dispatch_nmap_reconnaissance.pcap"
        self.start_wireshark_capture()

        # Esperar un momento para asegurarse de que Wireshark ha comenzado la captura
        time.sleep(self.initial_wait)
        file_to = "./tools/file_nmap_reconnaissance.nmap"
        command = f"nmap -T4 -sT -sV -sC --top-ports 1000 -oN {file_to} --open --version-trace --script-timeout 10000 {target_ip_range}"
        print(f"Running {command}\n")
        print("Be patient please...\n")
        dispatch_tool_output = self.dispatch_tool("bash", command)

        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.capture_duration)

        print("Deteniendo captura de tráfico en tiempo real...")
        self.stop_wireshark_capture()
        print("Captura de tráfico en tiempo real detenida. Archivo guardado como", self.pcap_output_file)

        return dispatch_tool_output

    @timer
    def capture_then_dispatch_nmap_ports_systems_services(self, target_ip_range):
        # Iniciar Wireshark, luego ejecutar Nmap
        print("Iniciando capture_then_dispatch_nmap_ports_systems_services...")
        self.pcap_output_file = "./tools/file_wireshark_dispatch_nmap_ports_systems_services.pcap"
        self.start_wireshark_capture()

        # Esperar un momento para asegurarse de que Wireshark ha comenzado la captura
        time.sleep(self.initial_wait)
        file_to = "./tools/file_nmap_ports_systems_services.nmap"
        command = f"nmap -sT -T4 -p- {target_ip_range} -oN {file_to}"
        print(f"Running {command}\n")
        print("Be patient please...\n")
        dispatch_nmap_ports_systems_services_output = self.dispatch_tool("bash", command)

        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.capture_duration)

        print("Deteniendo captura de tráfico en tiempo real...")
        self.stop_wireshark_capture()
        print("Captura de tráfico en tiempo real detenida. Archivo guardado como", self.pcap_output_file)

        return dispatch_nmap_ports_systems_services_output

    @timer
    def capture_then_dispatch_nmap_ports_services_vulnerabilities(self, target_ip_range):
        # Iniciar Wireshark, luego ejecutar Nmap
        print("Iniciando capture_then_dispatch_nmap_ports_services_vulnerabilities...")
        self.pcap_output_file = "./tools/file_wireshark_dispatch_nmap_ports_services_vulnerabilities.pcap"
        self.start_wireshark_capture()

        # Esperar un momento para asegurarse de que Wireshark ha comenzado la captura
        time.sleep(self.initial_wait)
        file_to = "./tools/file_nmap_ports_services_vulnerabilities.nmap"
        command = f"nmap -sT -sV --script vuln -T4 -p- {target_ip_range} -oN file_ports_services_vulnerabilities.nmap"
        print(f"Running {command}\n")
        print("Be patient please...\n")
        dispatch_nmap_ports_services_vulnerabilities_output = self.dispatch_tool("bash", command)

        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.capture_duration)

        print("Deteniendo captura de tráfico en tiempo real...")
        self.stop_wireshark_capture()
        print("Captura de tráfico en tiempo real detenida. Archivo guardado como", self.pcap_output_file)

        return dispatch_nmap_ports_services_vulnerabilities_output

    @timer
    def scan_then_capture(self):
        # Ejecutar Nmap, luego iniciar Wireshark
        print(f"Ejecutando escaneo de Nmap en {self.target_network}...")
        self.run_nmap_scan()
        print("Escaneo de Nmap completado. Resultados guardados en", self.nmap_output_file)

        # Esperar un momento antes de iniciar la captura para permitir que Wireshark inicie
        time.sleep(self.initial_wait)

        print("Iniciando captura de tráfico en tiempo real con Wireshark...")
        self.start_wireshark_capture()

        # Esperar un tiempo suficiente para capturar el tráfico
        time.sleep(self.capture_duration)

        print("Deteniendo captura de tráfico en tiempo real...")
        self.stop_wireshark_capture()
        print("Captura de tráfico en tiempo real detenida. Archivo guardado como", self.pcap_output_file)


# Ejemplo de uso
if __name__ == "__main__":
    interface = "en0"  # Reemplazar con tu interfaz de red adecuada (por ejemplo, en0, en1, etc.)
    target_network = "localhost"
    nmap_output_file = "nmap_scan_results.xml"
    pcap_output_file = "captura_trafico.pcap"

    # Parámetros de tiempo
    initial_wait = 5  # Tiempo de espera inicial antes de iniciar la siguiente acción
    capture_duration = 30  # Duración de la captura de tráfico en segundos

    scanner = NetworkScanner(interface, target_network, nmap_output_file, pcap_output_file, initial_wait,
                             capture_duration)

    # Opción 1: Capturar tráfico primero y luego ejecutar Nmap
    scanner.capture_then_scan()

    # Opción 2: Ejecutar Nmap primero y luego capturar tráfico
    scanner.scan_then_capture()
