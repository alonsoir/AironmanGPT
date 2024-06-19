import subprocess
import sys
import time

from loguru import logger

from tools.tools import timer


class NetworkScanner:
    def __init__(
            self,
            interface,
            target_network,
            nmap_output_file,
            pcap_output_file,
            initial_wait=5,
            capture_duration=30,
    ):
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
        wireshark_cmd = (
            f"tshark -i {self.interface} -w {self.pcap_output_file} {filter_expression}"
        )
        self.wireshark_process = subprocess.Popen(wireshark_cmd, shell=True)

    def stop_wireshark_capture(self):
        # Detener la captura de tráfico en tiempo real
        if self.wireshark_process:
            self.wireshark_process.terminate()
            self.wireshark_process = None

    @timer
    def run_bash_command(self, command):
        try:
            logger.info(f"Ejecutando comando: {command}")
            resultado = subprocess.run(
                command, shell=True, capture_output=True, text=True
            )
            return resultado.stdout
        except Exception as e:
            return str(e)

    @timer
    def run_python_command(self, comando):
        import subprocess
        logger.info(f"Ejecutando comando: {comando}")

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
        logger.info("Iniciando captura de tráfico en tiempo real con Wireshark...")
        self.start_wireshark_capture()

        # Esperar un momento para asegurarse de que Wireshark ha comenzado la captura
        time.sleep(self.initial_wait)

        logger.info(f"Ejecutando escaneo de Nmap en {self.target_network}...")
        self.run_nmap_scan()
        logger.info(
            "Escaneo de Nmap completado. Resultados guardados en", self.nmap_output_file
        )

        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.capture_duration)

        logger.info("Deteniendo captura de tráfico en tiempo real...")
        self.stop_wireshark_capture()
        logger.info(
            "Captura de tráfico en tiempo real detenida. Archivo guardado como",
            self.pcap_output_file,
        )

    @timer
    def analyze_pcap(self, header, target_ip_range, analysis_type="tcp"):
        analysis_cmds = {
            "raw": f"tshark -r {self.pcap_output_file} >| {self.pcap_output_file}_raw.txt",
            "tcp": f'tshark -r {self.pcap_output_file} -Y "ip.src == {target_ip_range}" -T fields -e ip.src -e ip.dst '
                   f'-e tcp.srcport -e tcp.dstport -e tcp.stream -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.fin '
                   f'-e tcp.flags.urg >| {self.pcap_output_file}_tcp.txt',
            "http": f'tshark -r {self.pcap_output_file} -Y "http && ip.src == {target_ip_range}" -T fields -e ip.src '
                    f'-e ip.dst -e http.host -e http.request.uri -e http.user_a'
                    f'gent >| {self.pcap_output_file}_http.txt',
            "dns": f'tshark -r {self.pcap_output_file} -Y "dns && ip.src == {target_ip_range}" -T fields -e ip.src -e '
                   f'dns.qry.name >| {self.pcap_output_file}_dns.txt',
            "icmp": f'tshark -r {self.pcap_output_file} -Y "icmp && ip.src == {target_ip_range}" -T fields -e ip.src '
                    f'-e ip.dst -e icmp.type -e icmp.code >| {self.pcap_output_file}_icmp.txt',
        }

        if analysis_type in analysis_cmds:
            rm_command = f"rm {self.pcap_output_file}_raw.txt"
            result = self.dispatch_tool("bash", rm_command)
            logger.info(result)
            tshark_cmd = analysis_cmds[analysis_type]
            logger.info(
                f"Ejecutando análisis de tipo {analysis_type}\n header is {header}\n target_ip_range is {target_ip_range}\n"
            )
            logger.info(f"command is {tshark_cmd}\n")
            result = self.dispatch_tool("bash", tshark_cmd)
            logger.info(header + result)
            return header + result
        else:
            logger.info(f"Tipo de análisis no soportado: {analysis_type}")

    @timer
    def capture_then_dispatch_nmap_reconnaissance(self, target_ip_range):
        # Iniciar Wireshark, luego ejecutar Nmap
        logger.info("Iniciando capture_then_dispatch_nmap_reconnaissance...")
        self.pcap_output_file = f"./tools/file_wireshark_dispatch_nmap_reconnaissance-{target_ip_range}.pcap"
        self.start_wireshark_capture()

        # Esperar un momento para asegurarse de que Wireshark ha comenzado la captura
        time.sleep(self.initial_wait)
        file_to = "./tools/file_nmap_reconnaissance.nmap"
        command = f"nmap -T4 -sT -sV -sC --top-ports 1000 -oN {file_to} --open --version-trace --script-timeout 10000 {target_ip_range}"
        logger.info(f"Running {command}\n")
        header = f"capture_then_dispatch_nmap_reconnaissance. {target_ip_range}\n"
        capture_then_dispatch_nmap_reconnaissance = header + self.dispatch_tool(
            "bash", command
        )
        logger.info(f"Waiting for {self.initial_wait} seconds...\n")
        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.initial_wait)

        logger.info("Deteniendo captura de tráfico en tiempo real...")
        self.stop_wireshark_capture()
        logger.info(
            "Captura de tráfico en tiempo real detenida. Archivo guardado como",
            self.pcap_output_file,
        )
        header = f"capture_then_dispatch_nmap_reconnaissance_raw.{target_ip_range}\n"
        raw = self.analyze_pcap(header, target_ip_range, "raw")
        logger.info(f"Waiting for {self.initial_wait} seconds...\n")
        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.initial_wait)
        header = f"capture_then_dispatch_nmap_reconnaissance_tcp.{target_ip_range}\n"
        tcp = self.analyze_pcap(header, target_ip_range, "tcp")
        logger.info(f"Waiting for {self.initial_wait} seconds...\n")
        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.initial_wait)
        header = f"capture_then_dispatch_nmap_reconnaissance_http.{target_ip_range}\n"
        http = self.analyze_pcap(header, target_ip_range, "http")
        logger.info(f"Waiting for {self.initial_wait} seconds...\n")
        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.initial_wait)
        header = f"capture_then_dispatch_nmap_reconnaissance_dns.{target_ip_range}\n"
        dns = self.analyze_pcap(header, target_ip_range, "dns")
        logger.info(f"Waiting for {self.initial_wait} seconds...\n")
        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.initial_wait)
        header = f"capture_then_dispatch_nmap_reconnaissance_icmp.{target_ip_range}\n"
        icmp = self.analyze_pcap(header, target_ip_range, "icmp")
        logger.info(f"Waiting for {self.initial_wait} seconds...\n")
        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.initial_wait)
        final_output = (
                capture_then_dispatch_nmap_reconnaissance
                + "\n"
                + raw
                + "\n"
                + tcp
                + "\n"
                + http
                + "\n"
                + dns
                + "\n"
                + icmp
        )
        return final_output

    @timer
    def capture_then_dispatch_nmap_ports_systems_services(self, target_ip_range):
        # Iniciar Wireshark, luego ejecutar Nmap
        logger.info("Iniciando capture_then_dispatch_nmap_ports_systems_services...")
        self.pcap_output_file = f"./tools/file_wireshark_dispatch_nmap_ports_systems_services-{target_ip_range}.pcap"
        self.start_wireshark_capture()

        # Esperar un momento para asegurarse de que Wireshark ha comenzado la captura
        time.sleep(self.initial_wait)
        file_to = "./tools/file_nmap_ports_systems_services.nmap"
        command = f"nmap -sT -T4 -p- {target_ip_range} -oN {file_to}"
        logger.info(f"Running {command}\n")
        logger.info("Be patient please...\n")
        header = (
            f"capture_then_dispatch_nmap_ports_systems_services.{target_ip_range}\n"
        )
        capture_then_dispatch_nmap_ports_systems_services = header + self.dispatch_tool(
            "bash", command
        )

        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.capture_duration)

        logger.info("Deteniendo captura de tráfico en tiempo real...")
        self.stop_wireshark_capture()
        logger.info(
            "Captura de tráfico en tiempo real detenida. Archivo guardado como",
            self.pcap_output_file,
        )

        header = (
            f"capture_then_dispatch_nmap_ports_systems_services_tcp.{target_ip_range}\n"
        )
        tcp = self.analyze_pcap(header, target_ip_range, "tcp")

        header = f"capture_then_dispatch_nmap_ports_systems_services_http.{target_ip_range}\n"
        http = self.analyze_pcap(header, target_ip_range, "http")

        header = (
            f"capture_then_dispatch_nmap_ports_systems_services_dns.{target_ip_range}\n"
        )
        dns = self.analyze_pcap(header, target_ip_range, "dns")

        header = f"capture_then_dispatch_nmap_ports_systems_services_icmp.{target_ip_range}\n"
        icmp = self.analyze_pcap(header, target_ip_range, "icmp")

        final_output = (
                capture_then_dispatch_nmap_ports_systems_services
                + "\n"
                + tcp
                + "\n"
                + http
                + "\n"
                + dns
                + "\n"
                + icmp
        )

        return final_output

    @timer
    def capture_then_dispatch_nmap_ports_services_vulnerabilities(
            self, target_ip_range
    ):
        # Iniciar Wireshark, luego ejecutar Nmap
        logger.info("Iniciando capture_then_dispatch_nmap_ports_services_vulnerabilities...")
        self.pcap_output_file = f"./tools/file_wireshark_dispatch_nmap_ports_services_vulnerabilities_{target_ip_range}.pcap"
        self.start_wireshark_capture()

        # Esperar un momento para asegurarse de que Wireshark ha comenzado la captura
        time.sleep(self.initial_wait)
        file_to = "./tools/file_nmap_ports_services_vulnerabilities.nmap"
        command = f"nmap -sT -sV --script vuln -T4 -p- {target_ip_range} -oN file_ports_services_vulnerabilities.nmap"
        logger.info(f"Running {command}\n")
        logger.info("Be patient please...\n")
        header = f"capture_then_dispatch_nmap_ports_services_vulnerabilities.{target_ip_range}\n"
        capture_then_dispatch_nmap_ports_services_vulnerabilities = (
                header + self.dispatch_tool("bash", command)
        )

        # Esperar un tiempo suficiente para capturar el tráfico después del escaneo
        time.sleep(self.capture_duration)

        logger.info("Deteniendo captura de tráfico en tiempo real...")
        self.stop_wireshark_capture()
        logger.info(
            "Captura de tráfico en tiempo real detenida. Archivo guardado como",
            self.pcap_output_file,
        )

        header = (
            f"capture_then_dispatch_nmap_ports_systems_services_tcp.{target_ip_range}\n"
        )
        tcp = self.analyze_pcap(header, target_ip_range, "tcp")

        header = f"capture_then_dispatch_nmap_ports_systems_services_http.{target_ip_range}\n"
        http = self.analyze_pcap(header, target_ip_range, "http")

        header = (
            f"capture_then_dispatch_nmap_ports_systems_services_dns.{target_ip_range}\n"
        )
        dns = self.analyze_pcap(header, target_ip_range, "dns")

        header = f"capture_then_dispatch_nmap_ports_systems_services_icmp.{target_ip_range}\n"
        icmp = self.analyze_pcap(header, target_ip_range, "icmp")

        final_output = (
                capture_then_dispatch_nmap_ports_services_vulnerabilities
                + "\n"
                + tcp
                + "\n"
                + http
                + "\n"
                + dns
                + "\n"
                + icmp
        )
        return final_output

    @timer
    def scan_then_capture(self):
        # Ejecutar Nmap, luego iniciar Wireshark
        logger.info(f"Ejecutando escaneo de Nmap en {self.target_network}...")
        self.run_nmap_scan()
        logger.info(
            "Escaneo de Nmap completado. Resultados guardados en", self.nmap_output_file
        )

        # Esperar un momento antes de iniciar la captura para permitir que Wireshark inicie
        time.sleep(self.initial_wait)

        logger.info("Iniciando captura de tráfico en tiempo real con Wireshark...")
        self.start_wireshark_capture()

        # Esperar un tiempo suficiente para capturar el tráfico
        time.sleep(self.capture_duration)

        logger.info("Deteniendo captura de tráfico en tiempo real...")
        self.stop_wireshark_capture()
        logger.info(
            "Captura de tráfico en tiempo real detenida. Archivo guardado como",
            self.pcap_output_file,
        )


# Ejemplo de uso
if __name__ == "__main__":
    interface = "en0"  # Reemplazar con tu interfaz de red adecuada (por ejemplo, en0, en1, etc.)
    target_network = "localhost"
    nmap_output_file = "nmap_scan_results.xml"
    pcap_output_file = "captura_trafico.pcap"

    # Parámetros de tiempo
    initial_wait = 5  # Tiempo de espera inicial antes de iniciar la siguiente acción
    capture_duration = 30  # Duración de la captura de tráfico en segundos

    scanner = NetworkScanner(
        interface,
        target_network,
        nmap_output_file,
        pcap_output_file,
        initial_wait,
        capture_duration,
    )

    # Opción 1: Capturar tráfico primero y luego ejecutar Nmap
    scanner.capture_then_scan()

    # Opción 2: Ejecutar Nmap primero y luego capturar tráfico
    scanner.scan_then_capture()
