import subprocess

# Import things that are needed generically
from langchain.pydantic_v1 import BaseModel, Field
from langchain.tools import BaseTool, StructuredTool, tool
from typing import Optional, Type, Any, Mapping

from langchain.callbacks.manager import (
    AsyncCallbackManagerForToolRun,
    CallbackManagerForToolRun,
)


class SearchInput(BaseModel):
    query: str = Field(description="should be a search query")


class NmapTool(BaseTool):
    name = "nmap tool"
    description = "This command performs a quick and complete scan of the network, identifying and mapping devices on the network."
    args_schema: Type[BaseModel] = SearchInput
    fileReconnaissance: Optional[Mapping[str, str]] = None
    target_ip_range: Optional[str] = None

    def _run(
        self, query: str, run_manager: Optional[CallbackManagerForToolRun] = None
    ) -> str:
        """Use the tool synchronously."""
        self.target_ip_range = query
        return self.runnmap()

    async def _arun(
        self, query: str, run_manager: Optional[AsyncCallbackManagerForToolRun] = None
    ) -> str:
        """Use the tool asynchronously."""
        self.target_ip_range = query
        return self.runnmap()

    def __init__(self, **data: Any):
        super().__init__(**data)
        self.fileReconnaissance = {"nmap": "./tools/file_Reconnaissance.nmap"}

    def runnmap(self):
        print(f"target ip range: {self.target_ip_range}")
        nmapargs = {
            "fileReconnaissance.nmap": self.fileReconnaissance.nmap,
            "TARGETIPRANGE": self.target_ip_range,
            "scriptargs": "-p- -sV -sC --top-ports 1000 --top-talked 1000 --script-trace --script-timeout 10000 --script-args '| nmap -p- -sV -sC --top-ports 1000 --top-talked 1000 --script-trace' {}".format(
                self.target_ip_range
            ),
        }
        # Construir el comando Nmap
        nmap_command = "nmap {scriptargs}".format(**nmapargs)

        try:
            # Ejecutar el comando Nmap y capturar la salida
            nmap_output = subprocess.check_output(
                nmap_command, shell=True, universal_newlines=True
            )
            return nmap_output
        except subprocess.CalledProcessError as e:
            return f"Error al ejecutar Nmap: {e.output}"
