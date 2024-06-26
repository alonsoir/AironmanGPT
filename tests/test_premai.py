import os

from premai import Prem
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("PREMAI_API_KEY")
client = Prem(api_key)

project_id = 540
# mythalion-13b
model = "remm-slerp-l2-13b"  # remm-slerp-l2-13b
system_prompt = "You are a helpful assistant."
session_id = "my-session"
temperature = 0.7
query = "Quien ganó el mundial de Sudafrica en 2010?"
messages_premai = [
    {"role": "user", "content": query},
]

response = client.chat.completions.create(
    project_id=project_id,
    messages=messages_premai,
    model=model,
    system_prompt=system_prompt,
    session_id=session_id,
    temperature=temperature,
)
print(query)
print(response.choices[0].message.content)
