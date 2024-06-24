"""
!pip install flask-ngrok

!ngrok authtoken <KEY>

!pip install transformers torch sentencepiece

"""

from flask import Flask, request, jsonify
from flask_ngrok import run_with_ngrok
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

app = Flask(__name__)
run_with_ngrok(app)  # Inicia ngrok cuando inicias la app

# Load model directly
from transformers import AutoTokenizer, AutoModelForCausalLM

tokenizer = AutoTokenizer.from_pretrained("0dAI/0dAI-7B")
model = AutoModelForCausalLM.from_pretrained("0dAI/0dAI-7B")

# Usar el modelo en GPU si está disponible
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)


@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json()
    prompt = data.get("prompt", "")

    # Tokenizar el prompt y mover los tensores a la GPU si está disponible
    inputs = tokenizer(prompt, return_tensors="pt").to(device)

    # Generar texto con el modelo
    generate_ids = model.generate(inputs.input_ids, max_length=30)

    # Decodificar el texto generado
    generated_text = tokenizer.batch_decode(
        generate_ids, skip_special_tokens=True, clean_up_tokenization_spaces=False
    )[0]
    return jsonify({"generated_text": generated_text})


if __name__ == "__main__":
    app.run()
