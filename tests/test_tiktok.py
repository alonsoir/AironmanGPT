import tiktoken

# Asegúrate de usar el tokenizador adecuado para el modelo GPT-4 Turbo
tokenizer = tiktoken.get_encoding("cl100k_base")

# Texto de ejemplo para tokenización
sample_text = "Este es un texto de prueba para verificar la tokenización."

# Tokenización
tokens = tokenizer.encode(sample_text)
print(f"Tokens: {tokens}")

# Decodificación
decoded_text = tokenizer.decode(tokens)
print(f"Decoded Text: {decoded_text}")

# Verifica que el texto decodificado sea igual al texto original
assert decoded_text == sample_text, "Error: La decodificación no coincide con el texto original."
