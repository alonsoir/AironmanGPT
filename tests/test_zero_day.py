from transformers import AutoTokenizer, AutoModelForCausalLM, AutoConfig

model_name = "0dAI/0dAI-7B"
# Cargar el tokenizer
tokenizer = AutoTokenizer.from_pretrained(model_name)

# Cargar la configuración del modelo sin cuantización
config = AutoConfig.from_pretrained(model_name)

# Cargar el modelo con la configuración modificada
model = AutoModelForCausalLM.from_pretrained(model_name, config=config)

prompt = "Hey, are you conscious? Can you talk to me?"

inputs = tokenizer(prompt, return_tensors="pt")

generate_ids = model.generate(inputs.input_ids, max_length=30)

print(tokenizer.batch_decode(generate_ids, skip_special_tokens=True, clean_up_tokenization_spaces=False)[0])
