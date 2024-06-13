# Import necessary libraries
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)
from datasets import Dataset
import numpy as np
import time

# Load the pre-trained model and tokenizer
model_name = "segolilylabs/Lily-Cybersecurity-7B-v0.2"
model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
tokenizer = AutoTokenizer.from_pretrained(model_name)


# Function to prepare the dataset
def prepare_dataset(data):
    dataset = Dataset.from_dict(data)
    tokenized_datasets = dataset.map(tokenize_function, batched=True)
    return tokenized_datasets


# Tokenize the dataset
def tokenize_function(examples):
    return tokenizer(examples["text"], padding="max_length", truncation=True)


# Define Training Arguments
training_args = TrainingArguments(
    output_dir="./results",  # Directory where the model predictions and checkpoints will be written.
    num_train_epochs=3,  # Total number of training epochs.
    per_device_train_batch_size=8,  # Batch size per device during training.
    per_device_eval_batch_size=8,  # Batch size for evaluation.
    warmup_steps=500,  # Number of warmup steps for learning rate scheduler.
    weight_decay=0.01,  # Strength of weight decay.
    logging_dir="./logs",  # Directory for storing logs.
    logging_steps=10,  # Log every X updates steps.
    evaluation_strategy="steps",  # Evaluation is done (and logged) every X steps.
    eval_steps=100,  # Evaluation and logging happen every 100 steps.
    save_steps=1000,  # Model checkpoint is saved every 1000 steps.
    load_best_model_at_end=True,
    # The model checkpoint with the best performance will be loaded at the end of training.
)

# Initial training with the first dataset
initial_data = {
    "text": [
        "example of network log 1",
        "example of network log 2",
        "example of network log 3",
    ],
    "label": [0, 1, 0],  # 0 for benign, 1 for malicious
}
tokenized_datasets = prepare_dataset(initial_data)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_datasets,
    eval_dataset=tokenized_datasets,  # Assuming the same dataset for simplicity; ideally, use a separate eval dataset.
)

trainer.train()

# Continuous Learning Loop
while True:
    # Assume new_data is fetched from somewhere periodically
    new_data = {
        "text": ["new example 1", "new example 2", "new example 3"],
        "label": [0, 1, 0],  # Update with new data labels
    }

    # Prepare the new dataset
    tokenized_new_data = prepare_dataset(new_data)

    # Update the trainer with the new dataset
    trainer.train_dataset = tokenized_new_data
    trainer.eval_dataset = tokenized_new_data

    # Retrain the model with the new dataset
    print("Retraining model with new data...")
    trainer.train()

    # Wait for a specified time interval before fetching new data again
    # time.sleep(24 * 3600)  # For example, wait for one day (24 hours * 3600 seconds/hour)
