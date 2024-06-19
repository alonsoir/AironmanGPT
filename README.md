![banner](https://i.imgur.com/U1BLTRf.png)

# Installation Guide for AironmanGPT Project

AironmanGPT also known as Jarvis is an artificial intelligence assistant based on the initial work from @luijait 
designed to perform pentesting tasks. 

The initial philosophy is to launch applications for each of the different phases, running wireshark/tshark at the 
same time to combine the two outputs and add them as input to the LLM, so that each output will give you its opinion. 

For now, in the initial phases I am using nmap with different parameters, along with wireshark. 

The system prompt for now only expects you to tell it the objective to investigate, which can be an IP or a range of IPs. 

The app expects you to have both some dependencies like nmap, wireshark and more to be installed on your system. 

The app lets you to run commands from your system and output the results to the llm. Just run command=your-command.

The app lets you to run command from your system and NOT output to the llm. Just run a command and see the results.

The app lets you to target a specific ip/range, which is the one that you want to scan. Basically it will run a bunch
of commands, output to the llm each output to feed it and give you the results. Just run target=your-target.

At some point I will create a make file to have all the dependencies ready. DONE!

At some point I will create a web interface to see the results, as well as to be able to properly export the results.

This guide will help you set up and run the project on your local environment.

## Prerequisites

   Before starting, make sure you have Python installed on your system. 
   This project has been tested with Python 3.10 
   and higher versions.
   Make sure you have docker installed on your system.
   nmap 
   wireshark
   curl

## Environment Setup

1. **Clone the Repository**

   First, you need to clone the GitHub repository to your local machine. You can do this by executing the following 
   command in your terminal:

```shell
  git clone https://github.com/alonsoir/AironmanGPT.git
```
```shell
  cd AironmanGPT
```

2. **Configure Environment Variables**
   
   Copy the `.example.env` file to 
   a new file named `.env`:

   You will need to set up some environment variables for the script to work correctly. 
   I had problems running the container with this format:

      OPENAI_API_KEY="API_KEY from openai.com"

   so i recommend you to use the following format, without double quotes:

```env
   DEHASHED_API_KEY=your_dehashed_api_key_here
   DEHASHED_USERNAME=your_dehashed_username
   OPENAI_API_KEY=API_KEY from openai.com
   GPT_MODEL_NAME=gpt-4-turbo-preview
   GPT_MODEL_NAME_TEST=babbage-002
```

4. **Install Dependencies**

   This project requires certain Python packages to run. Install them by running the following command:

```shell
  poetry shell
  poetry install  
```
5. Then Run the project:
```shell
  poetry run python main.py
```
6. (Optional) build the image and container:
```shell
  docker build -t aironman/aironmangpt:0.0.1 .
```
7. (Optional) run container:
```shell
  docker run -it --env-file .env aironman/aironmangpt:0.0.1
```

8. (Optional) run container:
```shell
  docker-compose run aironmangpt
```

9. (Optional, from scratch) use makefile:
```shell
  make all
```

10. (Optional, from scratch) build and run the container:
```shell
  make container-build container-run
```

DeHashed API Key (Optional, not tested yet)
1. Sign Up or Log In: Visit the DeHashed website (https://www.dehashed.com/). If you don't already have an account, 
you'll need to sign up. If you do, just log in.
2. Subscription: DeHashed is a paid service, so you'll need to subscribe to one of their plans to get access to the API. 
Choose a plan that fits your needs and complete the subscription process.
3. Accessing the API Key: Once you've subscribed, you can usually find your API key in your account settings or 
dashboard. Look for a section labeled "API" or something similar. If you're having trouble finding it, DeHashed's 
support or documentation might be able to help.
4. Security: Keep your API key secure. Don't share it with others or expose it in public code repositories.
 
OpenAI API Key
1. Sign Up or Log In: Go to the OpenAI website (https://openai.com/). You'll need to create an account if you don't 
have one, or log in if you do.
3. Getting the API Key: Once you have been granted access, you can find your API key in your OpenAI account dashboard. 
There should be a section for API keys or developer settings (https://platform.openai.com/api-keys).
4. Usage and Billing: Be aware of OpenAI's usage and billing policies. 
Depending on the volume of your requests and the specific models you use, you might incur charges. Plan accordingly and 
monitor your usage.
5. Security: As with any API key, it's crucial to keep your OpenAI key secure. Do not share it publicly or with anyone 
who should not have access to it.

6. General Tips for Managing API Keys:
Environment Variables: Store your API keys in environment variables rather than hard-coding them into your project. 
This makes your application more secure and flexible.

7. .gitignore: If you're using Git, ensure your .env file or any file containing API keys is listed in your .gitignore 
file to prevent it from being uploaded to a public repository.

8. Documentation: Always refer to the official documentation of the API provider for the most accurate and up-to-date 
information on obtaining and using API keys.

9. By following these steps and guidelines, you'll be able to obtain the necessary API keys to integrate DeHashed and 
OpenAI services into your projects.

GPT4All (Optional, in progress)

The idea is to be able to use autonomous agents for each of the phases of a pentesting operation. 
To do this, an LLM will be used that interacts with each of the invocations of said agents and collects the inputs and 
outputs in a coherent and appropriate manner.
To do this, I will try to use GPT4All to use some LLM that is not restricted by its original authors so that I can use 
these tools without restrictions.