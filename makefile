all: setup container-build container-run size

setup: requirements install_python install validate_python_libs

code:
	poetry run code .

pycharm:
	poetry run pycharm .

# run -------------------------------

run:
	docker run -it --env-file .env aironman/aironmangpt:latest

# Dependency utils -------------------------------

install_python:
	pyenv install $$(cat .python-version) -s

requirements:
	which docker
	which pyenv
	which poetry

validate_python_libs:
	poetry run python3 -c "import streamlit as st; print('Version de Streamlit:', st.__version__)";
	poetry run python3 -c "import embedchain as ec; print('Version de EmbedChain:', ec.__version__)";

# Python libraries ----------------------------------------

update:
	poetry update

install:
	poetry install --no-root

show:
	poetry show

info:
	poetry run poetry env info -p

delete:
	poetry env remove python

size:
	@echo "Size of Python virtual environment"
	@du -sh $(poetry run poetry env info --path 2>/dev/null)

# Container targets ------------------------------------------

CONTAINER_IMAGE=aironman/aironmangpt:latest

# build the container image
container-build:
	@echo "Building container image"
	docker build -f Dockerfile -t aironman/aironmangpt:0.0.1 .
container-run:
	docker run -it --env-file .env aironman/aironmangpt:0.0.1