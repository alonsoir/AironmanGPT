import time


def timer(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Function {func.__name__} took {elapsed_time:.4f} seconds to execute.")
        return result

    return wrapper


# Función para convertir la cadena a booleano
def str_to_bool(value):
    return value.lower() in ("true", "1", "t", "y", "yes")
