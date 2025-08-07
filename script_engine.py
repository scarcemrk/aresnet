import os
import importlib.util

def load_scripts(script_dir="scripts"):
    scripts = []
    for file in os.listdir(script_dir):
        if file.endswith(".py"):
            path = os.path.join(script_dir, file)
            spec = importlib.util.spec_from_file_location(file[:-3], path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            scripts.append(module)
    return scripts

def run_scripts(ip, port, banner):
    results = []
    scripts = load_scripts()
    for script in scripts:
        try:
            result = script.run(ip, port, banner)
            if result:
                results.append(result)
        except Exception as e:
            results.append(f"[SCRIPT ERROR] {script.__name__} failed on {ip}:{port} - {e}")
    return results