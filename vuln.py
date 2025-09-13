import pickle
import subprocess

# CRITICAL - Désérialisation dangereuse
def load_data(user_data):
    return pickle.loads(user_data)  # Exécution de code possible

# HIGH - Secret en dur  
database_password = "admin123"  # Mot de passe exposé

# HIGH - Injection de commandes
def run_command(user_input):
    cmd = f"ls {user_input}"
    subprocess.run(cmd, shell=True)  # Injection possible

print("Test avec vulnérabilités")
