import subprocess
import pickle

def unsafe_command(user_input):
    """CRITICAL - Command Injection"""
    cmd = f"ls {user_input}"
    subprocess.run(cmd, shell=True)  # Vulnérabilité !

def unsafe_pickle(data):
    """CRITICAL - Insecure Deserialization"""  
    return pickle.loads(data)  # Vulnérabilité !

def hardcoded_secret():
    """HIGH - Hardcoded Credentials"""
    password = "admin123"  # Vulnérabilité !
    return password

if __name__ == "__main__":
    unsafe_command("../")
    unsafe_pickle(b"test")
    print(hardcoded_secret())