import os
import subprocess

user_input = input("Enter a command: ")

# Command injection possible
os.system(user_input)

# Ou avec subprocess
subprocess.run(user_input, shell=True)
