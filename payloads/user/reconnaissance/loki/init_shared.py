#init_shared.py
# Description:
# This file, init_shared.py, is responsible for initializing and providing access to shared data across different modules in the Bjorn project.
#
# Key functionalities include:
# - Importing the `SharedData` class from the `shared` module.
# - Creating an instance of `SharedData` named `shared_data` that holds common configuration, paths, and other resources.
# - Ensuring that all modules importing `shared_data` will have access to the same instance, promoting consistency and ease of data management throughout the project.

# Add local lib directory to Python path for self-contained payload
import sys
import os
_lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib')
if os.path.exists(_lib_path) and _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

# Fix OpenSSL legacy provider issue for cryptography/paramiko
os.environ['CRYPTOGRAPHY_OPENSSL_NO_LEGACY'] = '1'

from shared import SharedData

shared_data = SharedData()
