# check if the client is connected to the server
import sys
from myadmin import admin_main
from myclient import get, voting_client
from myregistrar import reg_main
from my_utils import DEFAULT_HOST, DEFAULT_TIMEOUT, _maybe_load_keys_env

# Load any keys specified in environment variables
_maybe_load_keys_env()

if get(DEFAULT_HOST, timeout=DEFAULT_TIMEOUT) is None:
    print("The Voting server is not running @", DEFAULT_HOST)
    sys.exit(2)
print("Electronic voting system connected to -", DEFAULT_HOST)
print("Please Login")
print("1. Student")
print("2. Admin")
print("3. Registrar")
print("Enter X to close")
userinput = input("Please make a choice: ").strip()  

while userinput != "X":
    if userinput == "1":
        voting_client(timeout=DEFAULT_TIMEOUT)
    elif userinput == "2":
        admin_main()
    elif userinput == "3":
        reg_main()
    else:
        print("Invalid choice. Please try again.")

    print("\n-----------------\n")
    print("Please Login")
    print("1. Student")
    print("2. Admin")
    print("3. Registrar")
    print("Enter X to close")
    userinput = input("Please make a choice: ").strip()  