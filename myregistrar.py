#!/usr/bin/env python3
"""
Registrar CLI: register voters and set options before the election opens.

This script talks to the server on localhost:5000 and provides simple
commands:
- add     : register a voter (allowed while election closed)
- list-voters                : fetch and print registered voters
- show-options               : fetch and print options

"""

import sys
import requests

BASE_URL = "http://localhost:5000"


def add_voter(voter_id, name):
    url = f"{BASE_URL}/register"
    payload = {"voter_id": voter_id, "name": name}
    resp = requests.post(url, json=payload, timeout=5)
    resp.raise_for_status()
    print("registered:", resp.json() if resp.content else resp.text)


def list_voters():
    url = f"{BASE_URL}/voters"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    print(resp.json())


def show_options():
    url = f"{BASE_URL}/options"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    print("these are the option to vote from: ", resp.json().get("options", []))


def usage_and_exit():
    print("Usage: myregistrar.py add <voter_id> <name> | set-options <opt1> [opt2].. | list-voters | show-options")
    sys.exit(2)


def reg_main():
    print("\nLogged in as Registrar.")
    print("1. Register a student voter")
    print("2. List registered voters")
    print("3. List available options to be voted on")
    print("4. exit")

    userInput = input("Please make a choice: ").strip() #handling issues where user inputs spaces before or after the input

    if userInput == "1":
        voter_id = input("Enter voter ID: ")
        name = input("Enter voter name: ")
        try:
            add_voter(voter_id, name)
        except requests.HTTPError as he:
            print("HTTP error:", he.response.status_code, he.response.text)
        except Exception as e:
            print("error:", e)
    elif userInput == "2":
        try:
            list_voters()
        except requests.HTTPError as he:
            print("HTTP error:", he.response.status_code, he.response.text)
        except Exception as e:
            print("error:", e)
    elif userInput == "3":
        try:
            show_options()
        except requests.HTTPError as he:
            print("HTTP error:", he.response.status_code, he.response.text)
        except Exception as e:
            print("error:", e)
    elif userInput == "4":
        print("Logged out Goodbye!")
        return
    else:
        print("Invalid choice. Please try again.")
        return  
