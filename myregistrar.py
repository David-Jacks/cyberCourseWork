
import os
import requests
import base64
import json
from my_utils import DEFAULT_HOST, _maybe_load_keys_env, sign_ed25519, hash_id, encrypt_for_registrar, rsa_encrypt_to_b64, rsa_decrypt_from_b64
from Schnorr_ZKP import voter_public_key


# Register a voter with given voter_id and name
def add_voter(voter_id, name):
    url = f"{DEFAULT_HOST}/register"
    # Hash the voter id and encrypt the name for transport/storage
    voter_hash = None
    if hash_id is not None:
        voter_hash = hash_id(voter_id) 
    else:
        print("Error: hash_id function not available.")
        return

    # Encrypt the hashed voter id to the server so nothing raw is sent over the network.
    enc_voter_hash = None
    if rsa_encrypt_to_b64 is not None and os.environ.get("SERVER_PUB_KEY"):
        try:
            enc_voter_hash = rsa_encrypt_to_b64(os.environ.get("SERVER_PUB_KEY"), voter_hash.encode("utf-8"))
        except Exception:
            print("Err: failed to encrypt voter hash to server")
            return
        
    # Encrypt name for Registrar (so only Registrar can decrypt stored names)
    enc_name = None
    if encrypt_for_registrar is not None and os.environ.get("REGISTRAR_ENC_PUB_KEY"):
        try:
            # print(os.environ.get("REGISTRAR_ENC_PUB_KEY"))
            # print("i entered here")  
            enc_name = encrypt_for_registrar(os.environ.get("REGISTRAR_ENC_PUB_KEY"), name.encode("utf-8"))
        except Exception:
            print("Err: failed to encrypt name for registrar")
            return

    payload = {}
    
    if enc_voter_hash and enc_name:
        payload["enc_voter_hash"] = enc_voter_hash
        payload["enc_name"] = enc_name
        # schnorr support: include public key h if group configured
        try:
            # Do not generate or reveal the short secret here. If the
            # Schnorr group is configured, the server may generate a
            # short secret and return an encrypted secret for the
            # registrar to decrypt. We include no `h` and let the
            # server decide.
            p = os.environ.get("SCHNORR_P")
            g = os.environ.get("SCHNORR_G")
            q = os.environ.get("SCHNORR_Q")
            if p and g and q:
                pass
        except Exception:
            pass
    else:
        print("Error: encryption functions or keys issue.")
        return

    # Using the registrar's signing key to sign the payload
    headers = {}
    # Prefer explicit signing key, fall back to legacy names
    keypath = os.environ.get("REGISTRAR_SIGN_PRIV_KEY")
    payload_bytes = json.dumps(payload).encode("utf-8")
    if keypath and sign_ed25519 is not None:
        try:
            sig = sign_ed25519(keypath, payload_bytes)
            headers["X-Signature"] = base64.b64encode(sig).decode("ascii")
            headers["X-Signer"] = "registrar"
        except Exception as e:
            print("warning: failed to sign registration payload:", e)

    resp = requests.post(url, json=payload, timeout=5, headers=headers)
    resp.raise_for_status()
    # Prefer to decrypt an encrypted secret returned by the server
    try:
        parsed = resp.json() if resp.content else {}
    except Exception:
        parsed = {}
    # If server returned Schnorr group params, persist them and set env for client
    sch_group = parsed.get("sch_group") if isinstance(parsed, dict) else None
    if sch_group:
        try:
            os.environ.setdefault("SCHNORR_P", sch_group.get("p"))
            os.environ.setdefault("SCHNORR_Q", sch_group.get("q"))
            os.environ.setdefault("SCHNORR_G", sch_group.get("g"))
            # Persist to keys.env if present
            env_path = os.path.join(os.path.dirname(__file__), "keys", "keys.env")
            try:
                if os.path.exists(env_path):
                    with open(env_path, "r", encoding="utf-8") as f:
                        content = f.read()
                else:
                    content = ""
                to_append = []
                if "SCHNORR_P" not in content:
                    to_append.append(f"SCHNORR_P={sch_group.get('p')}")
                if "SCHNORR_Q" not in content:
                    to_append.append(f"SCHNORR_Q={sch_group.get('q')}")
                if "SCHNORR_G" not in content:
                    to_append.append(f"SCHNORR_G={sch_group.get('g')}")
                if to_append:
                    with open(env_path, "a", encoding="utf-8") as f:
                        f.write("\n" + "\n".join(to_append) + "\n")
                    print("Persisted SCHNORR_P/Q/G to keys/keys.env")
            except Exception:
                pass
            print("Registrar: received Schnorr group parameters and set them locally.")
        except Exception:
            pass

    enc_secret = parsed.get("enc_secret")
    if enc_secret and os.environ.get("REGISTRAR_ENC_PRIV_KEY"):
        try:
            secret_bytes = rsa_decrypt_from_b64(os.environ.get("REGISTRAR_ENC_PRIV_KEY"), enc_secret)
            secret = secret_bytes.decode("utf-8")
            print(f"your secret ticket for voting is: {secret} please save it safely! and do not share it with anyone else.")
        except Exception as e:
            print("warning: failed to decrypt returned secret:", e)
            print(parsed if parsed else resp.text)
    else:
        print(parsed if parsed else resp.text)


def list_voters():
    url = f"{DEFAULT_HOST}/voters"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    print(resp.json())


def reg_main():
    _maybe_load_keys_env()
    
    print("\nLogged into registrar portal.\n")
    print("1. List registered voters")
    print("2. exit")

    userInput = input("Please make a choice: ").strip() #handling issues where user inputs spaces before or after the input

    if userInput == "1":
        try:
            list_voters()
        except requests.HTTPError as he:
            print("HTTP error:", he.response.status_code, he.response.text)
        except Exception as e:
            print("error:", e)
    elif userInput == "2":
        print("Logged out Goodbye!")
        return
    else:
        print("Invalid choice. Please try again.")
        return  
