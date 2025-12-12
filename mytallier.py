import requests
from collections import Counter
import os
import json
import base64
from my_utils import DEFAULT_HOST, decrypt_ballot_with_election_priv
from my_sss import combine_private_key_shares
import tempfile

def fetch_ballots():
    url = f"{DEFAULT_HOST}/ballots"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    data = resp.json()
    return data.get("ballots", [])


def tally_and_print():

    ballots = fetch_ballots()

    if not ballots:
        print("no ballots found")
        return None


    #hetting the shares from the admin and tallier for decrypting ballots
    admin_share_spec = os.environ.get("ADMIN_SHARE")
    tallier_share_spec = os.environ.get("TALLIER_SHARE")

    if not admin_share_spec or not tallier_share_spec:
        print("ADMIN_SHARE and TALLIER_SHARE environment variables are required to reconstruct election private key.")
        return

    def _load_share(spec: str):
        try:
            if os.path.exists(spec):
                with open(spec, "r") as f:
                    spec = f.read().strip()
            x_str, b64 = spec.split(":", 1)
            x = int(x_str)
            share_bytes = base64.b64decode(b64)
            return (x, share_bytes)
        except Exception:
            return None

    s_admin = _load_share(admin_share_spec)
    s_tall = _load_share(tallier_share_spec)
    if not s_admin or not s_tall:
        print("Failed to parse share specs. Expected 'x:BASE64' or path to file containing it.")
        return

    # Reconstruct election private key PEM bytes
    try:
        pem = combine_private_key_shares([s_admin, s_tall])
    except Exception as e:
        print("failed to combine shares:", e)
        return

    # Putting the key in a temporal file so that i can use my decryption function on it.
    tf = tempfile.NamedTemporaryFile(delete=False)
    try:
        tf.write(pem)
        tf.flush()
        priv_path = tf.name
    finally:
        tf.close()

    decrypted_choices = []
    for b in ballots:
        enc = b.get("encrypted_ballot")
        if enc:
            try:
                pt = decrypt_ballot_with_election_priv(priv_path, enc)
                parsed = json.loads(pt.decode("utf-8"))
                decrypted_choices.append(parsed.get("choice"))
            except Exception as e:
                print("warning: failed to decrypt a ballot:", e)
        else:
            decrypted_choices.append(b.get("choice"))

    # I a determining a winner as the most common choice, without revealing counts
    # or any mapping to voters. If there is a tie I will list the tied options.
    counts = Counter([c for c in decrypted_choices if c is not None])
    if not counts:
        print("no valid votes decrypted")
        # cleanup temporary key file
        try:
            os.unlink(priv_path)
        except Exception:
            pass
        return None

    most = counts.most_common()
    top_count = most[0][1]
    winners = [choice for choice, cnt in most if cnt == top_count]

    if len(winners) == 1:
        print("Election completed, hence, the summer vation will be at ", winners[0])
    else:
        print("Election Completed, but we have a tie:", ", ".join(winners))

    # Prepare a structured result for programmatic consumption
    result = {
        "counts": dict(counts),
        "winners": winners,
        "top_count": top_count,
        "num_ballots": len(ballots),
    }

    # cleanup temporary key file
    try:
        os.unlink(priv_path)
    except Exception:
        pass

    return result


def tally_main():
    print("\nPlease wait......\n")
    try:
        tally_and_print()
    except requests.HTTPError as he:
        print("HTTP error:", he.response.status_code, he.response.text)
    except Exception as e:
        print("error:", e)
