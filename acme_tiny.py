#!/usr/bin/env python3

# MIT license. Forked from github.com/diafygi/acme-tiny
import argparse
import base64
import binascii
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import textwrap
import time

try:
    from urllib.request import urlopen, Request # Python 3
except ImportError: # pragma: no cover
    from urllib2 import urlopen, Request # Python 2

DEFAULT_CA = "https://acme-v02.api.letsencrypt.org" # DEPRECATED! USE DEFAULT_DIRECTORY_URL INSTEAD
DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)


def get_crt(
    account_key,
    csr,
    acme_dir,
    CA=DEFAULT_CA,
    disable_check=False,
    directory_url=DEFAULT_DIRECTORY_URL,
    contact=None,
    check_port=None
):
    directory, acct_headers, alg, jwk = None, None, None, None # global variables

    # helper functions - base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # helper function - run external commands
    def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
        proc = subprocess.Popen(cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(cmd_input)
        if proc.returncode != 0:
            raise IOError(f"{err_msg}\n{err}")
        return out

    # helper function - make request and automatically parse json response
    def _do_request(url, data=None, err_msg="Error", depth=0):
        try:
            request = Request(
                url,
                data=data,
                headers={"Content-Type": "application/jose+json", "User-Agent": "acme-tiny"})
            resp = urlopen(request)
            resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
        except IOError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code, headers = getattr(e, "code", None), {}
        try:
            resp_data = json.loads(resp_data)
        except ValueError as valueError:
            logger.exception("Error in parse response data as json!", valueError)
        if depth < 100 and code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
            raise IndexError(resp_data) # allow 100 retrys for bad nonces
        if code not in [200, 201, 204]:
            raise ValueError(f"{err_msg}:\nUrl: {url}\nData: {data}\nResponse Code: {code}\nResponse: {resp_data}")
        return resp_data, code, headers

    # helper function - make signed requests
    def _send_signed_request(url, payload, err_msg, depth=0):
        payload64 = "" if payload is None else _b64(json.dumps(payload).encode('utf8'))
        new_nonce = _do_request(directory['newNonce'])[2]['Replay-Nonce']
        protected = {"url": url, "alg": alg, "nonce": new_nonce}
        protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        protected_input = f"{protected64}.{payload64}".encode('utf8')
        out = _cmd(
            ["openssl", "dgst", "-sha256", "-sign", account_key],
            stdin=subprocess.PIPE,
            cmd_input=protected_input,
            err_msg="OpenSSL Error")
        data = json.dumps({"protected": protected64, "payload": payload64, "signature": _b64(out)})
        try:
            return _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
        except IndexError: # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

    # helper function - poll until complete
    def _poll_until_not(url, pending_statuses, err_msg):
        result, t0 = None, time.time()
        while result is None or result['status'] in pending_statuses:
            assert (time.time() - t0 < 3600), "Polling timeout" # 1 hour timeout
            time.sleep(0 if result is None else 2)
            result, _, _ = _send_signed_request(url, None, err_msg)
        return result

    # parse account key to get public key
    logger.info("Parsing account key...")
    out = _cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="OpenSSL Error")
    pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pub_pattern, out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = f"{pub_exp:x}"
    pub_exp = f"0{pub_exp}" if len(pub_exp) % 2 else pub_exp
    alg, jwk = "RS256", {
        "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
    }
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # find domains
    logger.info("Parsing CSR...")
    out = _cmd(
        ["openssl", "req", "-in", csr, "-noout", "-text"],
        err_msg=f"Error loading {csr}",
    )
    domains = set([])
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(
        r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n",
        out.decode('utf8'),
        re.MULTILINE | re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    domain_list_str = ", ".join(domains)
    logger.info(f"Found domains: {domain_list_str}")

    # get the ACME directory of urls
    logger.info("Getting directory...")
    directory_url = CA + "/directory" if CA != DEFAULT_CA else directory_url # backwards compatibility with deprecated CA kwarg
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    logger.info("Directory found!")

    # create account, update contact details (if any), and set the global key identifier
    logger.info("Registering account...")
    reg_payload = {"termsOfServiceAgreed": True} if contact is None else {"termsOfServiceAgreed": True, "contact": contact}
    account, code, acct_headers = _send_signed_request(directory['newAccount'], reg_payload, "Error registering")
    registered_status = "Registered!" if code == 201 else "Already registered!"
    account_id = acct_headers['Location']
    logger.info(f"{registered_status} Account ID: {account_id}")
    if contact is not None:
        account, _, _ = _send_signed_request(acct_headers['Location'], {"contact": contact}, "Error updating contact details")
        contact_list = "\n".join(account['contact'])
        logger.info(f"Updated contact details:\n{contact_list}")

    # create a new order
    logger.info("Creating new order...")
    order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    order, _, order_headers = _send_signed_request(directory['newOrder'], order_payload, "Error creating new order")
    logger.info("Order created!")

    # get the authorizations that need to be completed
    for auth_url in order['authorizations']:
        authorization, _, _ = _send_signed_request(auth_url, None, "Error getting challenges")
        domain = authorization['identifier']['value']

        # skip if already valid
        if authorization['status'] == "valid":
            logger.info(f"Already verified: {domain}, skipping...")
            continue
        logger.info(f"Verifying {domain}...")

        # find the http-01 challenge and write the challenge file
        challenge = [c for c in authorization['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        key_authorization = f"{token}.{thumbprint}"
        print(f"key_authorization = key_authorization")
        wellknown_path = os.path.join(acme_dir, token)
        with open(wellknown_path, "w") as wellknown_file:
            print(f"Writing key_authorization to file: {wellknown_file}")
            wellknown_file.write(key_authorization)
            print("Writing key_authorization done!")

        # check that the file is in place
        try:
            port_str = "" if not check_port else f":{check_port}"
            wellknown_url = f"http://{domain}{port_str}/.well-known/acme-challenge/{token}"
            assert (disable_check or _do_request(wellknown_url)[0] == key_authorization)
        except (AssertionError, ValueError) as e:
            raise ValueError(f"Wrote file to {wellknown_path}, but couldn't download {wellknown_url}: {e}")

        # say the challenge is done
        _send_signed_request(challenge['url'], {}, f"Error submitting challenges: {domain}")
        authorization = _poll_until_not(
            auth_url, ["pending"],
            f"Error checking challenge status for {domain}")
        if authorization['status'] != "valid":
            raise ValueError(f"Challenge did not pass for {domain}: {authorization}")
        os.remove(wellknown_path)
        logger.info(f"{domain} verified!")

    # finalize the order with the csr
    logger.info("Signing certificate...")
    csr_der = _cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
    _send_signed_request(order['finalize'], {"csr": _b64(csr_der)}, "Error finalizing order")

    # poll the order to monitor when it's done
    order = _poll_until_not(order_headers['Location'], ["pending", "processing"], "Error checking order status")
    if order['status'] != "valid":
        raise ValueError(f"Order failed: {order}")

    # download the certificate
    certificate_pem, _, _ = _send_signed_request(order['certificate'], None, "Certificate download failed")
    logger.info("Certificate signed!")
    return certificate_pem


def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from Let's Encrypt using the ACME protocol.
            It will need to be run on your server and have access to your private account key, so PLEASE READ THROUGH IT!
            It's only ~200 lines, so it won't take long.

            Example Usage: python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > signed_chain.crt
            """)
    )
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--disable-check", default=False, action="store_true", help="disable checking if the challenge file is hosted correctly before telling the CA")
    parser.add_argument("--directory-url", default=DEFAULT_DIRECTORY_URL, help="certificate authority directory url, default is Let's Encrypt")
    parser.add_argument("--ca", default=DEFAULT_CA, help="DEPRECATED! USE --directory-url INSTEAD!")
    parser.add_argument("--contact", metavar="CONTACT", default=None, nargs="*", help="Contact details (e.g. mailto:aaa@bbb.com) for your account-key")
    parser.add_argument("--check-port", metavar="PORT", default=None, help="what port to use when self-checking the challenge file, default is port 80")

    args = parser.parse_args(argv)
    logger.setLevel(args.quiet or logger.level)
    signed_crt = get_crt(
        args.account_key,
        args.csr,
        args.acme_dir,
        CA=args.ca,
        disable_check=args.disable_check,
        directory_url=args.directory_url,
        contact=args.contact,
        check_port=args.check_port)
    sys.stdout.write(signed_crt)


if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
