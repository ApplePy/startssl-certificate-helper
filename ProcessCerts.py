#!/bin/python3

import os
import argparse
import re
import sys
import json
import base64
from OpenSSL import crypto
import CertSecurity
from CertSecurity import CertSecurityGlobals


# Constants
class ProcessCertsGlobals:
    CURRENT_DIR = os.getcwd()
    INSUFFICIENT_PY_VERSION_MSG = 'Sorry, Python < 3.5 is not supported.'
    DEFAULT_CONFIG_FILE = os.path.join(CURRENT_DIR, "domains.json")


# --------- DOMAIN FUNCTIONS --------- #

def valid_domain(domain: str):
    """Check if the domain passed is valid"""

    domain_regex = re.compile("^(((\w+|\w+-*\w*-*\w+)\.)+(\w{2,}))$", flags=re.IGNORECASE)
    if domain_regex.match(domain):
        return True

    return False


def get_domain():
    """Retrieves the domain to retrieve a certificate for from the user.

    :return: The domain
    """
    domain = input("Enter the domain you would like to retrieve new SSL keys/certificates for and press [ENTER]: ")

    # Validate entered domain
    while not valid_domain(domain):
        domain = input("Invalid domain! Try again and then press [ENTER]: ")

    return domain


# --------- SETUP FUNCTIONS --------- #


def parse_args():
    """Parses the command-line arguments and returns them.

    :return: Returns a namespace object of the given arguments and their values
    """
    parser = argparse.ArgumentParser(description="Sets up generating SSL keys, CSRs, and "
                                                 "retrieving signed certificates from StartSSL for easy installation.",
                                     epilog="")
    parser.add_argument("--install", metavar="PATH",
                        help="Install the chained certificate and key to the specified location.")
    parser.add_argument("--format", choices=['PEM', 'DER', 'TEXT'], default='PEM',
                        help="Specify the format to use during installation ('PEM' is the default).")
    parser.add_argument("--config", metavar="PATH",
                        help="Specifies the path to the configuration file.")
    parser.add_argument("--encrypt-key", dest="encryptKey", action='store_true',
                        help="Specifies the path to the configuration file.")
    return parser.parse_args()


def main():
    """Main program."""

    # TODO: Remove debug
    CertSecurityGlobals.DEBUG_MODE = True

    # Version check
    if sys.version_info[0] < 3:
        exit(ProcessCertsGlobals.INSUFFICIENT_PY_VERSION_MSG)
    elif sys.version_info[1] < 5:
        exit(ProcessCertsGlobals.INSUFFICIENT_PY_VERSION_MSG)

    # Parse arguments
    args = parse_args()

    # Fill in arguments that were not valid or missing
    if not args.config or not os.path.isfile(args.config):
        # if there was a config file given, but it doesn't exist
        if args.config:
            print('Configuration file {0} does not exist.'.format(args.config))

        args.config = ProcessCertsGlobals.DEFAULT_CONFIG_FILE

        # Make sure the default config file name exists, otherwise exit
        if not os.path.isfile(ProcessCertsGlobals.DEFAULT_CONFIG_FILE):
            exit('Default configuration file {0} does not exist.'.format(ProcessCertsGlobals.DEFAULT_CONFIG_FILE))

    # TODO: Support multiple entries in domains.json

    # Open configuration file
    with open(args.config, "r") as file:
        config_contents = json.load(file)

    # Make directory to hold keys and csr
    try:
        ssl_dir = os.path.join(ProcessCertsGlobals.CURRENT_DIR, config_contents['domainName'] + ".ssl")
        os.mkdir(ssl_dir)
        CertSecurityGlobals.SSL_DIR = ssl_dir
        del ssl_dir
    except FileExistsError as err:
            print("Error: " + ssl_dir + " already exists, exiting.", file=sys.stderr)
            exit(err.errno)

    # Generate keys
    key_pair = CertSecurity.generate_key(key_file=config_contents['domainName'] + ".key",
                                         password=CertSecurity.get_password() if args.encryptKey else None)

    # Set up CSR data
    keys = ['domainName',
            'sans',
            'countryName',
            'stateOrProvinceName',
            'localityName',
            'organizationName',
            'organizationalUnitName',
            'emailAddress'
            ]
    csr_dict = {}
    for key in keys:
        csr_dict[key] = config_contents.get(key) or None

    # Generate CSR
    csr = CertSecurity.generate_csr(key_pair=key_pair,
                                    csr_data=csr_dict)
    # Get API certificate
    client_cert = None
    while True:
        try:
            client_cert = crypto.load_pkcs12(base64.b64decode(config_contents['clientCert']),
                                             input("Input API certificate password (Press 'Enter' for no password): "))
            break
        except crypto.Error:
            print("Bad API certificate password!", file=sys.stderr)
            exit(-1)

    # Request certificate
    domains = [config_contents['domainName']] + config_contents.get('sans')
    new_certificate = CertSecurity.request_certificate(csr, config_contents['tokenID'], client_cert, domains)
    del csr  # No longer needed

    # If certificate was not issued, return StartSSL status
    if new_certificate[0] != 2:
        return new_certificate[0]

    # Write certificate to disk  TODO: Clean this block up
    cert_path = os.path.join(CertSecurityGlobals.SSL_DIR, config_contents['domainName'] + ".cert")
    for file_format, file in CertSecurity.write_all_formats(cert_path):  # DER and PEM formats
            file.write(crypto.dump_certificate(file_format, new_certificate[1]))
    with open(cert_path + ".p12", "wb") as file:  # PKCS12 format
        # Set up container
        package = crypto.PKCS12()
        package.set_ca_certificates(new_certificate[2])
        package.set_certificate(new_certificate[1])
        package.set_privatekey(key_pair)
        package.set_friendlyname(config_contents['domainName'])

        file.write(package.export(CertSecurity.get_password() if args.encryptKey else None))

    # TODO: Create chained certs
    # TODO: Setup installation settings


if __name__ == "__main__":
    exit(main() or 0)
