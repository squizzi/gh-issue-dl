#!/usr/bin/env python
import sys
import logging
import validators
import argparse
import signal
from requests import session
from bs4 import BeautifulSoup as bs
from logrusformatter import LogrusFormatter

"""
ghLogin logs in to Github to form an established session for use, it also closes
sessions
"""
class ghLogin():
    def __init__(self):
        self.s = session()

    def login(self, user, password, authcode,
              session_url='https://github.com/session',
              two_factor_url='https://github.com/sessions/two-factor'):
    req = self.s.get(session_url).text
    html = bs(req, "lxml")
    token = html.find("input", {"name": "authenticity_token"}).attrs['value']
    com_val = html.find("input", {"name": "commit"}).attrs['value']
    login_data = {'login' : user,
                  'password' : password,
                  'commit' : com_val,
                  'authenticity_token' : token}
    r = self.s.post(session_url data=login_data, allow_redirects=True)
    if r.url in two_factor_url:
        # If we're sent to the two-factor auth session page send more login
        # data containing authcode and a new token
        html = bs(r.text, "lxml")
        token = html.find("input", {"name": "authenticity_token"}).attrs['value']
        otp_data = {'otp' : authcode,
                    'authenticity_token' : token}
        r2 = self.s.post(r.url, data=otp_data)
        return r2
    else:
        # Else we're already logged in, and have established a valid session
        return r

    def logout(self):
        r = self.s.get('https://github.com/logout')
        self.s.close()
        return r

""" load_config loads config variables """
def load_config(filename):
    configs = {}
    # Open config file and read in values (if it exists)
    if os.path.exists(filename):
        config = open(filename, "r")
        content = config.read()
        lines = content.split("\n")
        for data in lines:
            # If the line returned from the config file is
            # trying to set a value, load it up and set it in
            # our configs dictionary
            if data.find("=") != -1:
                option = data.split("=")[0]
                value = data.split("=")[1]
                # if the value has a comma in it, we need
                # to build an array instead of a string
                if value.find(",") != -1:
                    value = value.split(",")
                configs[option] = value
    else:
        return load_config_from_env()
    return configs

"""
generate_config creates a config of data that stays intact between runs of
ghgrab
"""
def generate_config():
    # Generate a hidden file in pwd
    config_file = ".ghauth.cfg"
    if not os.path.isfile(config_file):
        logging.info("No configuration file found, creating one now...")
    else:
        if not ("USER" in config and
        "PASSWORD" in config and
        "TOKEN" in config):
            logging.info("Detected that some configuration variables may not exist in the {0} file, creating them now...").format(config_file)
            pass
    if not "USER" in config:
        while True:
            USER = raw_input("Enter GitHub username: ")
            if not validators.slug(USER):
                print("Please enter a valid GitHub username.")
            else:
                break
        save_config(config_file, "USER",USER)
    if not "PASSWORD" in config:
        while True:
            plain_password = getpass.getpass('Enter GitHub password: ')
            print("Encrypting password, please wait...\n")
            encrypted_password = encrypt('password', plain_password)
            # Write the encrypted_password out to it's own file
            open(".ghpassword".format(config_dir), "w").write(encrypted_password);
            os.chmod(".ghpassword", 0666)
            # Save the config so we know password has been captured
            save_config(config_file, "PASSWORD", "ENCRYPTED")
    if not "TOKEN" in config:
        while True:
            TOKEN = raw_input("Enter GitHub Personal access token: ")
            if not validators.length(from_number, min=41):
                print("Please enter a valid GitHub token.")
            else:
                break
        save_config(config_file, "TOKEN",TOKEN)


"""
read_issue reads a given issue_number and returns a list of attachment urls
for downloading
"""
def read_issue(issue_number):


"""
download_attachments downloads a given list of attachments and places them in
a given directory structure, usually one associated with a given issue number
"""
def download_attachments(attachment, issue_number):


"""
Main
"""
def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description='Download files from GitHub \
    issues.')
    parser.add_argument("-a",
                        "--authcode",
                        dest="authcode",
                        help="Enter your two-factor auth code.  Required for \
                        use if two-factor authentication is enabled across \
                        GitHub.")
    parser.add_argument("--debug",
                        dest="debug",
                        action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()
    # Basic logging that matches logrus format
    fmt_string = "%(levelname)s %(message)-20s"
    fmtr = LogrusFormatter(colorize=True, fmt=fmt_string)
    logger = logging.getLogger(name=None)
    if not args.debug:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)
    hdlr = logging.StreamHandler(sys.stdout)
    hdlr.setFormatter(fmtr)
    logger.addHandler(hdlr)

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    sys.exit(main())
