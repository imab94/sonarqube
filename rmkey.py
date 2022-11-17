import pexpect
from pexpect import pxssh
import os
import requests
import json
import time

json_data = json.loads(requests.get("http://las-svc/pharase").text)
username = json_data.get("UserName")
passpharase = json_data.get("PASSPHARASE")
cmd_secret_key_delete = "gpg --delete-secret-key "+username
cmd_pub_key_delete = "gpg --delete-key "+username
child_del_sec_key = pexpect.spawn(cmd_secret_key_delete, cwd=os.getcwd())
child_del_sec_key.expect(['Delete this key from the keyring? (y/N)', pxssh.EOF, pxssh.TIMEOUT])
child_del_sec_key.sendline('y')
child_del_sec_key.expect(['This is a secret key! - really delete? (y/N)', pxssh.EOF, pxssh.TIMEOUT])
child_del_sec_key.sendline('y')
time.sleep(30)
child_del_pub_key = pexpect.spawn(cmd_pub_key_delete, cwd=os.getcwd())
child_del_pub_key.expect(['Delete this key from the keyring? (y/N)', pxssh.EOF, pxssh.TIMEOUT])
child_del_pub_key.sendline('y')
