from email.policy import default
from operator import le
import os
from traceback import print_tb
from unittest import skip
import requests
import socket
import time
import json
import argparse



class bgcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RED = '\033[31m'
    GREEN = '\033[32m'


def time_result():
    seconds = time.time()
    local_time = time.ctime(seconds)
    return local_time	


parser = argparse.ArgumentParser()
parser.add_argument('--method=', nargs='+')
parser.add_argument('--file=', nargs='+')
parser.add_argument('--limit-expect=')
parser.add_argument('--hide=', nargs='+')
parser.add_argument('--iframe=',nargs='+')
list = []
for _, value in parser.parse_args()._get_kwargs():
    if value is not None:
        try:
            list.append(value)
            args_method = list[4]
            args_limit_expect = list[3]
            args_file = list[0]
            args_hide = list[1]
            args_iframe = list[2]
        except:
            continue

args_file = str(args_file)
args_file = args_file.replace("[","")
args_file = args_file.replace("]","")
args_hide = str(args_hide)
args_hide = args_hide.replace("[","")
args_hide = args_hide.replace("]","")
args_hide = args_hide.replace("'","")
args_iframe = str(args_iframe)
args_iframe = args_iframe.replace("[","")
args_iframe = args_iframe.replace("]","")
args_iframe = args_iframe.replace("'","")

class hardening():

    def apache_server_version_info():
        sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1',80))
        if result == 0:
            print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service Active"+bgcolors.ENDC)
        else:
            print(bgcolors.RED+f"[*] {time_result()} Apache Web Service Not Actived"+bgcolors.ENDC)

        url_http = "http://127.0.0.1:80"
        url_https = "http://127.0.0.1:443"
        r = requests.get(url_http)
        try:
            x = r.headers['Server']
        except:
            skip()
            
        if len(x) > 9:
            print(bgcolors.RED+f"[*] {time_result()} Apache Web Service Version Disclosure Found ({x})"+bgcolors.ENDC)
            apache_sec_file = "/etc/apache2/conf-available/security.conf"
            os.system(f"echo 'ServerSignature Off' >> {apache_sec_file} ")
            os.system(f"echo 'ServerTokens Prod' >> {apache_sec_file} ")
            os.system(f"echo 'SecServerSignature Apache' >> {apache_sec_file} ")
        else:
            print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service Version Disclosure Not Found"+bgcolors.ENDC)

    # def apache_load_module():
        # try:
        #     os.system("mkdir /tmp/installing_script")
        #     os.system("cd /tmp/installing_script")
        #     os.system("git clone https://github.com/SpiderLabs/ModSecurity.git")
        #     os.system("./build.sh")
        #     os.system("./configure –with-apxs=/usr/bin/apxs")
        #     os.system("")
        # except:
        #     skip()

    def method_block(args_method,args_file):
        method_put = ""
        method_post = ""
        method_get = ""
        method_head = ""
        method_options = ""
        method_put = ""
        method_move = ""
        method_trace = ""
        method_connect = ""
        for i in args_method:
            if i.lower() == "put":
                method_put = "PUT"

            if i.lower() == "post":
                method_post = "POST"

            if i.lower() == "get":
                method_get = "GET"

            if i.lower() == "head":
                method_head = "HEAD"

            if i.lower() == "options":
                method_options = "OPTİONS"

            if i.lower() == "move":
                method_move = "MOVE"

            if i.lower() == "trace":
                method_trace = "TRACE"
            
            if i.lower() == "connect":
                method_connect = "CONNECT"

        #payload1 = f'''<Directory {args_file}>\n\t<LimitExcept {method_put} {method_post}  {method_get} {method_head} {method_options}>\n\t\tdeny from all\t</LimitExcept>\n</Directory>'''
        args_file = str(args_file)
        args_file = args_file.replace("[","")
        args_file = args_file.replace("]","")
        REQUEST_METHOD = "REQUEST_METHOD"
        payload = f'''
        <Directory {args_file}>
            RewriteEngine on
            RewriteCond %{REQUEST_METHOD} ^({method_put}|{method_post}|{method_head}|{method_options}|{method_move}|{method_trace}|{method_connect}|{method_get}) [NC]
            RewriteRule .* - [F,L]
        </Directory>
        

        '''

        # payload = f'''
        # <Directory {args_file}>
        #     <LimitExcept {method_put} {method_post}  {method_get} {method_head} {method_options}>
        #         Deny from all
        #     </LimitExcept>
        # </Directory>
        # '''

        os.system(f"echo  '{payload}'   >> /etc/apache2/apache2.conf")
        os.system("sudo systemctl restart apache2")
        print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service: '{args_file}' file banned  {method_put} {method_post}  {method_get} {method_head} {method_options} method  "+bgcolors.ENDC)

    def hide_path(args_file):
        payload = f'''
        <Directory {args_file}>
            Options Indexes FollowSymLinks
            AllowOverride None
            Require all granted
            Options -Indexes
        </Directory>
        '''
        os.system(f"echo  '{payload}' >> /etc/apache2/apache2.conf")
        os.system("sudo systemctl reload apache2")
        print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service: '{args_file}' file banned"+bgcolors.ENDC)

    def iframe_sec(iframe):
        if str(iframe) == "yes":
            payload = '''
            Header always append X-Frame-Options DENY
            '''
            os.system(f"echo  '{payload}' >> /etc/apache2/apache2.conf")
            os.system("sudo systemctl reload apache2")
            print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service: iframe banned "+bgcolors.ENDC)

            sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1',80))
            if result == 0:
                print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service: X-Frame-Options: SAMEORIGIN test started"+bgcolors.ENDC)
            else:
                print(bgcolors.RED+f"[*] {time_result()} Apache Web Service Not Actived"+bgcolors.ENDC)

            url_http = "http://127.0.0.1:80"
            r = requests.get(url_http)

            try:
                x = r.headers['X-Frame-Options']
            except:
                pass

            if x:
                print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service: X-Frame-Options: SAMEORIGIN TEST PASSED"+bgcolors.ENDC)
                print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service: You Test test_iframe.html file "+bgcolors.ENDC)

        else:
            print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service: İFRAME BANNED (SKIPPED) "+bgcolors.ENDC)

    def http_only():
        payload = '''
        Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure
        '''
        os.system(f"echo  '{payload}' >> /etc/apache2/apache2.conf")
        os.system("sudo systemctl reload apache2")
        print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service: iframe banned "+bgcolors.ENDC)
        # sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # result = sock.connect_ex(('127.0.0.1',80))
        # if result == 0:
        #     print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service: X-Frame-Options: SAMEORIGIN test started"+bgcolors.ENDC)
        # else:
        #     print(bgcolors.RED+f"[*] {time_result()} Apache Web Service Not Actived"+bgcolors.ENDC)

        # url_http = "http://127.0.0.1:80"
        # r = requests.get(url_http)
        # try:
        #     y = r.headers['HttpOnly']
        # except:
        #     pass

        # if y:
        #     print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service: X-Frame-Options: Http_only TEST PASSED"+bgcolors.ENDC)
        # else:
        #     print(bgcolors.GREEN+f"[*] {time_result()} Apache Web Service: Http_only BANNED (SKIPPED) "+bgcolors.ENDC)
    





hardening.apache_server_version_info()
hardening.iframe_sec(args_iframe)
hardening.http_only()

if args_limit_expect.lower() == "yes":
    try:
        if args_limit_expect.lower() == "yes":
            hardening.method_block(args_method ,args_file)
        else:
            pass
    except:
        pass
if args_hide.lower() == "yes":
    hardening.hide_path(args_file)
