"# port-scanner" 

**this has only been tested on windows 10**

Setup:
1. Make sure you are using python 2.7
2. pip install argparse
3. pip install pdfkit
(optional) if you are using linux install pdfkit **this has not been thoroughly tested**


usage: main.py [-h] [-T TARGET_IP [TARGET_IP ...]] [-f FILE]
               [-p PORTS [PORTS ...]] [-t TIMEOUT] [-sT] [-sU] [-sP] [-tr]
               [-oP PDF]

optional arguments:
  -h, --help            show this help message and exit
  -T TARGET_IP [TARGET_IP ...], --target_ip TARGET_IP [TARGET_IP ...]
                        either -t or -f must be set. -t can be used with a
                        single ip, multiple ip's separated by spaces, or a
                        range. -f is for files
  -f FILE, --file FILE  Read target ip's from a file (one ip per line)
  -p PORTS [PORTS ...], --ports PORTS [PORTS ...]
                        Ports to scan. Syntax '-p 22' or '-p 1-1000'
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout interval. Default value = 5
  -sT, --tcp            Scan TCP. This is the default if no scan type is
                        selected
  -sU, --udp            Scan UDP
  -sP, --ping           Ping sweep
  -tr, --traceroute     Run traceroutes
  -oP PDF, --pdf PDF    print to pdf
