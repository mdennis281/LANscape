# LANscape
A python based local network scanner.

![screenshot](https://github.com/user-attachments/assets/7d77741e-3bad-4b6b-a33f-6a392adde23f)


PyPi Stats: 

![Monthly Downloads](https://img.shields.io/pypi/dm/lanscape)

Latest release: 

![Releases](https://img.shields.io/github/v/tag/mdennis281/LANscape?sort=date&filter=releases%2F*)

Tests: 

![pytest](https://img.shields.io/github/actions/workflow/status/mdennis281/LANscape/test.yml?branch=main&label=pytest) 
![packaging](https://img.shields.io/github/actions/workflow/status/mdennis281/LANscape/test-package.yml?label=packaging) 
![pylint](https://img.shields.io/github/actions/workflow/status/mdennis281/LANscape/pylint.yml?branch=main&label=pylint)


## Local Run
```sh
pip install lanscape
python -m lanscape
```

## Flags
 - `--port <port number>` port of the flask app (default: automagic)
 - `--persistent` dont shutdown server when browser tab is closed (default: false)
 - `--reloader` essentially flask debug mode- good for local development (default: false)
 - `--logfile <path>` save log output to the given file path
 - `--loglevel <level>` set the logger's log level (default: INFO)
 - `--flask-logging` turn on flask logging (default: false)

Examples:
```shell
python -m lanscape --reloader
python -m lanscape --port 5002
python -m lanscape --logfile /tmp/lanscape.log --loglevel DEBUG
```

## Troubleshooting

### MAC Address / Manufacturer is inaccurate/unknown
The program does an ARP lookup to determine the MAC address. This lookup
can sometimes require admin-level permissions to retrieve accurate results.
*Try elevating your shell before execution.*

### Message "WARNING: No libpcap provider available ! pcap won't be used"
This is a missing dependency related to the ARP lookup. This is handled in the code, but you would get marginally faster/better results with this installed: [npcap download](https://npcap.com/#download)

### The accuracy of the devices found is low
I use a combination of ARP and Ping to determine if a device is online. This method drops in stability when used in many threads. 
Recommendations:

  - Drop parallelism value (advanced dropdown)
  - Use python > 3.10 im noticing threadpool improvements after this version
  - Create a bug - I'm curious


### Something else
Feel free to submit a github issue detailing your experience.


