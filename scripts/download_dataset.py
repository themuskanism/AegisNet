"""Download only the two documented benchmark data files; verify before use."""
import hashlib
from pathlib import Path
import urllib.request

BASE='https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/'
FILES=[('2018-12-21-15-50-14-192.168.1.195.pcap','scenario34.pcap','92ec7e2f6658ee4b007d0b816986c46cc0338bc5e2bec6ceaaca566c695e4699'),('bro/conn.log.labeled','conn.log.labeled','d69e49b2aae8c1bd33286936531658202dec47d989f0439bad3f8be180467a6e')]

def main():
    folder=Path('data/benchmark');folder.mkdir(parents=True,exist_ok=True)
    for remote,name,expected in FILES:
        target=folder/name
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest()==expected:
            print(name,'already verified');continue
        temp=folder/(name+'.partial')
        with urllib.request.urlopen(BASE+remote,timeout=60) as source,temp.open('wb') as dest:
            while chunk:=source.read(1024*1024):dest.write(chunk)
        if hashlib.sha256(temp.read_bytes()).hexdigest()!=expected:raise RuntimeError('Checksum mismatch: '+name)
        temp.replace(target);print(name,'downloaded and verified')
    print('Read-only PCAP analysis only. Do not replay packets onto a network.')

if __name__=='__main__':main()
