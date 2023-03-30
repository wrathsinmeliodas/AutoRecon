
#!/bin/bash

if [ -z "$1" ]
then
        echo "Usage: ./james.sh <domain>"
        echo "Example: ./james.sh yahoo.com"
        exit 1
fi

#edit directory before starting the bash script
cd ..
mkdir $1
cd $1

#saved directories(don't edit this.)
if [ ! -d "thirdlevel" ]; then
	mkdir thirdlevels
fi

if [ ! -d "scans" ]; then
	mkdir scans
fi

printf "\n\n =====================================> Stating Recon <===================================== \n\n"

echo "=====================================> Gathering subdomains with subliat3r... <====================================="
subfinder -d $1 -o results.txt

echo $1 >> results.txt

echo "=====================================> Gathering third-level domains... <====================================="
cat results.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u >> third-level.txt

echo "=====================================> Gathering thirdlevel domains with sublist3r... <====================================="
for domain in $(cat third-level.txt); do
	subfinder -d $domain -o thirdlevels/$domain.txt;
	cat thirdlevels/$domain.txt | sort -u >> results.txt;
done

echo "=====================================> Probing subdomains with httprobe... <====================================="
cat results.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' |tr -d ":443" > probed.txt

echo "=====================================> Scanning for open ports... <====================================="
nmap -iL probed.txt -oA scans/scanned.txt

echo "=====================================> Running Aquatone... <====================================="
cat scans/scanned.txt | aquatone

echo "=====================================> Starting Nuclei... <====================================="
mkdir nuclei_op
nuclei -l probed.txt -t "/root/tools/nuclei-templates/cves/*.yaml" -c 60 -o nuclei_op/cves.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/files/*.yaml" -c 60 -o nuclei_op/files.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/panels/*.yaml" -c 60 -o nuclei_op/panels.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/security-misconfiguration/*.yaml" -c 60 -o nuclei_op/security-misconfiguration.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/technologies/*.yaml" -c 60 -o nuclei_op/technologies.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/tokens/*.yaml" -c 60 -o nuclei_op/tokens.txt
nuclei -l probed.txt -t "/root/tools/nuclei-templates/vulnerabilities/*.yaml" -c 60 -o nuclei_op/vulnerabilities.txt

echo "=====================================> Now looking for CORS misconfiguration... <====================================="
python3 /root/Crosy/corsy.py -i probed.txt -t 40 | tee -a corsy_op.txt

echo "=====================================> Starting CMS detection... <====================================="
whatweb -i probed.txt | tee -a whatweb_op.txt

echo "=====================================> Running smuggler... <====================================="
python3 /root/smuggler/smuggler.py -u probed.txt | tee -a smuggler_op.txt

printf "\n\n =====================================> Recon Stopped <====================================="
