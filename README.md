# SQLi-Tool 
*type: CLI-application*
Simple SQLi CLI tool. Dynamically sets the payload parameters and uses a wordlists of SQLi strings to scan a form for SQL vulnerabilities.



## **Instructions:**
- ***Install***
#### Once downloaded, be sure to navigate to the directory containing requirements.txt and install the dependancies using pip
```sh
python3 -m pip install ./requirements.txt
```

- ***Run***
```sh
python3 ./sqli_tool.py --wordlist [wordlist] --url [url] --format [url_encoded/json] --timeout [integer] --sleep [float]
```
- ***Help***
```sh
python3 ./sqli_tool.py --help
```
![helpMessage](https://github.com/user-attachments/assets/612eceba-cd81-4c40-9d62-394e2fda8333)

### Currently only scans a specific url. Future plans include collecting all links from a domain and running SQLi-Tool against all local paths found. for SQLi vulnerabilities.
