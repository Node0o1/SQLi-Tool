# SQLi-Tool 
#### *Type: CLI application*
Simple SQLi CLI tool. Dynamically sets the payload parameters and uses a wordlists of SQLi strings to scan a form for SQL vulnerabilities.



### **Instructions:**

```sh
python3 ./sqli_tool.py --wordlist [wordlist] --url [url] --format [url_encoded/json] --timeout [integer] --sleep [float]
```

- Currently only scans a specific url. Future plans include collecting all links from a domain and running SQLi-Tool against all local paths found. for SQLi vulnerabilities.
