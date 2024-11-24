<style>
  #1{
    text-decoration:italic;
  }
  #2{
    text-decoration:italic;
    font-size:12pt;
</style>


<h1>SQLi-Tool</h1>
Simple SQLi CLI tool. Dynamically sets the payload parameters and uses a wordlists of SQLi strings to scan a form for SQL vulnerabilities.

<p style="text-decoration:italic;">type: CLI application</p>

<h3>;Instructions:</h3>

```sh
python3 ./sqli_tool.py --wordlist [wordlist] --url [url] --format [url_encoded/json] --timeout [integer] --sleep [float]
```

<p style="text-decoration:italic; font-size:12pt;">Currently only scans a specific url. Future plans include collecting all links from a domain and running SQLi-Tool against all local paths found. for SQLi vulnerabilities.</p>
