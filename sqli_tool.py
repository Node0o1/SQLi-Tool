import requests
from bs4 import BeautifulSoup as sp
import argparse
from time import sleep


def get_parser_arguments() -> object:
    parser:object = argparse.ArgumentParser(
        prog= "SQLi.py",
        description= "SQLi testing tool",
        epilog= "CLI tool for automating SQLi injection techniques"
    )
    parser.add_argument(
        "-W",
        "--wordlist",
        type= str,
        dest= "filename",
        default= None,
        help= "Filename of the SQLi wordlist. Required value and will be promted to enter if omitted.",
    )
    parser.add_argument(
        "-U",
        "--url",
        type= str,
        dest= "url",
        default= None,
        help= "URL of the GET/POST request which the payload will be embedded. Required value and will be promted to enter if omitted.",
    )
    parser.add_argument(
        "-F",
        "--format",
        type= str,
        dest= "payload_format",
        default= "url_encode",
        help= "Set the format to 'json' if payload should be sent as JSON object or 'url_encode' to url encode the payload. Default vlaue is url_encode",
    )
    parser.add_argument(
        "-T",
        "--timeout",
        type= int,
        dest= "timeout",
        default= 0x14,
        help= "Set timeout limit for each request. Default value is 20 seconds.",
    )
    parser.add_argument(
        "-S",
        "--sleep",
        type= float,
        dest= "sleep_rate",
        default= 0x01,
        help= "Set the sleep rate to pause in between requests. Default value is 1 second.",
    )
    return parser.parse_args()


class SQLi_Worker:
    __successful_payloads:list
    __url_payload:dict
    __browser_headers:dict
    __default_response:bytes
    __url:str
    __payload_format:str
    __timeout:int
    __interesting_param:str

    @classmethod
    def __init__(self, url:str, payload_format:str, timeout:int) -> None:
        self.__url_payload = dict()
        self.__browser_headers = {
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0"
        }
        self.__successful_payloads = list() 
        self.__default_response = b''
        self.__timeout = timeout
        self.__url = url
        self.__payload_format = payload_format
        self.seek_params()
        self.set_default_response()
        
    @classmethod
    def send_sqli_attempt(self) -> object:
        try:
            match self.__payload_format:
                case "json":
                    data = requests.post(url=self.__url, json= self.__url_payload, headers=self.__browser_headers, timeout=self.__timeout, allow_redirects= True)
                case "url_encode":
                    data = requests.post(url=self.__url, data=self.__url_payload, headers=self.__browser_headers, timeout=self.__timeout, allow_redirects= True)
                case _: print(f"Invalid payload settings. Must be json or url_encoded. Not {self.__payload_format}"); raise requests.RequestException
        except requests.RequestException as e: print(f"{type(e).__name__}: {e.args}"); self.exit_on_error()
        else: return data

    @classmethod
    def seek_params(self) -> None:
        html = sp(self.send_sqli_attempt().content, "html.parser")
        tags = html.find_all('input')
        for _,tag in enumerate(tags):
            if(not("name=" in str(tag))): continue
            self.__interesting_param=str(tag.attrs["name"])
            self.__url_payload[self.__interesting_param]="h4ck3r"

    @classmethod
    def log_payload_success(self, payload_string:str) -> None:
        self.__successful_payloads.append(payload_string)

    @classmethod
    def set_payload(self, payload_string:str) -> None:
        self.__url_payload[self.__interesting_param] = payload_string

    @classmethod
    def set_default_response(self) -> None:
        try:self.__default_response = self.send_sqli_attempt()
        except Exception as e: print(f"{type(e).__name__}: {e.args}")

    @classmethod
    def get_default(self) -> bytes:
        return self.__default_response
    
    @classmethod
    def test_response(self, data:object) -> bool:
        return 0x01 if data.content == self.__default_response.content else 0x00
    
    @classmethod
    def get_success_responses(self) -> list:
        return self.__successful_payloads
    
    @staticmethod
    def exit_on_error() -> None:
        input("Exiting Program... Press [ENTER] to Exit")
        exit()
    
    @staticmethod
    def response_details(response_type:str, response:object) -> None:
        print(f"{chr(0x0a)}-- {response_type} --")
        print(f"Payload: {response.request.body}")
        print(f"Response: {chr(0x0a)}{response.content}")


def main() -> None:
    args:object = get_parser_arguments()
    url,sqli_wordlist,payload_format,timeout,sleep_rate = (args.url, args.filename, args.payload_format, args.timeout, args.sleep_rate)
    if(not(url)):url=str(input("URL> "))
    if(not(sqli_wordlist)):str(input("SQLi-Wordlist> "))
    
    SQLi:object = SQLi_Worker(url= url, payload_format= payload_format, timeout= timeout)
    SQLi.response_details("DEFAULT RESPONSE", SQLi.get_default())

    with open(sqli_wordlist, mode="rb") as wordlist:
        cur_pos:tuple = wordlist.tell()
        eof:tuple = wordlist.seek(0,2)
        wordlist.seek(0,0)

        while(not(cur_pos == eof)):
            payload_string:str = wordlist.readline().decode('utf-8').strip()
            cur_pos=wordlist.tell()
            SQLi.set_payload(payload_string)
            response:bytes = SQLi.send_sqli_attempt()
            if(SQLi.test_response(response)):continue
            SQLi.response_details("SUCCESS RESPONSE", response)
            SQLi.log_payload_success(payload_string)
            sleep(sleep_rate)

    succesful_payloads:list = SQLi.get_success_responses()
    print("\nSuccessful Payloads: ")
    for payload in succesful_payloads:
        print(f"{chr(0x09)*2}{payload}")
    

if(__name__=="__main__"):
    main()
    print("\n[Program Finished]\n")
