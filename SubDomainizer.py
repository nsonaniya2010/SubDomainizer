#!/usr/bin/env python3
import termcolor
import argparse
from bs4 import BeautifulSoup
import requests
import re
import htmlmin
import urllib.parse as urlparse
import tldextract
import sys

parse = argparse.ArgumentParser()
parse.add_argument('-u', '--urls', help="Enter the URL or list of URL in which you want to find (sub)domains.")
parse.add_argument('-l', '--listfile', help="List file which needs to be scanned for URLs")
parse.add_argument('-o', '--output', help="Enter the file name to which you want to save the results.")
parse.add_argument('-c', '--cookie', help="Cookies which needs to be sent with request. User double quotes if have more than one.")

args = parse.parse_args()
url = args.urls
listfile = args.listfile

if args.cookie:
    heads = {'Cookie' : args.cookie}
else:
    heads=None

def argerror(urls, listfile):
    if (urls == None and listfile == None) or (urls != None and listfile != None):
        print("Either and atmost one of -u/--url or -l/--listfile argument is required.Exiting...")
        sys.exit(1)
    else:
        pass


def getUrlsFromFile():
    with open(args.listfile, 'rt') as f:
        urllst = f.readlines()
    urllst = [x.strip() for x in urllst]
    return urllst


jsLinkList = list()
jsname = list()
finalset = set()
s3bucketset = set()
cfset = set()

finallist = list()


class JsExtract:
    def IntJsExtract(self, url, heads):
        if url.startswith('http'):
            req = requests.get(url, headers = heads)
        else:
            req = requests.get('http://' + url, headers = heads)
        decoding = req.encoding
        print(termcolor.colored("Searching for Inline Javascripts.....", color='yellow', attrs=['bold']))
        try:
            html = req.content.decode(decoding)
            minhtml = htmlmin.minify(html, remove_empty_space=True)
            minhtml = minhtml.replace('\n', '')
            compiledInline = re.compile(r"<script.*?>(.*?)</script>")
            jss = compiledInline.findall(minhtml)
            for js in jss:
                finallist.append(js)
            print(termcolor.colored("Successfully got all the Inline Scripts.", color='blue', attrs=['bold']))
        except UnicodeDecodeError:
            print("Decoding error.")

    def ExtJsExtract(self, url, heads):
        domain = urlparse.urlparse(url).netloc
        print(termcolor.colored("Searching for External Javascript links in page.....", color='yellow', attrs=['bold']))
        if url.startswith('http'):
            req = requests.get(url, headers = heads)
        else:
            req = requests.get('http://' + url, headers = heads)
        decoding = req.encoding
        try:
            html = req.content.decode(decoding)
            soup = BeautifulSoup(html, features='html.parser')
            for link in soup.find_all('script'):
                if link.get('src') != None and link.get('src').endswith('.js'):
                    if link.get('src').startswith('https://' + domain) or link.get('src').startswith(
                            'http://' + domain):
                        jsLinkList.append(link.get('src'))
                    elif link.get('src').startswith('http'):
                        jsLinkList.append(link.get('src'))
                    else:
                        if url.startswith('https'):
                            jsLinkList.append('https://' + domain + link.get('src'))
                        else:
                            jsLinkList.append('http://' + domain + link.get('src'))
            print(
                termcolor.colored("Successfully got all the external js links", color='blue', attrs=['bold']))
        except UnicodeDecodeError:
            print("Decoding error, Exiting...")
            sys.exit(1)

    def SaveExtJsContent(self, lst):
        for js in lst:
            try:
                req = requests.get(js)
                content = req.content.decode('utf-8')
                finallist.append(content)
            except:
                pass


def logo():
    return """
   _____       _     _____                        _       _              
  / ____|     | |   |  __ \                      (_)     (_)             
 | (___  _   _| |__ | |  | | ___  _ __ ___   __ _ _ _ __  _ _______ _ __ 
  \___ \| | | | '_ \| |  | |/ _ \| '_ ` _ \ / _` | | '_ \| |_  / _ \ '__|
  ____) | |_| | |_) | |__| | (_) | | | | | | (_| | | | | | |/ /  __/ |   
 |_____/ \__,_|_.__/|_____/ \___/|_| |_| |_|\__,_|_|_| |_|_/___\___|_|Version 1.0                                                                                                                                          
  Find interesting Subdomains hidden in Inline and External Javascripts  \n"""


def getDomain(url):
    finalset.add(urlparse.urlparse(url).netloc)
    ext = tldextract.extract(url)
    return ext.registered_domain


def getSubdomainsfromFile(filesname, url):
    print(termcolor.colored("Finding Subdomains of given domain in all Javascript files found...", color='yellow',
                            attrs=['bold']))
    cfreg = re.compile(r'([\w]+.cloudfront\.net)')
    s3bucketreg = re.compile(r'([\w-]+\.s3\.amazonaws\.com)')
    s3bucketafter = re.compile(r'(s3\.amazonaws\.com/[\w-]+)')
    regex = re.compile(r'([\w.]+\.' + getDomain(url) + ')')

    for file in filesname:
        for item in cfreg.findall(file):
            cfset.add(item)
        for item in s3bucketreg.findall(file):
            s3bucketset.add(item)
        for item in s3bucketafter.findall(file):
            s3bucketset.add(item)
        for subdomain in regex.findall(file):
            finalset.add(subdomain)
    print(termcolor.colored("Got all the important data.\n", color='green',attrs=['bold']))


def subextractor(url):
    jsfile = JsExtract()
    jsfile.IntJsExtract(url,heads)
    jsfile.ExtJsExtract(url,heads)
    jsfile.SaveExtJsContent(jsLinkList)
    getSubdomainsfromFile(finallist, url)


def saveandprintdomains():
    print("\n~~~~~~~~~~~~~~~~~~~~~RESULTS~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
    if s3bucketset:
        print(termcolor.colored("Some S3 buckets found. Here are the URLs:\n", color='green', attrs=['bold']))
        for item in s3bucketset:
            print(item)
    else:
        print(termcolor.colored("No S3 buckets were found.\n", color='red', attrs=['bold']))

    if cfset:
        print(termcolor.colored("Some cloudfront domains found. Here are the URLs:", color='green', attrs=['bold']))
        for item in cfset:
            print(termcolor.colored(item, color='blue', attrs=['bold']))
    else:
        print(termcolor.colored("No cloudfront domains found.\n", color='red', attrs=['bold']))

    print("\nSuccessfully got all the subdomains...\n")
    for item in finalset:
        print(termcolor.colored(item, color='green', attrs=['bold']))
    if args.output:
        print("\nWriting all the subdomains to given file...\n")
        with open(args.output, 'w+') as f:
            for item in sorted(finalset):
                f.write(item + '\n')
        print("\nWriting Done..\n")


def printlogo():
    return termcolor.colored(logo(), color='red', attrs=['bold'])


if __name__ == "__main__":
    print(printlogo())
    argerror(url, listfile)
    if listfile:
        urllist = getUrlsFromFile()
        if urllist:
            for i in urllist:
                print(termcolor.colored("Extracting data from internal and external js for url:",color='blue', attrs=['bold'] ))
                print(termcolor.colored(i, color='red', attrs=['bold']))
                try:
                    try:
                        subextractor(i)
                    except requests.exceptions.ConnectionError:
                        print('An error occured while fetching URL, Might be URL is wrong, Please check!')
                except requests.exceptions.InvalidSchema:
                    print("Invalid Schema Provided!")
                    sys.exit(1)
    else:
        try:
            try:
                subextractor(url)
            except requests.exceptions.ConnectionError:
                print('An error occured while fetching URL, Might be server is down, or domain does not exist, Please check!')
                sys.exit(1)
        except requests.exceptions.InvalidSchema:
            print("Invalid Schema Provided!")
            sys.exit(1)

    saveandprintdomains()
