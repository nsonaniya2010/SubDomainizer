[![Python 3.x](https://img.shields.io/badge/python-3.6%7C3.7-yellow.svg)](https://www.python.org/) 
[![Twitter](https://img.shields.io/badge/twitter-@neeraj_sonaniya-blue.svg)](https://twitter.com/neeraj_sonaniya)

## SubDomainizer

SubDomainizer is a tool designed to find hidden subdomains and secrets present is either webpage, Github, and external javascripts present in the given URL.
This tool also finds S3 buckets, cloudfront URL's and more from those JS files which could be interesting like S3 bucket is open to read/write, or subdomain takeover and similar case for cloudfront.
It also scans inside given folder which contains your files.

## Cloud Storage Services Supported:
SubDomainizer can find URL's for following cloud storage services:
```
1. Amazon AWS services (cloudfront and S3 buckets)
2. Digitalocean spaces 
3. Microsoft Azure 
4. Google Cloud Services 
5. Dreamhost 
6. RackCDN. 
```
## Secret Key's Searching: (beta)
SubDomainizer will also find secrets present in content of the page and javascripts files.
Those secret finding depends on some specific keywords and *Shannon Entropy* formula.
It might be possible that some secrets which searched by tool is false positive.
This secret key searching is in beta and later version might have increased accuracy for search results.

## Screenshot:

![SubDomainizer](https://i.imgur.com/x3XSamk.png)

## Installation Steps

1. Clone SubDomainzer from git:
```
git clone https://github.com/nsonaniya2010/SubDomainizer.git
```
2. Change the directory:
```
cd SubDomainizer
```

3. Install the requirements:

```
pip3 install -r requirements.txt
```
4. Enjoy the Tool.

## Update to latest version:

Use following command to update to latest version:

```
git pull
```

## Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-u            | --url         | URL in which you want to find (sub)domains.
-l            | --listfile    | File which contain list of URL's needs to be scanned.
-o            | --output      | Output file name in which you need to save the results.
-c            | --cookie      | Cookies which needs to be sent with request.
-h            | --help        | show the help message and exit.
-cop          | --cloudop     | Give file name in which you need to store cloud services results.
-d            | --domain      | Give TLD (eg. for www.example.com you have to give example.com) to find subdomain for given TLD.
-g            | --gitscan     | Needed if you want to get things via Github too.
-gt           | --gittoken    | Github API token is needed, if want to scan (also needed -g also).
-k            | --nossl         |  Use this to bypass the verification of SSL certificate.
-f           | --folder        | Root folder which contains files/folder.

### Examples
* To list help about the tool:
```
python3 SubDomainizer.py -h
```
* To find subdomains, s3 buckets, and cloudfront URL's for given single URL:
```
python3 SubDomainizer.py -u http://www.example.com
```
* To find subdomains from given list of URL (file given):
```
python3 SubDomainizer.py -l list.txt
```

* To save the results in (output.txt) file:
```
python3 SubDomainizer.py -u https://www.example.com -o output.txt
```
* To give cookies:
```
python3 SubDomainizer.py -u https://www.example.com -c "test=1; test=2"
```
* To scan via github:
```
python3 SubDomainizer.py -u https://www.example.com -o output.txt -gt <github_token> -g 
```
* No SSL Certificate Verification:
```
python3 SubDomainizer.py -u https://www.example.com -o output.txt -gt <github_token> -g  -k
```
* Folder Scanning:
```
python3 SubDomainizer.py -f /path/to/root/folder/having/files/and/folders/  -d example.com  -gt <github_token> -g  -k
```

## Difference in results (with cookies and without cookies on facebook.com):

Results before using facebook cookies in SubDomainizer:

![BeforeCookies](https://i.imgur.com/v7igAId.png)

Results after using facebook cookies in SubDomainizer:

![AfterCookies](https://i.imgur.com/QKY09mx.png)

## License
This tools is licensed under the MIT license. take a look at the [LICENSE](https://github.com/nsonaniya2010/SubDomainizer/blob/master/LICENSE) fore information about it.

## Version
**Current version is 1.4**

## Want to Donate?
Want to donate for the improvement in features and tools? or Liked this tool?
[Donate Here](https://paypal.me/BugsByNeeraj)
