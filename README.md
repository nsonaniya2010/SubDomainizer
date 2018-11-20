## SubDomainizer
SubDomainizer is a tool designed to find hidden subdomains present is either inline javascript or external javascripts present in the given URL.
This tool also finds S3 buckets, cloudfront URL's and more from those JS files which could be interesting like S3 bucket is open to read/write, or subdomain takeover and similar case for cloudfront.


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
sudo apt-get update
sudo apt-get install python3-termcolor python3-bs4 python3-requests python3-htmlmin python3-tldextract
```
4. Enjoy the Tool.

## Usage

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-u            | --url         | URL in which you want to find (sub)domains.
-l            | --listfile    | File which contain list of URL's needs to be scanned.
-o            | --output      | Output file name in which you need to save the results.
-c            | --cookie      | Cookies which needs to be sent with request.
-h            | --help        | show the help message and exit.
-cop          | --cloudop     | Give file name in which you need to store cloud services results.

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

## License
This tools is licensed under the GNU GPL license. take a look at the [LICENSE](https://github.com/nsonaniya2010/SubDomainizer/blob/master/LICENSE) fore information about it.

## Version
**Current version is 1.0**

## Want to Donate?
Want to donate for the improvement in features and tools? or Liked this tool?
[Donate Here](https://paypal.me/BugsByNeeraj)
