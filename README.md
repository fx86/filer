# filer
Walks portable memory and provides easy search for laters. ;)

Current setup intends to use the following libraries:

* sudo port install libmagic
* git clone git@github.com:ahupp/python-magic.git
	* cd `python-magic`
	* `python setup.py install`

To run:
After the above installation steps, type the following in the terminal:

python crawler.py `direct-path-to-USB-device`

Goals:

1. Crawl USB devices surreptiously
2. Write results to a database
3. Comprehensive file type detection