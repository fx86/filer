# filer
Walks portable memory and provides easy search for laters. ;)

* Uses pyusb to gather information about the portable memory.


##### Search for a python package for USB:

I'm looking for a package which accurately identifies USB drives. From the intensive googling that has been done recently by yours truly, I figure that the package should find devices of  deviceClass 9, its vendor and product IDs and the paths that they are mounted at. Maybe, their human-readable names as well. 

1. [PyUSB](https://github.com/walac/pyusb/blob/master/docs/tutorial.rst):

At first, I thought this would be *the* library. But once I got it to work, I started having second thoughts. 
* PyUSB seems to be an overkill. This project didn't need communication between the device; I am planning to use `os.walk` to walk the flash-drive directories. And sometimes inaccurate ; for example, at multiple times it showed devices which had been removed.

* It was also unable to read Manufacturer and device strings using the .manufacturer function()
Weirdly, `usb.util.get_string(xdev, xdev.iManufacturer)` would work.

* If you see "Backend not available" error while importing, you will need to set the DYLD_LIBRARY_PATH variable for the library to work 
  This helped on my local setup:

  > export DYLD_LIBRARY_PATH=/opt/local/lib/:$DYLD_LIBRARY_PATH
  
2. [pyudev](https://pyudev.readthedocs.org/en/latest/):
* Next up is pyudev. This seems like the *man for the job*. But I'm going to list all packages before coming back to evaluate this.

3. 
