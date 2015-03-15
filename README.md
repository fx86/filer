# filer
Walks portable memory and provides easy search for laters. ;)

* Uses pyusb to gather information about the portable memory.

##### Warning:

* If you see "Backend not available" error, you will need to set the DYLD_LIBRARY_PATH variable for the library to work 
  This helped on my local setup:

  > export DYLD_LIBRARY_PATH=/opt/local/lib/:$DYLD_LIBRARY_PATH