'''
    Crawls a given file path and gets meta data
'''
import sys
import os
import time
import hashlib
import csv
from collections import OrderedDict

import magic  # python-magic

KEYS = ['path', 'ctime', 'filetype', 'filesize', 'mtime', 'atime', 'digest']


class CSVWriter:
    # source:
    # http://python-forensics.org/2014/06/python-forensics-sqlite-invesigations-part-one/

    def __init__(self, csvfile):
        try:
            # create a writer object and then write the header row
            self.csvfile = open(csvfile, 'w')
            self.writer = csv.DictWriter(self.csvfile, fieldnames=KEYS)
            self.writer.writeheader()
        except csv.Error as error:
            print "CSV File: Initialization Failed"
            print error
            sys.exit(1)

    def writerow(self, row):
        try:
            self.writer.writerow(row)
        except csv.Error as error:
            print "CSV File Write: Failed"
            print "Error: ", error
            sys.exit(1)

    def close(self):
        # Close the CSV File
        try:
            self.csvfile.close()
        except:
            print "Failed to close CSV File Object"
            sys.exit(1)


def getfilepaths(pth):
    return [os.path.join(dp, f) for dp, dn, fn in os.walk(pth) for f in fn]


def getmetadata(path):
    '''
        captures metadata of path received.
    '''
    metadata = OrderedDict()
    (mde, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(path)
    # file size in bytes
    metadata['path'] = path
    metadata['filesize'] = size
    # access time
    metadata['atime'] = time.asctime(time.localtime(atime))
    # modified time
    metadata['mtime'] = time.asctime(time.localtime(mtime))
    # time of most recent metadata change on Unix,
    # or the time of creation (Windows)
    metadata['ctime'] = time.asctime(time.localtime(ctime))
    metadata['filetype'] = magic.from_file(path, mime=True)
    metadata['digest'] = hashlib.md5(path).hexdigest()
    return metadata

if __name__ == "__main__":
    PATH = sys.argv[1]
    print "PATH to be scraped: ", PATH

    allpaths = getfilepaths(PATH)
    capturedata = CSVWriter('testfile.csv')
    for path in allpaths:
        meta = getmetadata(path)
        capturedata.writerow(meta)
    capturedata.close()
