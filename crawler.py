'''
    Crawls a given file path and gets meta data
'''
import sys
import os
import time
import hashlib
import csv
import logging
import platform
import argparse
from subprocess import Popen, PIPE, CalledProcessError
from collections import OrderedDict

import magic  # python-magic
import usb1
import libusb1

KEYS = ['path', 'ctime', 'filetype', 'filesize', 'mtime', 'atime', 'digest']
DEVICES = []


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
            logging.info("CSV File: Initialization Failed")
            logging.info(error)
            sys.exit(1)

    def writerow(self, row):
        try:
            self.writer.writerow(row)
        except csv.Error as error:
            logging.info("CSV File Write: Failed")
            logging.info(error)
            sys.exit(1)

    def close(self):
        # Close the CSV File
        try:
            self.csvfile.close()
        except:
            logging.info("Failed to close CSV File Object")
            sys.exit(1)


def getfilepaths(pth):
    return [os.path.join(dp, f) for dp, dn, fn in os.walk(pth) for f in fn]


def getmetadata(path):
    '''
        captures metadata of path received.
    '''
    try:
        metadata = OrderedDict()
        meta = os.stat(path)
        (mde, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = meta
        # file size in bytes
        metadata['path'] = path
        metadata['filesize'] = size
        for timestamp in ['atime', 'mtime', 'ctime']:
            metadata[timestamp] = time.asctime(time.localtime(eval(timestamp)))
        metadata['filetype'] = magic.from_file(path, mime=True)
        metadata['digest'] = hashlib.md5(path).hexdigest()
        return metadata
    except Exception, error:
        logging.info('Error capturing metadata for %s' % path)
        logging.info('Error is %s' % error)


def run(cmd):
    '''
        Runs commands and returns results
    '''
    proc = Popen(cmd.split(),
                 stdout=PIPE,
                 stderr=PIPE)
    output, errors = proc.communicate()
    returncode = proc.returncode
    if returncode:
        print " >> ", output
        print " << ", errors
        raise CalledProcessError(returncode, 'description')
    return output


def getdevicepath():
    '''
        platform agnostic function that finds USB devices
    '''
    global DEVICES
    osname = platform.system()
    print "OS name is:", osname, osname == 'Darwin'
    if osname == 'Darwin':
        devices = run('diskutil list | grep /dev/')
    elif osname is 'Linux':
        devices = run('ls -l /dev/disk/')

    if DEVICES is None:
        DEVICES = devices
    else:
        return [dev for dev in devices if dev not in DEVICES]


def hotplug_callback(context, device, event):
    device_status = {
        libusb1.LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED: 'arrived',
        libusb1.LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT: 'left',
    }[event]

    print "Device %s: %s" % (device_status, device)
    if device_status == 'arrived':
        usbdrive = getdevicepath()
        writedata(usbdrive)


def writedata(filename, source):
    logging.info("Crawling path: %s" % source)
    allpaths = getfilepaths(source)
    capturedata = CSVWriter(filename)
    for path in allpaths:
        meta = getmetadata(path)
        capturedata.writerow(meta)
    capturedata.close()


if __name__ == "__main__":
    logging.basicConfig(filename='filer.log',
                        level=logging.NOTSET,
                        format='%(asctime)s %(message)s')

    parser = argparse.ArgumentParser()
    parser.add_argument("--path", help="Direct file path to be crawled",
                        type=str)
    parser.add_argument("--usb", help="In USB mode, script monitors for events \
                        and crawls them continuously", default=False)
    args = parser.parse_args()
    PATH, USB = args.path, args.usb
    STARTINGTIME = time.time()

    # Call to initialize the DEVICES global variable
    getdevicepath()

    # TODO: device name should be derived from product and vendor IDs
    # Should be human readable.
    FILENAME = 'dev-type.csv'
    if PATH is not None:
        writedata(FILENAME)

    # Warning: This loop is buggy
    elif USB is not False:
        context = usb1.USBContext()
        if not context.hasCapability(libusb1.LIBUSB_CAP_HAS_HOTPLUG):
            print 'Hotplug support is missing. Please update libusb version.'
            sys.exit(1)
        opaque = context.hotplugRegisterCallback(hotplug_callback)
        try:
            while True:
                context.handleEvents()
        except (KeyboardInterrupt, SystemExit):
            print "Exiting.."
            pass

    TOTALTIME = time.time() - STARTINGTIME
    logging.info("Crawl completed in : %s" % TOTALTIME)
