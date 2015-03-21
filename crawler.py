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
from subprocess import check_output, CalledProcessError
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
    logging.info("RUNNING: %s" % cmd)
    try:
        return check_output(cmd, shell=True)
    except CalledProcessError:
        logging.error("CalledProcessError error occurred for %s" % cmd)


# TODO: http://stackoverflow.com/questions/8785217/reliable-and-as-portable
# -as-possible-way-to-map-from-device-name-to-mountpoint
def getmountsonosx(device_identifier):
    '''
        gets mount points on osx
    '''

    # http://stackoverflow.com/questions/2600514/alternative-to-udev-functionality-on-osx
    # TODO
    # 1. Parse `system_profiler SPUSBDataType -xml`
    #   a. for each device without `Built-In` param,
    #      get `Mount Point`, manufacturer, vendor
    # 2. if DEVICES is empty, save them in global variable DEVICEs
    # 3. If new mount points appear, return [ [mp, vendor, prod, manuftr]]
    pass


def getmounstonlinux():
    '''
        get mounts on Linux
    '''
    # TODO
    # 1. Parse OS utility
    #   a. for each USB device get `Mount Point`, manufacturer, vendor
    # 2. if DEVICES is empty, save them in global variable DEVICEs
    # 3. If new mount points appear, return [ [mp, vendor, prod, manuftr]]
    pass


def getnewdevices():
    osname = platform.system()
    if osname == 'Darwin':
        return getmountsonosx()
    elif osname is 'Linux':
        # TODO : find new USB devices on linux
        return getmounstonlinux()


def hotplug_callback(context, device, event):
    device_status = {
        libusb1.LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED: 'arrived',
        libusb1.LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT: 'left',
    }[event]

    if libusb1.LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED:
        print "Device %s: %s" % (device_status, device)
        usbdrives = getnewdevices()
        if usbdrives:
            for device in usbdrives:
                writedata('usbdevice.csv', device)
    else:
        print "Device left: ", device


def writedata(filename, source):
    print "In writedata ", filename, source
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
    print PATH, USB
    # Call to initialize the DEVICES global variable
    print DEVICES
    getnewdevices()
    print DEVICES

    # TODO: device name should be derived from product and vendor IDs
    # Should be human readable.
    FILENAME = 'dev-type.csv'
    if PATH is not None:
        writedata(FILENAME, PATH)

    # Warning: This loop is buggy
    elif USB is not False:
        print "USB mode, baby!"
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
