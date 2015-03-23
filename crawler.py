'''
    Crawls a given file path and gets meta data
    Usage:
        python crawler.py --usb True
        OR
        python crawler.py <path-to-directory>
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

md5 = hashlib.md5()
KEYS = ['path', 'ctime', 'filetype', 'filesize', 'mtime', 'atime', 'digest']
CACHE = {}


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
            self.csvfile.flush()
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


def checksum_md5(filename, blocksize=128 * md5.block_size):
    '''
        Get md5 digest of file
    '''
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(blocksize), b''):
            md5.update(chunk)
    return md5.hexdigest()


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
        metadata['digest'] = checksum_md5(path)
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
def get_mounts_osx():
    '''
        parses system_profiler for mount information,
        to get name, manufacturer and mount points.
        Passes them to write_data to walk and save metadata.
    '''
    from plistlib import readPlistFromString as rPFS
    time.sleep(5)
    alldetails = []
    alldevices = rPFS(run('system_profiler SPUSBDataType -xml'))[0]['_items']
    for num in range(len(alldevices)):
        for dev in alldevices[num]['_items']:
            if (dev.get('Built-in_Device') != 'Yes'):
                temp = {'mount_point': [],
                        'volume_name': [],
                        'volume_uuid': []}

                for param in ['_name', 'manufacturer',
                              'product_id', 'vendor_id']:
                    temp[param] = dev.get(param)
                if 'volumes' in dev:
                    for ind, eachvol in enumerate(dev['volumes']):
                        mp = dev['volumes'][ind].get('mount_point', '')
                        name = dev['volumes'][ind].get('_name', '')
                        vol_uuid = dev['volumes'][ind].get('volume_uuid', '')
                        temp['mount_point'].append(mp)
                        temp['volume_name'].append(name)
                        temp['volume_uuid'].append(vol_uuid)
                alldetails.append(temp)
    return alldetails


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


def get_new_devices():
    '''
        Calls the right function based on the
        platform.
    '''
    osname = platform.system()
    if osname == 'Darwin':
        return get_mounts_osx()
    elif osname is 'Linux':
        # TODO : find new USB devices on linux
        return getmounstonlinux()
    else:
        print "Not implemented for :", osname
        return []


def hotplug_callback(context, device, event):
    '''
        libbusb call-back when device arrives / leaves.
        On arrival, we crawl it.
    '''
    if libusb1.LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED:
        usbdrives = get_new_devices()
        if usbdrives:
            for dev in usbdrives:
                for mnt, vol, uuid in zip(dev['mount_point'],
                                          dev['volume_name'],
                                          dev['volume_uuid']):
                    key = md5("%s-%s-%s" % (mnt, vol, uuid)).hexdigest()
                    created_on = os.stat(mnt).st_ctime
                    if CACHE.get(key) < created_on:
                        CACHE[key] = time.time()
                        if mnt:
                            filename = vol + " " + time.ctime(time.time())
                            write_data(filename + '.csv', mnt)
                    else:
                        print "IGNORING cached device: ", vol
                        logging.info("CACHED : %s" % mnt)
    else:
        print "Device left: ", device


def write_data(fname, source):
    '''
        Writes metadata for each file to a specific csv file
    '''
    mesg = "Crawling {:s}. Saving it to: {:s}".format(source, fname)
    print mesg
    logging.info(mesg)
    allpaths = getfilepaths(source)
    capturedata = CSVWriter(fname)
    for path in allpaths:
        meta = getmetadata(path)
        if meta:
            capturedata.writerow(meta)
        else:
            logging.info("Found no meta for path : %s" % path)
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

    temp_filename = "".join([x if x.isalnum() else "_" for x in PATH])
    FILENAME = temp_filename + time.ctime(time.time()) + ".csv"
    if PATH is not None:
        write_data(FILENAME, PATH)

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
            sys.exit(1)

    TOTALTIME = time.time() - STARTINGTIME
    logging.info("Crawl completed in : %s" % TOTALTIME)
