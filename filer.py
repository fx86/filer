'''
	Detect and file all interesting artifacts from
	USB drives
'''
import usb.core as we
import os


def get_devices():
	'''
		Returns a list of devices.
	'''

	devices = we.find(bDeviceClass=9, find_all=True)
	devices_FOUND = sum([1 for _ in we.find(bDeviceClass=9, find_all=True)])
	print "Found {:d} devices".format(devices_FOUND)

	for dev in devices:
		try:
			#print dev
			print dev.manufacturer, dev.product, dev.serial_number, dev.bDeviceClass
		except (AttributeError, we.USBError) as error:
			print str(error)
			pass

if __name__ == '__main__':
	get_devices()
