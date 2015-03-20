'''
    Detect and file all interesting artifacts from
    USB drives
'''
import usb
import usb.backend.libusb1


def get_devices():
    busses = usb.busses()
    for bus in busses:
        devices = bus.devices
        for dev in devices:
            vendor, product = dev.idVendor, dev.idProduct
            print dev.deviceClass, dev.deviceClass == 9, vendor, product
            if dev is None:
                # and dev.deviceClass == 9:
                try:
                    xdev = usb.core.find(idVendor=vendor, idProduct=product)
                    if xdev._manufacturer is None:
                        xdev._manufacturer = usb.util.get_string(
                            xdev, xdev.iManufacturer)
                    if xdev._product is None:
                        xdev._product = usb.util.get_string(
                            xdev, xdev.iProduct)
                    printstring = str(xdev._manufacturer).strip()
                    printstring = ' = ' + str(xdev._product).strip()
                    stx = '%6d %6d: ' + printstring
                    print stx % (vendor, dev.idProduct)
                    print dev.manufacturer
                except:
                    pass

if __name__ == '__main__':
    get_devices()
