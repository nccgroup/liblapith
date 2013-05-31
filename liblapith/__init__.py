# Released as open source by NCC Group Plc - http://www.nccgroup.com/
# Developed by Felix Ingram, felix dot ingram at nccgroup dot com
# http://www.github.com/nccgroup/liblapith
# Released under LGPL. See LICENSE for more information

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET

from itertools import chain

def load(objects):
    if not isinstance(objects, list):
        objects = [objects]
    scanned = []
    for scan in objects:
        try:
            scanned.append(ET.parse(scan))
        except (IOError):
            ## passed a string that cannot be found, so assume it's
            ## XML data
            try:
                scanned.append(ET.fromstring(scan))
            except (ET.ParseError):
                raise TypeError("Could not parse", scan)
    return Results(scanned)

class Results:
    def __init__(self, scan_list):
        self._scan_list = scan_list

    @property
    def targets(self):
        tags = (x.findall(".//ReportHost/HostProperties/tag[@name='host-ip']")
                for x in self._scan_list)
        ips = (y.text for y in chain.from_iterable(tags))
        return list(ips)

    def __repr__(self):
        if len(self._scan_list) == 1:
            return "<Results - {0} scan>".format(len(self._scan_list))
        else:
            return "<Results - {0} scans>".format(len(self._scan_list))
