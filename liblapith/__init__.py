# Released as open source by NCC Group Plc - http://www.nccgroup.com/
# Developed by Felix Ingram, felix dot ingram at nccgroup dot com
# http://www.github.com/nccgroup/liblapith
# Released under LGPL. See LICENSE for more information

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET

from itertools import chain
from collections import defaultdict
from datetime import datetime

PLUGIN_MULTITAGS = (
        ("bid", int),
        ("cert", str),
        ("cve", str),
        ("edb-id", str),
        ("osvdb", int),
        ("see_also", str),
        ("xref", str),
        )
PLUGIN_TAGS = (
        ("cpe", str),
        ("cvss_base_score", float),
        ("cvss_temporal_score", float),
        ("cvss_temporal_vector", str),
        ("cvss_vector", str),
        ("description", str),
        ("exploit_available", str),
        ("exploitability_ease", str),
        ("fname", str),
        ("patch_publication_date", lambda x: datetime.strptime(x, "%Y/%m/%d")),
        ("plugin_modification_date", lambda x: datetime.strptime(x, "%Y/%m/%d")),
        ("plugin_name", str),
        ("plugin_output", str),
        ("plugin_publication_date", lambda x: datetime.strptime(x, "%Y/%m/%d")),
        ("plugin_type", str),
        ("risk_factor", str),
        ("solution", str),
        ("synopsis", str),
        ("vuln_publication_date", lambda x: datetime.strptime(x, "%Y/%m/%d")),
        )

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

    def __repr__(self):
        if len(self._scan_list) == 1:
            return "<Results - {0} scan>".format(len(self._scan_list))
        else:
            return "<Results - {0} scans>".format(len(self._scan_list))

    @property
    def targets(self):
        hosts = chain.from_iterable(x.findall("Report/ReportHost") for x in self._scan_list)
        keys = (x.findall("HostProperties/tag[@name='host-ip']") for x in hosts)
        result = defaultdict(dict)
        for host in hosts:
            ip = host.findtext("HostProperties/tag[@name='host-ip']", "NO-IP")
            items = host.findall("ReportItem")
            for item in items:
                id_ = int(item.attrib["pluginID"])
                attribs = item.attrib
                for tag, conv in PLUGIN_TAGS:
                    text = item.findtext(tag)
                    if text: attribs[tag] = conv(text)
                for tag, conv in PLUGIN_MULTITAGS:
                    tags = item.findall(tag)
                    if tags:
                        texts = (x.findtext(".") for x in tags)
                        attribs[tag] = list(conv(x) for x in texts if x)
                result[ip][id_] = attribs
        return result

    @property
    def policies(self):
        policies = (x.findtext("Policy/policyName", "NO POLICY NAME") for x in
                self._scan_list)
        return list(policies)

    @property
    def plugins(self):
        items = chain.from_iterable(x.findall("Report/ReportHost/ReportItem") for x in
                self._scan_list)
        keys = (int(x.attrib["pluginID"]) for x in items)
        result = dict()
        targets = self.targets
        for key in keys:
            hosts = dict()
            for host in targets:
                if key in targets[host]:
                    hosts[host] = targets[host][key]
            result[key] = hosts
        return result

    def add_file(self, obj):
        try:
            self._scan_list.append(ET.parse(obj))
        except (IOError):
            ## passed a string that cannot be found, so assume it's
            ## XML data
            try:
                self._scan_list.append(ET.fromstring(obj))
            except (ET.ParseError):
                raise TypeError("Could not parse", obj)
