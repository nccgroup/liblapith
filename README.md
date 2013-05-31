# Liblapith - a library for parsing Nessus results files

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Felix Ingram, felix dot ingram at nccgroup dot com

http://www.github.com/nccgroup/liblaptith

Released under LGPL. See LICENSE for more information

## Example

```
    >>> import liblapith
    >>> scan = liblapith.load("<filename>")
    >>> scan = liblapith.load("<filename>", "<filename>")
    >>> scan = liblapith.load(["<filename>", "<filename>"])
    >>> scan = liblapith.load(<xml string>)
    >>> scan = liblapith.load([<xml string>, <xml string>])
    >>> scan = liblapith.load(open("filename"))
    >>> scan = liblapith.load(open("<filename>"), open("<filename>"))
    >>> scan = liblapith.load([open("<filename>"), open("<filename>")])
    >>> scan.targets.keys()
    ["192.168.0.1", "192.168.0.2", "192.168.0.3", "192.168.0.4"]
    >>> scan.targets["192.168.0.1"]
    {1: <results for plugin ID 1>, 8338: <results for plugin ID>}
    >>> scan.policies
    ["<policy name>", ...]
    >>> scan.plugins.keys()
    [1, 10, 20, ... plugin IDs ..., 8338]
    >>> scan.plugins[8228]
    {"192.168.0.1": <results for host>, ... }
    >>> scan.plugins[8228]["192.168.0.1"]
    {"id": 8338, "name": <plugin name>, "plugin_output": <plugin output>, ...}
    >>> scan.add_file("<filename>")
    >>> scan.plugins[8228]
    {"192.168.0.1": <results for host>, "192.168.2.5": <results for host>, ... }
```
