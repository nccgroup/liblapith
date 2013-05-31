# Liblapith - a library for parsing Nessus results files

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
    >>> scan.targets
    ["192.168.0.1", "192.168.0.2", "192.168.0.3", "192.168.0.4"]
    >>> scan.policies
    ["<policy name>", ...]
    >>> scan.plugins
    [1, 10, 20, ... plugin IDs ..., 8338]
    >>> scan.targets["192.168.0.1"]
    {1: <results for plugin ID 1>, 8338: <results for plugin ID>}
    >>> scan.plugins[8228]
    {"192.168.0.1": <results for host>, ... }
    >>> scan.plugins[8228]["192.168.0.1"]
    {"id": 8338, "name": <plugin name>, "plugin_output": <plugin output>, ...}
    >>> scan.add_results("<filename>")
    >>> scan.plugins[8228]
    {"192.168.0.1": <results for host>, "192.168.2.5": <results for host>, ... }
```
