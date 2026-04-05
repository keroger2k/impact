"""
Collector registry.

To add a new platform:
  1. Create collectors/<platform>.py and subclass BaseCollector.
  2. Add one entry to _REGISTRY below: "myplatform": ("collectors.mymodule", "MyClass")
  3. Use that type string in devices.txt.

Imports are intentionally lazy (done inside get_collector_class at call time)
to prevent circular-import errors on Windows and to keep startup fast when
only a subset of platform modules are actually needed.

Type strings are case-insensitive.
"""

import importlib

# Registry: type string → (module_path, class_name)
_REGISTRY: dict[str, tuple[str, str]] = {
    # Palo Alto
    "paloalto":       ("collectors.paloalto",        "PaloAltoCollector"),
#    "panorama":       ("collectors.paloalto",        "PaloAltoCollector"),  # M-600

    # Cisco NX-OS (SSH)
    "nxos":           ("collectors.nxos",            "NXOSCollector"),

    # Cisco IOS / IOS-XE via Catalyst Center REST API
 #   "catalystcenter": ("collectors.cisco_catalyst",  "CatalystCenterCollector"),
  #  "dnac":           ("collectors.cisco_catalyst",  "CatalystCenterCollector"),  # alias

    # Future
    # "ios":          ("collectors.ios",             "IOSCollector"),       # direct SSH
    # "f5":           ("collectors.f5",              "F5Collector"),
    # "juniper":      ("collectors.juniper",         "JuniperCollector"),
}


def get_collector_class(platform_type: str):
    """
    Look up and return a collector class by platform type string.
    Module is imported on first use (lazy) — not at package load time.
    Returns None if the type is not registered.
    """
    entry = _REGISTRY.get(platform_type.lower())
    if entry is None:
        return None
    module_path, class_name = entry
    module = importlib.import_module(module_path)
    return getattr(module, class_name)