# SNMP_DISCOVERY

This code will enable windows users to discover all print devices that are present in the network.
net-snmp is the main C API(free) used for discovery.

You can download the library at http://net-snmp.sourceforge.net/

Note:
- You must know the network address of your LAN
- To get information from network device you must know the OIDs per device
- Have knowledge to the authentication settings of the network device
- To start, call init and provide the properties of DiscoverDeviceReq object
