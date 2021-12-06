import re
import os
import pprint

from netmiko import __version__ as netmiko_version

from netaddr import IPAddress

# NAPALM base
import napalm.base.constants as C
from napalm.base.base import NetworkDriver
from napalm.base import helpers
from napalm.base.exceptions import CommandErrorException, ReplaceConfigException
from napalm.base.netmiko_helpers import netmiko_args
from napalm.base.exceptions import ConnectionException, MergeConfigException, \
                                   ReplaceConfigException, CommitError, \
                                   CommandErrorException

class StarOSDriver(NetworkDriver):
    
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        if optional_args is None:
            optional_args = {}

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.replace = True
        self.loaded = False
        self.changed = False
        self.netmiko_optional_args = netmiko_args(optional_args)
        self.device = None
        self.platform = "staros"


    def open(self):
        self.device = self._netmiko_open(
            device_type="terminal_server", netmiko_optional_args=self.netmiko_optional_args
        )


    def close(self):
        self._netmiko_close()


    def _send_command(self, command, raw_text=False, cmd_verify=True):
        """
        Wrapper for Netmiko's send_command method.
        """
        return self.device.send_command(command, cmd_verify=cmd_verify)


    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        null = chr(0)
        try:
            if self.device is None:
                return {"is_alive": False}
            else:
                # Try sending ASCII null byte to maintain the connection alive
                self._send_command(null, cmd_verify=False)
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure that the connection is unusable,
            # hence return False.
            return {"is_alive": False}
        return {"is_alive": self.device.remote_conn.transport.is_active()}

    
    def get_facts(self):
        """Return a set of facts from the devices."""
        # default values.
        vendor = "Cisco"
        uptime = -1
        serial_number, fqdn, os_version, hostname, domain_name, model = ("",) * 6

        # obtain output from device
        show_ver = self._send_command("show version")
        #show_hosts = self._send_command("show hosts")
        show_int_status = self._send_command("show ip interface summary")
        #show_hostname = self._send_command("show hostname")
        show_system_uptime = self._send_command("show system uptime")
        show_hardware = self._send_command("show hardware")

        # Uptime
        uptime = " ".join(show_system_uptime.splitlines()[1].split()[2:])

        # StarOS Version
        for line in show_ver.splitlines():
            if "Image Version: " in line:
                line = line.strip()
                os_version = line.split()[2]
                os_version = os_version.strip()

        # Serial Number
        for line in show_hardware.splitlines():
            if "UUID/Serial Number" in line:
                line = line.strip()
                serial_number = line.split()[3].strip()

        #hostname = show_hostname.strip()

        # interface_list filter
        interface_list = []
        show_int_status = show_int_status.strip()

        for line in show_int_status.splitlines()[3:-1]:
            if not line:
                continue
            interface = line.split()[0]
            # Return canonical interface name
            interface_list.append(helpers.canonical_interface_name(interface))

        return {
            "uptime": uptime,
            "vendor": vendor,
            "os_version": str(os_version),
            "serial_number": str(serial_number),
            "model": "VPC-SI",
            "hostname": str(hostname),
            "fqdn": fqdn,
            "interface_list": interface_list,
        }


    def get_config(self, retrieve="all", full=False, sanitized=False):
        """
        Return the configuration of a device.

        Args:
            retrieve(string): Which configuration type you want to populate, default is all of them.
                              The rest will be set to "".
            full(bool): Retrieve all the configuration. For instance, on ios, "sh run all".
            sanitized(bool): Remove secret data. Default: ``False``.

        Returns:
          The object returned is a dictionary with a key for each configuration store:

            - running(string) - Representation of the native running configuration
            - candidate(string) - Representation of the native candidate configuration. If the
              device doesnt differentiate between running and startup configuration this will an
              empty string
            - startup(string) - Representation of the native startup configuration. If the
              device doesnt differentiate between running and startup configuration this will an
              empty string
        """

        # default values
        config = {"startup": "", "running": "", "candidate": ""}  

        running = str(
            self._send_command("show config")
        )
        
        config["running"] =  running.strip()

        return config


    def get_interfaces_ip(self):
        '''
        Friday September 17 08:23:15 UTC 2021
        Intf Name:       LOCAL1
        Intf Type:       Broadcast
        Description:
        VRF:             None
        IP State:        UP (Bound to 1/1 untagged, ifIndex 16842753)
        IP Address:      10.32.20.12          Subnet Mask:     255.255.255.0   
        Bcast Address:   10.32.20.255         MTU:             1500
        Resoln Type:     ARP                  ARP timeout:     1200 secs
        L3 monitor LC-port switchover: Disabled
        Number of Secondary Addresses: 0
        '''
        cmd_output = self._send_command("show ip interface").splitlines()

        #print(cmd_output)

        iface_name = cmd_output[1].split()[2]
        iface_type = cmd_output[2].split()[2]
        ip_addr = cmd_output[6].split()[2]
        subnet_mask = cmd_output[6].split()[5]

        prefix_len = IPAddress(subnet_mask).netmask_bits()
            
        interfaces_ip = {}
        interfaces_ip[iface_name] = {
            'ipv4': {
                ip_addr: {
                    'prefix_length': prefix_len
                }
            }
        }

        return interfaces_ip
