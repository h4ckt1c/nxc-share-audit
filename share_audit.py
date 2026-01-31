#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetExec Module: share_audit
Author: Pentest Module
Description: Enumerates SMB shares and their permissions (Share ACLs)

This module lists all shares on a remote Windows host and shows the share permissions.
Useful for identifying overly permissive shares during penetration tests.

Usage:
    nxc smb <target> -u <user> -p <pass> -M share_audit
    nxc smb <target> -u <user> -p <pass> -M share_audit -o DETAILED=true
"""

from impacket.dcerpc.v5 import transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket import nt_errors
from impacket.dcerpc.v5.rpcrt import DCERPCException
import traceback


class CMEModule:
    name = "share_audit"
    description = "Enumerate SMB shares and their permissions"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        DETAILED    Show detailed ACL information (default: false)
        """
        self.detailed = False

        if "DETAILED" in module_options:
            self.detailed = module_options["DETAILED"].lower() == "true"

    def on_login(self, context, connection):
        """
        Main module execution - runs after successful authentication
        """
        context.log.info("Starting share permissions audit")

        try:
            shares = self.enum_shares(context, connection)

            if not shares:
                context.log.info("No shares found or unable to enumerate shares")
                return

            context.log.success(f"Found {len(shares)} share(s)")

            for share in shares:
                self.display_share_info(context, share)

        except Exception as e:
            context.log.error(f"Error during share enumeration: {str(e)}")
            if context.log.level == "DEBUG":
                context.log.error(traceback.format_exc())

    def enum_shares(self, context, connection):
        """
        Enumerate shares and their permissions using NetShareEnum and NetShareGetInfo
        """
        shares_info = []

        try:
            # Build RPC connection string
            binding = f"ncacn_np:{connection.host}[\\pipe\\srvsvc]"
            rpctransport = transport.DCERPCTransportFactory(binding)

            # Set credentials
            rpctransport.set_credentials(
                connection.username,
                connection.password,
                connection.domain,
                connection.lmhash,
                connection.nthash
            )

            # Set timeouts
            rpctransport.set_connect_timeout(10)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)

            # Enumerate shares (Level 1 - basic info)
            resp = srvs.hNetrShareEnum(dce, 1)

            for share in resp['InfoStruct']['ShareInfo']['Level1']['Buffer']:
                share_name = share['shi1_netname'][:-1]  # Remove null terminator
                share_type = share['shi1_type']
                share_comment = share['shi1_remark'][:-1] if share['shi1_remark'] else ""

                # Skip IPC$ and special administrative shares if desired
                # (but we'll show them with a note)

                # Get detailed share info including Security Descriptor (Level 502)
                try:
                    resp502 = srvs.hNetrShareGetInfo(dce, share_name + '\x00', 502)
                    security_descriptor = resp502['InfoStruct']['ShareInfo502']['shi502_security_descriptor']

                    permissions = self.parse_security_descriptor(context, security_descriptor)

                    shares_info.append({
                        'name': share_name,
                        'type': self.get_share_type(share_type),
                        'comment': share_comment,
                        'permissions': permissions
                    })

                except DCERPCException as e:
                    if 'ACCESS_DENIED' in str(e):
                        context.log.error(f"Access denied getting info for share: {share_name}")
                        shares_info.append({
                            'name': share_name,
                            'type': self.get_share_type(share_type),
                            'comment': share_comment,
                            'permissions': ['ACCESS DENIED']
                        })
                    else:
                        context.log.error(f"Error getting info for share {share_name}: {str(e)}")

            dce.disconnect()

        except Exception as e:
            context.log.error(f"RPC Error: {str(e)}")
            if context.log.level == "DEBUG":
                context.log.error(traceback.format_exc())

        return shares_info

    def parse_security_descriptor(self, context, sd):
        """
        Parse a Security Descriptor and extract ACL entries
        """
        permissions = []

        if not sd:
            return ["No security descriptor available"]

        try:
            # The security descriptor has a DACL (Discretionary Access Control List)
            if hasattr(sd, 'Dacl') and sd['Dacl']:
                dacl = sd['Dacl']

                if hasattr(dacl, 'Data') and dacl['Data']:
                    for ace_count in range(dacl['Data']['AceCount']):
                        ace = dacl['Data']['Data'][ace_count]

                        # Get the SID from the ACE
                        sid = ace['Ace']['Sid'].formatCanonical()

                        # Get access mask (permissions)
                        mask = ace['Ace']['Mask']['Mask']

                        # Get ACE type (Allow/Deny)
                        ace_type = ace['TypeName']

                        # Translate SID to name if possible (common ones)
                        trustee = self.translate_sid(sid)

                        # Translate access mask to readable permissions
                        perms = self.translate_permissions(mask)

                        perm_string = f"{trustee}: {perms} ({ace_type})"
                        permissions.append(perm_string)
                else:
                    permissions.append("Empty DACL (No access)")
            else:
                permissions.append("No DACL (Everyone Full Control)")

        except Exception as e:
            context.log.error(f"Error parsing security descriptor: {str(e)}")
            permissions.append(f"Error parsing: {str(e)}")

        return permissions

    def translate_sid(self, sid):
        """
        Translate well-known SIDs to friendly names
        """
        well_known_sids = {
            'S-1-1-0': 'Everyone',
            'S-1-5-7': 'Anonymous',
            'S-1-5-11': 'Authenticated Users',
            'S-1-5-18': 'SYSTEM',
            'S-1-5-19': 'LOCAL SERVICE',
            'S-1-5-20': 'NETWORK SERVICE',
            'S-1-5-32-544': 'Administrators',
            'S-1-5-32-545': 'Users',
            'S-1-5-32-546': 'Guests',
            'S-1-5-32-547': 'Power Users',
            'S-1-5-32-548': 'Account Operators',
            'S-1-5-32-549': 'Server Operators',
            'S-1-5-32-550': 'Print Operators',
            'S-1-5-32-551': 'Backup Operators',
            'S-1-5-32-552': 'Replicators',
        }

        return well_known_sids.get(sid, sid)

    def translate_permissions(self, mask):
        """
        Translate access mask to readable permissions
        For shares, the common permissions are:
        - Full Control: 0x001F01FF
        - Change: 0x001301BF
        - Read: 0x001200A9
        """
        # File/Share access rights
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        GENERIC_EXECUTE = 0x20000000
        GENERIC_ALL = 0x10000000

        FILE_READ_DATA = 0x0001
        FILE_WRITE_DATA = 0x0002
        FILE_APPEND_DATA = 0x0004
        FILE_EXECUTE = 0x0020

        # Standard rights
        DELETE = 0x00010000
        READ_CONTROL = 0x00020000
        WRITE_DAC = 0x00040000
        WRITE_OWNER = 0x00080000

        # Common combinations
        FULL_CONTROL = 0x001F01FF
        CHANGE = 0x001301BF
        READ = 0x001200A9

        if mask == FULL_CONTROL or mask == GENERIC_ALL:
            return "Full Control"
        elif mask == CHANGE:
            return "Change"
        elif mask == READ or mask == GENERIC_READ:
            return "Read"
        else:
            # Break down the permissions
            perms = []
            if mask & (GENERIC_READ | FILE_READ_DATA):
                perms.append("Read")
            if mask & (GENERIC_WRITE | FILE_WRITE_DATA):
                perms.append("Write")
            if mask & (GENERIC_EXECUTE | FILE_EXECUTE):
                perms.append("Execute")
            if mask & DELETE:
                perms.append("Delete")
            if mask & WRITE_DAC:
                perms.append("Change Permissions")
            if mask & WRITE_OWNER:
                perms.append("Take Ownership")

            if perms:
                return ", ".join(perms)
            else:
                return f"Custom (0x{mask:08X})"

    def get_share_type(self, share_type):
        """
        Translate share type to readable string
        """
        types = {
            0: "Disk",
            1: "Print Queue",
            2: "Device",
            3: "IPC",
            0x80000000: "Hidden Disk",
            0x80000001: "Hidden Print",
            0x80000002: "Hidden Device",
            0x80000003: "Hidden IPC"
        }
        return types.get(share_type, f"Unknown ({share_type})")

    def display_share_info(self, context, share):
        """
        Display share information in a readable format
        """
        share_name = share['name']
        share_type = share['type']
        comment = share['comment']
        permissions = share['permissions']

        # Highlight potentially dangerous configurations
        dangerous = False
        for perm in permissions:
            if 'Everyone' in perm and ('Full Control' in perm or 'Change' in perm):
                dangerous = True
            if 'Anonymous' in perm:
                dangerous = True

        # Format output
        if dangerous:
            context.log.highlight(f"[!] Share: {share_name} [{share_type}]")
        else:
            context.log.info(f"Share: {share_name} [{share_type}]")

        if comment:
            context.log.info(f"  Comment: {comment}")

        context.log.info("  Permissions:")
        for perm in permissions:
            if dangerous and ('Everyone' in perm or 'Anonymous' in perm):
                context.log.highlight(f"    [!] {perm}")
            else:
                context.log.info(f"    - {perm}")
