import requests
import json
import time
import meraki
import pycurl
import numpy as np
from io import BytesIO
from operator import itemgetter
from passwordgenerator import pwgenerator
import logging
import msal
import re
import urllib.request
from datetime import datetime, timedelta

'''
Below is a list of all the necessary Meraki credentials
'''

# Meraki credentials are placed below
meraki_config = {
	'api_key': "",
	'orgName': ""
}

# writing function to obtain org ID via linking ORG name
mdashboard = meraki.DashboardAPI(meraki_config['api_key'])
result_org_id = mdashboard.organizations.getOrganizations()
for x in result_org_id:
    if x['name'] == meraki_config['orgName']:
        meraki_config['org_id'] = x['id']

# branch subnets is a variable to display local branch site info
branchsubnets = []
# variable with new and existing s2s VPN config
merakivpns = []

# performing initial get to obtain all Meraki existing VPN info to add to merakivpns list above
originalvpn = mdashboard.organizations.getOrganizationThirdPartyVPNPeers(
    meraki_config['org_id']
)
merakivpns.append(originalvpn)

# Meraki call to obtain Network information
tagsnetwork = mdashboard.networks.getOrganizationNetworks(meraki_config['org_id'])

# loop that iterates through the variable tagsnetwork and matches networks with vWAN in the tag
for i in tagsnetwork:
    if i['tags'] is None:
        pass
    elif "viptela-" in i['tags']:
        network_info = i['id'] # need network ID in order to obtain device/serial information
        netname = i['name'] # network name used to label Meraki VPN and Azure config
        nettag = i['tags']  # obtaining all tags for network as this might be used for failover
        va = mdashboard.networks.getNetworkSiteToSiteVpn(network_info) # gets branch local vpn subnets
        testextract = ([x['localSubnet'] for x in va['subnets']
						if x['useVpn'] == True])  # list comprehension to filter for subnets in vpn
        (testextract)
        privsub = str(testextract)[1:-1] # needed to parse brackets
        devices = mdashboard.devices.getNetworkDevices(network_info)
        x = devices[0]
        up = x['serial'] # serial number to later obtain the uplink information for the appliance
        firmwareversion = x['firmware'] # now we obtained the firmware version, need to still add the validation portion
        firmwarecompliance = str(firmwareversion).startswith("wired-15") # validation to say True False if appliance is on 15 firmware
        if firmwarecompliance == True:
            print("firmware is compliant, continuing")
        else:
            break # if box isnt firmware compliant we break from the loop
        modelnumber = x['model']

        uplinks = mdashboard.devices.getNetworkDeviceUplink(network_info, up) # obtains uplink information for branch

		# creating keys for dictionaries inside dictionaries
        uplinks_info = dict.fromkeys(['WAN1', 'WAN2', 'Cellular'])
        uplinks_info['WAN1'] = dict.fromkeys(
            ['interface', 'status', 'ip', 'gateway', 'publicIp', 'dns', 'usingStaticIp'])
        uplinks_info['WAN2'] = dict.fromkeys(
            ['interface', 'status', 'ip', 'gateway', 'publicIp', 'dns', 'usingStaticIp'])
        uplinks_info['Cellular'] = dict.fromkeys(
            ['interface', 'status', 'ip', 'provider', 'publicIp', 'model', 'connectionType'])

        for uplink in uplinks:
            if uplink['interface'] == 'WAN 1':
                for key in uplink.keys():
                    uplinks_info['WAN1'][key] = uplink[key]
            elif uplink['interface'] == 'WAN 2':
                for key in uplink.keys():
                    uplinks_info['WAN2'][key] = uplink[key]
            elif uplink['interface'] == 'Cellular':
                for key in uplink.keys():
                    uplinks_info['Cellular'][key] = uplink[key]

        uplinksetting = mdashboard.uplink_settings.getNetworkUplinkSettings(network_info) # obtains meraki sd wan traffic shaping uplink settings
        for g in uplinks_info:
			# loops through the variable uplinks_info which reveals the value for each uplink key
            if uplinks_info['WAN2']['status'] == "Active" or uplinks_info['WAN2']['status'] == "Ready" and uplinks_info['WAN1']['status'] == "Active" or uplinks_info['WAN1']['status'] == "Ready":
                print("both uplinks active")

                pubs = uplinks_info['WAN2']['publicIp']
                pubssec = uplinks_info['WAN1']['publicIp']
                secondaryuplinkindicator = 'True'

                port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])/1000
                wan2port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])/1000

            elif uplinks_info['WAN2']['status'] == "Active":
                pubs = uplinks_info['WAN2']['publicIp']
                port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])/1000

            elif uplinks_info['WAN1']['status'] == "Active":
                pubs = uplinks_info['WAN1']['publicIp']
                port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])/1000

            else:
                print("uplink info error")


		# writing function to get ISP
        splist = []

        def sp(primispvar, secispvar):
            b_obj = BytesIO()
            crl = pycurl.Curl()
            # Set URL value
            crl.setopt(crl.URL, 'https://ipapi.co/' + primispvar + '/json/')
			# Write bytes that are utf-8 encoded
            crl.setopt(crl.WRITEDATA, b_obj)
			# Perform a file transfer
            crl.perform()
			# End curl session
            crl.close()
			# Get the content stored in the BytesIO object (in byte characters)
            get_body = b_obj.getvalue()
			# Decode the bytes stored in get_body to HTML and print the result
            resdict = json.loads(get_body.decode('utf-8'))
            isp = resdict['org']
			# print(isp)
            splist.append(isp)
            if secondaryuplinkindicator == 'True':
                b_objsec = BytesIO()
                crl = pycurl.Curl()
				# Set URL value
                crl.setopt(crl.URL, 'https://ipapi.co/' +
                           '76.102.224.16' + '/json/')
				# Write bytes that are utf-8 encoded
                crl.setopt(crl.WRITEDATA, b_objsec)
				# Perform a file transfer
                crl.perform()
				# End curl session
                crl.close()
				# Get the content stored in the BytesIO object (in byte characters)
                get_bodysec = b_objsec.getvalue()
				# Decode the bytes stored in get_body to HTML and print the result
                resdictsec = json.loads(get_bodysec.decode('utf-8'))
                ispsec = resdictsec['org']
				# print(isp)
                splist.append(ispsec)


        sp(pubs, pubssec)
        localsp = splist[0]
        secisp = splist[1]

		# Don't use the same public IP for both links; use a place holder
        if(pubs == pubssec):
                pubssec = "1.2.3.4"

        # listing site below in output with branch information
        if secondaryuplinkindicator == 'True':
            branches = str(netname) + "  " + str(pubs) + "  " + str(localsp) + "  " + str(port) + "  " + str(pubssec) + "  " + str(secisp) + "  " + str(wan2port) + "  " + str(privsub)
        else:
            branches = str(netname) + "  " +  str(pubs) + "  " +  str(localsp) + "  " +  str(port) + "  " +  str(privsub)

        print(branches)

# Final Call to Update Meraki VPN config with Parsed Blob from Azure 
updatemvpn = mdashboard.organizations.updateOrganizationThirdPartyVPNPeers(
    meraki_config['org_id'], merakivpns[0]
)
print(updatemvpn)
