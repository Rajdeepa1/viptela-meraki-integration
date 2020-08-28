import requests, json, time
import meraki
import re
import ast

# class that contains all Meraki necessary config
class MerakiConfig:
    api_key = ''
    org_name = 'Cloud Test Org'
    tag_prefix = 'viptela-'
    org_id = None

# function to parse list of tags for an individual network
def strip_meraki_network_tags(meraki_network_tag):
    # below parses the for the specific network tag on the network w/ viptela-
    meraki_tag_strip_part1 = re.findall(r'[v]+[i]+[p]+[t]+[e]+[l]+[a]+[-].*',\
         str(meraki_network_tag))
    return meraki_tag_strip_part1[0]

# writing function to obtain org ID via linking ORG name
mdashboard = meraki.DashboardAPI(MerakiConfig.api_key)
result_org_id = mdashboard.organizations.getOrganizations()
for x in result_org_id:
    if x['name'] == MerakiConfig.org_name:
        MerakiConfig.org_id = x['id']

# defining function that creates dictionary of IPsec config from Umbrella config
def get_meraki_ipsec_config(name, public_ip, lan_subnets, secret, network_tags) -> dict:
    ipsec_config = {
        "name": name,
        "publicIp": public_ip,
        "privateSubnets": [lan_subnets],
        "secret": secret,
        "ikeVersion": "2",
        "ipsecPolicies": {
            "ikeCipherAlgo": ["aes256"],
            "ikeAuthAlgo": ["sha256"],
            "ikeDiffieHellmanGroup": ["group14"],
            "ikeLifetime": 28800,
            "childCipherAlgo": ["aes256"],
            "childAuthAlgo": ["sha256"],
            "childPfsGroup": ["group14"],
            "childLifetime": 3600
        },
        "networkTags": [ network_tags ]
    }

    return ipsec_config

# function to update Meraki VPN config
def update_meraki_vpn(vpn_list):
    updatemvpn = mdashboard.organizations.updateOrganizationThirdPartyVPNPeers(
    MerakiConfig.org_id, vpn_list
    )

# function to validate that MX is on version 15 or greater
def validate_mx_firmware(branch_node):
    # call to get device info
    devices = mdashboard.devices.getNetworkDevices(branch_node)
    print(devices)
    # validating firmware to ensure device is on 15
    firmwareversion = devices[0]['firmware'] 
    # validation to say True False if MX appliance is on 15 firmware
    firmwarecompliance = str(firmwareversion).startswith("wired-15") 
    if firmwarecompliance == True:
        print("firmware is compliant")
    else:
        print("firmware is not compliant breaking loop")
        firmwarecompliance = False

    return firmwarecompliance

# this function performs initial get to obtain all Meraki existing VPN info 
def get_meraki_ipsec_tunnels():
    originalvpn = mdashboard.organizations.getOrganizationThirdPartyVPNPeers(
        MerakiConfig.org_id
        )  
    return originalvpn     

# this function performs an org wide Meraki call to obtain VPN info for all networks in an org
def org_wide_vpn_status():
    # defining the URL for the GET below
    org_vpn_url = 'https://api.meraki.com/api/v1/organizations/'\
        +MerakiConfig.org_id+'/appliance/vpn/statuses'
    # creating the header in order to authenticate the call
    header = {"X-Cisco-Meraki-API-Key": MerakiConfig.api_key, "Content-Type": "application/json"}
    # performing API call to meraki dashboard
    vpn_statuses = requests.get(org_vpn_url, headers=header).content
    # vpn_status is a data type of bytes, going to convert to a string then adictionary
    decoded_vpn_statuses = vpn_statuses[1:-1].decode("UTF-8") # parsing outer brackets
    # converting string to dictionary
    meraki_vpn_peers = ast.literal_eval(decoded_vpn_statuses)
    
    return meraki_vpn_peers

# variable with new and existing s2s VPN config for Meraki
merakivpns = []

# performing initial get to obtain all Meraki existing VPN info 
original_meraki_tunnels = get_meraki_ipsec_tunnels()
print(original_meraki_tunnels)

# executing function to get all existing site/vpn info
meraki_config_dump = org_wide_vpn_status()
print(meraki_config_dump)

# Meraki call to obtain Network information
tagsnetwork = mdashboard.networks.getOrganizationNetworks(MerakiConfig.org_id)

# loop that iterates through the variable tagsnetwork and matches networks with vWAN in the tag
for i in tagsnetwork:
    if i['tags'] is None:
        pass
    elif "viptela-" in i['tags']:
        network_info = i['id'] # need network ID in order to obtain device/serial information
        netname = i['name'] # network name used to label Meraki VPN and Azure config
        nettag = i['tags']  # obtaining all tags for network as this might be used for failover

        # obtaining lan subnets by iterating through meraki_config_dump variable
        for meraki_networks in meraki_config_dump:
            # conditional statement matches on network ID
            if network_info == meraki_networks['networkId']:
                print("network detected")
                # variable representing all MX branch site subnets
                mx_branch_subnets = meraki_networks['exportedSubnets'][0]['subnet']
                # variable containing list of both public IPs
                mx_wan_links = meraki_networks['uplinks']

        # calling function to parse tags for SIG specific tag
        meraki_net_tag = strip_meraki_network_tags(nettag)
        print(meraki_net_tag)

        # calling function to build dictionary of meraki vpn config
        primary_meraki_remote_config = get_meraki_ipsec_config(netname, "viptela_public_ip", \
            "viptela_lan_subnets", "secret", meraki_net_tag)

        # building list of dictionaries with Meraki local site config
        mx_branch_config_dictionary = str(netname) + " " + str(mx_branch_subnets) + " " + str(meraki_net_tag) + " " + str(mx_wan_links)
        print(mx_branch_config_dictionary)
