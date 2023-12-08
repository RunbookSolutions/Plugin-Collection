import nmap
import time
import logging
from runbooksolutions.agent.API import API

class Plugin:
    provided_network: dict = {}
    networks: list = []

    def __init__(self, api: API) -> None:
        self.api = api

    def scan_network(self, network_id: str, scan_arguments: str = "-sn") -> str:
        start_time = time.time()
        self.provided_networks = self.getNetworkByID(network_id)
        
        # Return if we can't find the provided network ID
        if self.provided_networks is None:
            logging.critical(f"Unable to find network {network_id}.")
            return f"Unable to find network {network_id}."

        # Get the Networks we will be scanning in the event the network provided has subnets.
        self.networks = self.getNetworksToScan(self.provided_networks)
        logging.debug(f"Networks To Process: {[network.get('network') for network in self.networks]}")

        # Scan Each Network
        for network in self.networks:
            logging.debug(f"Scanning: {network.get('network')}")
            scan_results = self.preformScan(network, scan_arguments)
            logging.debug(f"Scan Results: {scan_results}")

            self.processNowOfflineAddresses(scan_results, network)

            for result in scan_results:
                self.processScanResult(result, network, self.provided_networks)
        
        return f"Scan Completed in {time.time() - start_time} seconds"

    def processNowOfflineAddresses(self, results: list, network: dict) -> None:
        UpAddresses = [address.get('address') for address in results]
        for address_data in network.get('addresses'):
            if address_data.get('address') not in UpAddresses and address_data.get('status') == "online":
                self.updateAddressStatus(address_data.get('id'), "offline")
                logging.debug(f"Address {address_data.get('address')} is now Down!")


    # {'address': '192.168.1.1', 'status': 'up', 'hostname': None, 'source': {'id': '9acb0f52-1bdd-4f7b-8706-20a073447866', 'address': '192.168.1.1', 'devices': [], 'status': 'online'}}
    def processScanResult(self, result: dict, network: dict, primary_network: dict) -> None:
        # Ensure we were given the origional source address information
        source = result.get('source')
        if source is None:
            logging.critical(f"Source Not Provided! {result}")
            return

        # Does an Address Status Change Need to Happen?
        if result.get('status') == "up" and source.get('status') == "offline":
            self.updateAddressStatus(source.get('id'), 'online')

        # Result is offline Return
        if result.get('status') == "down":
            return

        scan_hostname = result.get('hostname')
        source_devices = source.get('devices')

        if source_devices is not None:
            # Generate Temp so we can pre-search for hostname and non-hostname results
            temp = scan_hostname if scan_hostname else 'DEVICE_' + result.get('address')
            for device in source_devices:
                # We already have the device with a matching name
                if device.get("name") == temp:
                    logging.debug(f"Device is Good! {temp}")
                    return
                # We already have the device with a matching hostname
                if device.get("hostname") == temp:
                    logging.debug(f"Device is Good! {temp}")
                    return

                # Check if we have an existing Temp Device that should have its name updated
                if temp != 'DEVICE_' + result.get('address'):
                    if device.get("name") == 'DEVICE_' + result.get('address'):
                        logging.info("Updating Device with new hostname")
                        self.UpdateDeviceName(device.get("id"), temp)
                        return

        # If we don't have a provided hostname
        if scan_hostname is None:
            logging.error(f"No Hostname Found! {result.get('address')}")
            
            name = 'DEVICE_' + result.get('address')
            # Check if there is already a place holder...
            device = self.getDeviceByName(name)
            if device is None:
                logging.debug("Creating Stand-in Device")
                result = self.CreateDevice(name, None, result.get('source').get('id'), network.get('id'))
            # Return we are done processing this result
            return

        # We have a hostname
        logging.debug(f"Find or Create Hostname {result.get('hostname')}")
        device = self.getDeviceByHostName(result.get('hostname'))
        if device is None:
            result = self.CreateDevice(result.get('hostname'), result.get('hostname'), result.get('source').get('id'), network.get('id'))
            if result is None:
                logging.error(f"Error Creating Device {result}")
                return
        else:
            self.UpdateDevice(device.get('id'), result.get('source').get('id'))
            logging.info("Link Existing Device")
            return


    def preformScan(self, network: dict, scan_arguments: str) -> dict:
        nm = nmap.PortScanner()
        nm.scan(hosts=network.get('network'), arguments=scan_arguments)

        results = []

        for address in nm.all_hosts():
            result = {
                "address": address,
                "status": nm[address].state(),
                "hostname": nm[address].hostname() or None
            }
            for network_address in network.get('addresses', []):
              if network_address.get('address') == address:
                  result["source"] = network_address
                  break
            results.append(result)

        return results
    
    def getNetworksToScan(self, network: dict) -> list:
        networks = []
        if network.get('subnets'):
            for subnet in network.get('subnets'):
              networks.append(self.getNetworkByID(subnet.get('id')))
        else:
            networks.append(network)
        return networks

    def getNetworkByID(self, network_id: str) -> dict | None:
        response = self.api.graphQL(self.GET_NETWORK_INFO_QUERY, {'id': network_id})
        if not response or not response.get('data', {}).get('core', {}).get('network', {}).get('single'):
            return None
        return response['data']['core']['network']['single']

    def getDeviceByHostName(self, hostname: str) -> dict | None:
        response = self.api.graphQL(self.LIST_DEVICE_BY_HOSTNAME_QUERY, {'hostname': hostname})
        if not response or not response.get('data', {}).get('core', {}).get('device', {}).get('single'):
            return None
        return response['data']['core']['device']['single']

    def getDeviceByName(self, hostname: str) -> dict | None:
        response = self.api.graphQL(self.LIST_DEVICE_BY_NAME_QUERY, {'name': hostname})
        if not response or not response.get('data', {}).get('core', {}).get('device', {}).get('single'):
            return None
        return response['data']['core']['device']['single']

    def UpdateDeviceName(self, device_id: str, hostname: str) -> None:
        response = self.api.graphQL(self.UPDATE_DEVICE_MUTATION, 
        {
            'input': {
                'id': device_id,
                'name': hostname,
                'hostname': hostname,
            }
        })
        if not response or not response.get('data', {}).get('core', {}).get('device', {}).get('update'):
            return None
        return response['data']['core']['device']['update']

    def UpdateDevice(self, device_id: str, address_id: str) -> None:
        response = self.api.graphQL(self.UPDATE_DEVICE_MUTATION, 
        {
            'input': {
                'id': device_id,
                'addresses': {
                    'connect': [address_id],
                },
            }
        })
        if not response or not response.get('data', {}).get('core', {}).get('device', {}).get('update'):
            return None
        return response['data']['core']['device']['update']

    def CreateDevice(self,name: str, hostname: str | None, address_id: str, network_id: str) -> dict | None:
        
        response = self.api.graphQL(self.CREATE_DEVICE_MUTATION, 
        {
            'input': {
                'name': name,
                'hostname': hostname,
                'description': 'Created By NMAP Scan Plugin',
                'type': 'other',
                'addresses': {
                    'connect': [address_id],
                },
            }
        })
        if not response or not response.get('data', {}).get('core', {}).get('device', {}).get('create'):
            return None
        return response['data']['core']['device']['create']
    
    def updateAddressStatus(self, address_id: str, status: str) -> dict | None:
        response = self.api.graphQL(self.UPDATE_ADDRESS_STATUS_MUTATION, 
        {
            'input': {
                'id': address_id,
                'status': status,
            }
        })
        if not response or not response.get('data', {}).get('core', {}).get('networks', {}).get('addresses', {}).get('update'):
            return None
        return response['data']['core']['networks']['addresses']['update']

    GET_NETWORK_INFO_QUERY = """
        query GetNetworkInfo($id: ID = "") {
            core {
                network {
                    single(id: $id) {
                        id
                        mask
                        network
                        addresses {
                            id
                            address
                            devices {
                                id
                                name
                                hostname
                                type
                            }
                            status
                        }
                        subnets {
                            id
                        }
                        devices {
                            id
                            name
                            type
                        }
                    }
                }
            }
        }
    """

    UPDATE_ADDRESS_STATUS_MUTATION = """
        mutation UpdateAddressStatus($input: CoreNetworksAddressUpdateInput) {
            core {
                networks {
                    address {
                        update(input: $input) {
                            id
                            status
                        }
                    }
                }
            }
        }
    """

    LIST_DEVICE_BY_HOSTNAME_QUERY = """
        query ListDeviceByName($hostname: String!) {
            core {
                device {
                    single(hostname: $hostname) {
                        id
                        name
                        hostname
                        type
                    }
                }
            }
        }
    """

    LIST_DEVICE_BY_NAME_QUERY = """
        query ListDeviceByName($name: String!) {
            core {
                device {
                    single(name: $name) {
                        id
                        name
                        hostname
                        type
                    }
                }
            }
        }
    """

    CREATE_DEVICE_MUTATION = """
        mutation CreateDevice($input: CoreDeviceCreateInput!) {
            core {
                device {
                    create(input: $input) {
                        id
                    }
                }
            }
        }
    """

    UPDATE_DEVICE_MUTATION = """
        mutation UpdateDevice($input: CoreDeviceUpdateInput!) {
            core {
                device {
                    update(input: $input) {
                        id
                    }
                }
            }
        }
    """
