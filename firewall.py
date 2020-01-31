# A Python class for Firewall implementation. Public methods are:
# 1. Constructor that takes an allow rules filename and creates an instance
# 2. accept_packet method that takes a request with four arguments:
#    direction, protocol, port, ip_address and returns a boolean decision

class Firewall:
    # Constructor that takes file that contains the rules and initializes the firewall object
    def __init__ (self, filename):
        # The data structure for storing the rules without an ip range
        self.__rule_set_no_interval = []
        # The data structure for storing the rules with an ip range
        self.__rule_set_intervals = []
        self.__create_new_rules(filename)


    # Constructor to read rules from file and create the internal data structure
    # We need to convert quad-dotted IP address to the 32-bit decimal number form
    # We need to handle single IP address, port number as well as IP range and port range
    def __create_new_rules(self, filename):
        # Read the allow rules from file and create an internal lookup database
        with open(filename, 'r') as f:
            for line in f.readlines():
                entry = []
                direction, protocol, port, ip_address = line.strip().split(',')

                # Extract the direction and encode as an integer
                direction_flag = 0 if direction == 'inbound' else 1
                entry.append(direction_flag)

                # Extract the protocol and encode as an integer
                protocol_flag = 0 if protocol == 'tcp' else 1
                entry.append(protocol_flag)

                # Extract the port or port range
                port_range = port.split('-')
                port_int_range = [int(p) for p in port_range]
                entry.append(port_int_range)

                # Extract the IP address or IP address range
                ip_range = ip_address.split('-')
                ip_int_range = [self.__ip_addr_to_int(ip) for ip in ip_range]
                entry.append(ip_int_range)

                if ('-' in ip_address):
                    # Add this rule to the ip intervals dataset
                    self.__rule_set_intervals.append(entry)
                else:
                    # Add this rule to the single val dataset
                    self.__rule_set_no_interval.append(entry)

        # Sort the rules by largest to smallest ip breadth for linear search
        self.__rule_set_intervals.sort(key = lambda x: (x[3][1] - x[3][0]), reverse = True)

        # Sort the rules by smallest to largest value for binary search
        self.__rule_set_no_interval.sort(key = lambda x: x[3][0])


    # Convert a quad-dotted IP address to the 32-bit decimal number form
    # As explained here: https://en.wikipedia.org/wiki/IPv4
    def __ip_addr_to_int(self, ip_address):
        ip_field = ip_address.split('.')
        ip_addr_int = ((int(ip_field[0])*256 + int(ip_field[1]))*256 + int(ip_field[2]))*256 + int(ip_field[3])
        return ip_addr_int


    # Helper method for checking if an IP address or port number in with a given range
    def __is_item_in_range(self, item, irange):
        if len(irange) == 1 and (item == irange[0]):
            return True
        if len(irange) == 2 and (irange[0] <= item <= irange[1]):
            return True
        return False

    # Takes a list of rules, an item to search (IP address or port number) and the index of the item
    # Faster search using binary_search, performed on set of rules corresponding to single ip values
    #  takes O(log n)
    def __find_rule_binary_search(self, packet):
        left = 0
        right = len(self.__rule_set_no_interval) - 1
        while left <= right:
            mid = left + (right - left) // 2
            # Check if item is present at mid
            if self.__is_item_in_range(packet[3], self.__rule_set_no_interval[mid][3]) \
                    and self.__is_item_in_range(packet[2], self.__rule_set_no_interval[mid][2]) \
                    and packet[1] == self.__rule_set_no_interval[mid][1] \
                    and packet[0] == self.__rule_set_no_interval[mid][0]:
                #print('Matching rule:', self.__rule_set_no_interval[mid])
                return True
            # If range is greater, focus on the left-half
            if self.__rule_set_no_interval[mid][3][0] < packet[3]:
                left = mid + 1
            # If range is smaller, focus on the right-half
            else:
                right = mid - 1
        # We are done with the search, reject request
        return False

    # This sequence of checking is performed on the set of rules corresponding to ip ranges,
    # Linear seatch takes O(n)
    def __find_rule_linear_search(self, packet):
        for rule in self.__rule_set_intervals:
            # Check if the packet IP address matches the rule
            # Check if the packet port matches the rule
            # Check if the packet protocol matches the rule
            # Check if the packet direction matches the rule
            if self.__is_item_in_range(packet[3], rule[3]) \
                    and self.__is_item_in_range(packet[2], rule[2]) \
                    and packet[1] == rule[1] \
                    and packet[0] == rule[0]:
                # A matching rule found, accept request

                #print('Matching rule:', rule)
                return True
        # No matching rule found; reject request
        return False


    # This is the primary external API that takes four arguments (direction, protocol, port, ip_address)
    # and returns a boolean result
    def accept_packet(self, direction, protocol, port, ip_address):
        # Covert the incoming packet into a form similar to our rules structure
        packet = []

        # Extract the direction and encode as an integer
        direction_flag = 0 if direction == 'inbound' else 1
        packet.append(direction_flag)

        # Extract the protocol and encode as an integer
        protocol_flag = 0 if protocol == 'tcp' else 1
        packet.append(protocol_flag)

        # Extract the port as an integer
        packet.append(int(port))

        # Extract the IP address as an integer
        packet.append(self.__ip_addr_to_int(ip_address))
        #print('Packet', packet)

        # Perform binary search first, then linear search for matching rule
        # If found, accept the request otherwise reject it
        return (self.__find_rule_binary_search(packet) or self.__find_rule_linear_search(packet));

# End of the Firewall class
