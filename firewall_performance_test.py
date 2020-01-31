from ipaddress import IPv4Address
import csv
import random
from timeit import default_timer

from firewall import Firewall

# class to help test the performance of the Firewall class

class RuleGenerator:
    def __init__(self):

        self.directions = ["inbound", "outbound"]
        self.protocols = ["udp", "tcp"]
        self.min_port = 1
        self.max_port = 65535
        self.min_ip = IPv4Address('0.0.0.0')
        self.max_ip = IPv4Address('255.255.255.255')

        # Generate random rules and write to file
        # self.__generate_and_write_rules(self, output_file, num_rules)

    # Generate random requests for testing
    def generate_test_requests(self, num_rules):
        request_list = []
        for num in range(0, num_rules):
            request_list.append(self.__generate_simple_rule())
        return request_list

    # Method to generate random allow rules
    def generate_and_write_rules(self, output_file, num_rules, num_port_ranges, num_ip_ranges, num_combo):
        rules_list = self.__generate_rules(num_rules, num_port_ranges, num_ip_ranges, num_combo)
        with open(output_file, 'w', newline='\n') as f:
            writer = csv.writer(f)
            writer.writerows(rules_list)
        print(len(rules_list), 'rules are written to', output_file)

    def __get_port_range(self):
        port_list = [random.randint(self.min_port, self.max_port),
                     random.randint(self.min_port, self.max_port)]
        port_list.sort()
        return str(port_list[0]) + '-' + str(port_list[1])

    def __get_ip_range(self):
        ip_address_list = [IPv4Address(random.randint(int(self.min_ip), int(self.max_ip))),
                           IPv4Address(random.randint(int(self.min_ip), int(self.max_ip)))]
        ip_address_list.sort()
        return str(ip_address_list[0]) + '-' + str(ip_address_list[1])

    def __generate_simple_rule(self):
        direction = self.directions[random.randint(0, 1)]
        protocol = self.protocols[random.randint(0, 1)]
        port = str(random.randint(self.min_port, self.max_port))
        ip_address = str(IPv4Address(random.randint(int(self.min_ip), int(self.max_ip))))
        return [direction, protocol, port, ip_address]

    def __generate_port_range_rule(self):
        direction = self.directions[random.randint(0, 1)]
        protocol = self.protocols[random.randint(0, 1)]
        port = self.__get_port_range()
        ip_address = str(IPv4Address(random.randint(int(self.min_ip), int(self.max_ip))))
        return [direction, protocol, port, ip_address]

    def __generate_ip_range_rule(self):
        direction = self.directions[random.randint(0, 1)]
        protocol = self.protocols[random.randint(0, 1)]
        port = str(random.randint(self.min_port, self.max_port))
        ip_address = self.__get_ip_range()
        return [direction, protocol, port, ip_address]

    def __generate_combo_rule(self):
        direction = self.directions[random.randint(0, 1)]
        protocol = self.protocols[random.randint(0, 1)]
        port = self.__get_port_range()
        ip_address = self.__get_ip_range()
        return [direction, protocol, port, ip_address]

    def __generate_rules(self, num_rules, num_port_ranges, num_ip_ranges, num_combo):
        rules = []
        # Generate simple rules
        for num in range(0, (num_rules - (num_port_ranges + num_ip_ranges + num_combo))):
            rules.append(self.__generate_simple_rule())

        # Generate rules with port ranges
        for num in range(0, num_port_ranges):
            rules.append(self.__generate_port_range_rule())

        # Generate rules with IP ranges
        for num in range(0, num_ip_ranges):
            rules.append(self.__generate_ip_range_rule())

        # Generate rules with a combination of port and IP ranges
        for num in range(0, num_combo):
            rules.append(self.__generate_combo_rule())

        # Shuffle the rules to mix them up!
        random.shuffle(rules)
        return rules


if __name__ == '__main__':
    # Initialize a new test rules generator
    generator = RuleGenerator()
    generator.generate_and_write_rules('./generated_rules.csv', 1000000, 100000, 100000, 5000)
    print('Created test generator with 1000000 rules')

    # Create a new Firewall instance with the generated rules
    firewall = Firewall('./generated_rules.csv')

    # Generate some rules now
    request_list = generator.generate_test_requests(1000)
    print('Created test case with 1000 requests')

    # Evaluate the time taken to process the n requests
    start = default_timer()
    for request in request_list:
        firewall.accept_packet(request[0], request[1], int(request[2]), request[3])
    end = default_timer()

    print(len(request_list), 'requests processed in', (end - start), 'seconds')
