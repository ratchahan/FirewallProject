import unittest
from firewall import Firewall

# class to test the accuracy of the Firewall class rule matching

class firewallTest (unittest.TestCase):
    def testAcceptPacketTrue(self):
        firewall = Firewall('allow_rules.csv')
        self.assertEqual(firewall.accept_packet("inbound", "udp", 53, "192.168.2.5"), True)

        self.assertEqual(firewall.accept_packet("inbound", "tcp", 20, "192.168.1.101"), True)

        self.assertEqual(firewall.accept_packet("inbound", "udp", 53, "192.168.2.1"), True)

        self.assertEqual(firewall.accept_packet("outbound", "tcp", 10234, "192.168.10.11"), True)

    def testAcceptPacketFalse(self):
        firewall = Firewall('allow_rules.csv')
        self.assertEqual(firewall.accept_packet("inbound", "tcp", 81, "192.168.1.2"), False)

        self.assertEqual(firewall.accept_packet("inbound", "udp", 24, "52.12.48.92"), False)


if __name__ == '__main__':
    unittest.main()
