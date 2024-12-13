from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

class StarTopo(Topo):
    def build(self, n=5):
        # Add a central switch
        switch = self.addSwitch('s1')

        # Add hosts and connect them to the switch
        for i in range(1, n + 1):
            host = self.addHost(f'h{i}')
            self.addLink(host, switch)

if __name__ == '__main__':
    setLogLevel('info')
    # Create the custom topology
    topo = StarTopo(n=5)
    # Create the network with the custom topology and a remote controller
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633), switch=OVSSwitch)
    net.start()
    CLI(net)
    net.stop()  
