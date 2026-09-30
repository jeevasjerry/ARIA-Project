from mininet.topo import Topo


class ARIATopo(Topo):

    def build(self):

        h1 = self.addHost(
            'h1',
            ip='192.168.100.1/24'
        )

        h2 = self.addHost(
            'h2',
            ip='192.168.100.2/24'
        )

        s1 = self.addSwitch('s1')

        self.addLink(h1, s1)
        self.addLink(h2, s1)


topos = {
    'aria': ARIATopo
}
