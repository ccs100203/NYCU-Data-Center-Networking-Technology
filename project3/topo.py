from mininet.topo import Topo

class MyTopo( Topo ):
    def __init__( self ):
        Topo.__init__( self )

        # Add hosts
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        h4 = self.addHost( 'h4' )
        h5 = self.addHost( 'h5' )
        h6 = self.addHost( 'h6' )

        # Add switches
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )
        s4 = self.addSwitch( 's4' )

        
        # Add links
        self.addLink( h1, s1, bw=100 )
        self.addLink( h2, s1, bw=100 )
        self.addLink( h3, s2, bw=100 )
        self.addLink( h4, s3, bw=100 )
        self.addLink( h5, s4, bw=100 )
        self.addLink( h6, s4, bw=100 )

        self.addLink( s1, s2, bw=1000, loss=5 )
        self.addLink( s2, s3, bw=1000, loss=5 )
        self.addLink( s3, s4, bw=1000, loss=5 )


topos = { 'mytopo': MyTopo }