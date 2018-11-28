package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFOXMField;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

import edu.wisc.cs.sdn.apps.l3routing.*;
import edu.wisc.cs.sdn.apps.util.ArpServer;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        
        /*********************************************************************/
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}
	
	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/* TODO: Install rules to send:                                      */
		/*       (1) packets from new connections to each virtual load       */
		/*       balancer IP to the controller                               */
		/*       (2) ARP packets to the controller, and                      */
		/*       (3) all other packets to the next rule table in the switch  */
		addRuleForLBOnSwitch(sw);
		/*********************************************************************/
	}
	
	public void addRuleForLBOnSwitch(IOFSwitch sw) {
		// Add rules to reach each load balancer
		for (int virtualIP : this.instances.keySet()) {
			System.out.println("Installing rule for IP: " + IPv4.fromIPv4Address(virtualIP));
			installRuleHelper(virtualIP, OFPort.OFPP_CONTROLLER.getValue(), sw);
		}
		
	}
	

	public boolean installRuleHelper(int ip, int port, IOFSwitch s) {	
		
		System.out.println("############ Inside installRuleHelper ##############");
		
		// IPv4 PACKET FORWARD RULE
		OFMatch matchCriteria = new OFMatch();
		matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		matchCriteria.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
		matchCriteria.setNetworkDestination(ip);
		
		OFAction actionOutput = new OFActionOutput(port);
		
		// Creating list of instructions to be executed when the dest ip matches
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();
		OFInstructionApplyActions actions = new OFInstructionApplyActions();
		List<OFAction> actionList = new ArrayList<OFAction>();
		
		actionList.add(actionOutput);
		actions.setActions(actionList);
		instructions.add(actions);
		boolean result1 = SwitchCommands.installRule(s, table, (short)(SwitchCommands.DEFAULT_PRIORITY + 1), matchCriteria, instructions);
		
		System.out.println("rule to redirect IP packet for " + IPv4.fromIPv4Address(ip) + " added: " + result1);
		
		// ARP RULE
		matchCriteria = new OFMatch();
		matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_ARP);
		matchCriteria.setField(OFOXMFieldType.ARP_TPA, ip);
		//matchCriteria.setNetworkDestination(ip);
		
		actionOutput = new OFActionOutput(port);
		
		// Creating list of instructions to be executed when the dest ip matches
		instructions = new ArrayList<OFInstruction>();
		actions = new OFInstructionApplyActions();
		actionList = new ArrayList<OFAction>();
		
		actionList.add(actionOutput);
		actions.setActions(actionList);
		instructions.add(actions);
		
		boolean result2 = SwitchCommands.installRule(s, table, (short)(SwitchCommands.DEFAULT_PRIORITY + 1), matchCriteria, instructions);
		
		System.out.println("rule for processing ARP request for " + IPv4.fromIPv4Address(ip) + " added: " + result1);
		
		return result1 && result2;
	}
	
	
	public boolean TCPRuleHelper(int srcIP, int destIP, byte[] srcMac, byte[] destMac, IOFSwitch sw, int lbIP, byte[] lbMac) {
		
		short TIMEOUT = 20;
		
		// Rule to route to the server
		OFMatch matchCriteria = new OFMatch();
		matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		matchCriteria.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
		
		matchCriteria.setNetworkDestination(lbIP);
		matchCriteria.setNetworkSource(srcIP);
		
		matchCriteria.setDataLayerDestination(lbMac);
		matchCriteria.setDataLayerSource(srcMac);
		
		// Creating list of instructions to be executed when the dest ip matches
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();
		OFInstructionApplyActions actions = new OFInstructionApplyActions();
		List<OFAction> actionList = new ArrayList<OFAction>();
		actionList.add(new OFActionSetField(OFOXMFieldType.ETH_DST, destMac));
		actionList.add(new OFActionSetField(OFOXMFieldType.IPV4_DST, destIP));
		actions.setActions(actionList);
		instructions.add(actions);
		boolean result1 = SwitchCommands.installRule(sw, table, SwitchCommands.MAX_PRIORITY, 
				matchCriteria, instructions, SwitchCommands.NO_TIMEOUT, TIMEOUT);
		
		
		// Rule to route the response
		matchCriteria = new OFMatch();
		matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		matchCriteria.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
		
		matchCriteria.setNetworkDestination(srcIP);
		matchCriteria.setNetworkSource(destIP);
		
		matchCriteria.setDataLayerDestination(srcMac);
		matchCriteria.setDataLayerSource(destMac);
		
		// Creating list of instructions to be executed when the dest ip matches
		instructions = new ArrayList<OFInstruction>();
		actions = new OFInstructionApplyActions();
		actionList = new ArrayList<OFAction>();
		actionList.add(new OFActionSetField(OFOXMFieldType.ETH_SRC, lbMac));
		actionList.add(new OFActionSetField(OFOXMFieldType.IPV4_SRC, lbIP));
		actions.setActions(actionList);
		instructions.add(actions);
		boolean result2 = SwitchCommands.installRule(sw, table, SwitchCommands.MAX_PRIORITY, 
				matchCriteria, instructions, SwitchCommands.NO_TIMEOUT, TIMEOUT);
		
		return result1 && result2;
	}
	
	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
	
		System.out.println("---------------- Inside receive method in Loadbalancer ------------------");
		
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0,
				pktIn.getPacketData().length);
		
		/*********************************************************************/
		/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
		/*       SYNs sent to a virtual IP, select a host and install        */
		/*       connection-specific rules to rewrite IP and MAC addresses;  */
		/*       ignore all other packets                                    */
		
		/*********************************************************************/		
		
		// TCP Handshake
		/*
		 * Connection-specific rules should match packets on the basis of Ethernet type, source IP address, 
		 * destination IP address, protocol, TCP source port, and TCP destination port. 
		 * Connection-specific rules should take precedence over the rules that send TCP packets to the controller,
		 * otherwise every TCP packet would be sent to the controller. 
		 * Therefore, these rules should have a higher priority than the rules installed when a switch joins the network.  
		 * Also, we want connection-specific rules to be removed when a TCP connection ends, 
		 * so connection-specific rules should have an idle timeout of 20 seconds.
		 */
		if(ethPkt.getEtherType() == Ethernet.TYPE_IPv4) {
			
			System.out.println("Packet type is IPv4");
			
			IPv4 ipPacket = (IPv4) ethPkt.getPayload();
			
			if(ipPacket.getProtocol() == IPv4.PROTOCOL_TCP) {
				
				System.out.println("Packet protocol is TCP");
				
				TCP tcpPacket = (TCP) ipPacket.getPayload();
				// Connection specific rule.
				if(tcpPacket.getFlags() == TCP_FLAG_SYN) {
					
					System.out.print("TCP FLAG IS SYN");
					
					// Get the LoadBalancer based on dest address
					int lbIP = ipPacket.getDestinationAddress();
					LoadBalancerInstance currLB = instances.get(lbIP);
					
					// Get the Target host specifications.
					int newDestIP = currLB.getNextHostIP();
					byte[] newDestMac = getHostMACAddress(newDestIP);
					
					int srcIP = ipPacket.getSourceAddress();
					byte[] srcMAC = ethPkt.getSourceMACAddress();
					
					byte[] lbMAC = ethPkt.getDestinationMACAddress();
					
					boolean result = TCPRuleHelper(srcIP, newDestIP, srcMAC, newDestMac, sw, lbIP, lbMAC);
					
					
					// Do we need to send reply to this incoming packet? after installing rules
					
//					//Change the payload's source and destination MAC,Address.
//					ipPacket.setDestinationAddress(newDestIP);
//					ethPkt.setDestinationMACAddress(newDestMac);
//					ipPacket.setSourceAddress(virtualIP);
//					ethPkt.setSourceMACAddress(currLB.getVirtualMAC());
					
					
					
					
					
				}
				
			}
		} else if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
			System.out.println("Packet type is ARP");
			sendARPReply(ethPkt, sw, (short)pktIn.getInPort());
		}
		// We don't care about other packets
		
		System.out.println("---------------- Done with receive method in Loadbalancer ------------------");
		return Command.CONTINUE;
	}
	
	public void sendARPReply(Ethernet etherPacket, IOFSwitch sw, short port) {
		
		System.out.println("----------------- sendARPReply -------------------");
		StringBuilder sb = new StringBuilder();
		for (int key : instances.keySet()) {
			sb.append(IPv4.fromIPv4Address(key));
			sb.append(", ");
		}
		
		ARP arpPacket = (ARP)etherPacket.getPayload();
		
		
		
		int lbIP = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		
		// Ignore all the ARP requests for IPs other than loadbalancers IPs
		// TODO: Might need to forward it to the ArpServer receive function
		if (!instances.containsKey(lbIP)) {
			return;
		}
		
		
		System.out.println("loadbalancer table: " + sb.toString());
		System.out.println("Arp request for IP: " + IPv4.fromIPv4Address(lbIP));
		System.out.println("lbMac: " + instances.get(lbIP).getVirtualMAC());
		
		byte [] lbMAC = instances.get(lbIP).getVirtualMAC();

		// create ethernet packet
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_ARP);
		
		// source mac of the packet - interface on which we received initially
		ether.setSourceMACAddress(lbMAC);

		// set destination mac
		ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());

		// Create ARP packet
		ARP arp = new ARP();

		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte)4);
		arp.setOpCode(ARP.OP_REPLY);
		arp.setSenderHardwareAddress(lbMAC);
		arp.setSenderProtocolAddress(lbIP);
		arp.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
		arp.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
	
		ether.setPayload(arp);
		SwitchCommands.sendPacket(sw, port, ether);
	}
	
	
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
