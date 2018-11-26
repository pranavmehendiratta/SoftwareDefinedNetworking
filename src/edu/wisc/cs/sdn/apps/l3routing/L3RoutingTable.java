package edu.wisc.cs.sdn.apps.l3routing;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.routing.Link;

public class L3RoutingTable {
	HashMap<Long, Integer> switchToIndex;
	HashMap<Integer, Long> indexToSwitch;
	HashMap<String, Integer> ports;
	long [][] graph;
	
	
	public L3RoutingTable() {
		switchToIndex = null;
		indexToSwitch = null;
		ports = null;
		graph = null;
	}
	
	public void initializeGraph(int size, Set<Link> links) {
		graph = new long[size][size];
	
		for (int i = 0; i < size; i++) {
		    Arrays.fill(graph[i], Integer.MAX_VALUE);
		}

		long src;
		long dest;
		
		Iterator<Link> iterator = links.iterator();
		while (iterator.hasNext()) {
			Link l = iterator.next();
			src = l.getSrc();
			dest = l.getDst();
		
			graph[switchToIndex.get(src)][switchToIndex.get(dest)] = 1;
			graph[switchToIndex.get(dest)][switchToIndex.get(src)] = 1;
			
			// Same switch
			graph[switchToIndex.get(src)][switchToIndex.get(src)] = 0;
			graph[switchToIndex.get(dest)][switchToIndex.get(dest)] = 0;
		}

		System.out.println("Initial graph");
		print(graph);
	}
	
	public void initializeMap(Map<Long, IOFSwitch> switches) {
		switchToIndex = new HashMap<Long, Integer>();
		indexToSwitch = new HashMap<Integer, Long>();
		int counter = 0;
		for (Long key : switches.keySet()) {
			switchToIndex.put(key, counter);
			indexToSwitch.put(counter, key);
			counter++;
		}
	}
	
	public String getKey(long start, long end) {
		return start + "#" + end;
	}
	
	
	public void initializePorts(Set<Link> links) {
		ports = new HashMap<String, Integer>();
		
		Iterator<Link> iterator = links.iterator();
		while (iterator.hasNext()) {
			Link l = iterator.next();
			
			// Dst to src -> send on dst port
			ports.put(getKey(l.getDst(), l.getSrc()), l.getDstPort());
			
			// Src to dst -> send on src port
			ports.put(getKey(l.getSrc(), l.getDst()), l.getSrcPort());
		}
	}
	
	/**
	 * Reference - https://www.geeksforgeeks.org/floyd-warshall-algorithm-dp-16/
	 * @param switches
	 * @param links
	 */
	public void floydWarshall(Map<Long, IOFSwitch> switches, Collection<Link> links) {
		initializeMap(switches);
		initializePorts((Set<Link>) links);
		initializeGraph(switches.size(), (Set<Link>)links);
		
		
		int size = switches.size();
		long [][] dist = new long[size][size];
		int i, j, k; 
		  
	    /* Initialize the solution matrix same as input graph matrix. Or  
	       we can say the initial values of shortest distances are based 
	       on shortest paths considering no intermediate vertex. */
	    for (i = 0; i < size; i++) 
	        for (j = 0; j < size; j++) 
	            dist[i][j] = graph[i][j]; 
	  
	    /* Add all vertices one by one to the set of intermediate vertices. 
	      ---> Before start of an iteration, we have shortest distances between all 
	      pairs of vertices such that the shortest distances consider only the 
	      vertices in set {0, 1, 2, .. k-1} as intermediate vertices. 
	      ----> After the end of an iteration, vertex no. k is added to the set of 
	      intermediate vertices and the set becomes {0, 1, 2, .. k} */
	    for (k = 0; k < size; k++) 
	    { 
	        // Pick all vertices as source one by one 
	        for (i = 0; i < size; i++) 
	        { 
	            // Pick all vertices as destination for the 
	            // above picked source 
	            for (j = 0; j < size; j++) 
	            { 
	                // If vertex k is on the shortest path from 
	                // i to j, then update the value of dist[i][j] 
	                if (dist[i][k] + dist[k][j] < dist[i][j]) 
	                    dist[i][j] = dist[i][k] + dist[k][j]; 
	            } 
	        } 
	    } 
	    print(dist);
	}
	
	public int findPath(long start, long end) {
		int startIndex = switchToIndex.get(start);
		int endIndex = switchToIndex.get(end);
		
		System.out.println("Inside findPath");
		System.out.println("startIndex: " + startIndex);
		
		// Directly send the packet to the end switch
		int minDist = Integer.MAX_VALUE;
		int nextHop = -1;
		if (graph[startIndex][endIndex] == 1) {
			nextHop = endIndex;
			minDist = 1;
			return nextHop;
		}
		
		// Calculate the minimum path
		for (int i = 0; i < graph.length; i++) {
			if (graph[startIndex][i] == 1) { // Switch is connected to start host switch
				if (graph[i][endIndex] < minDist) {
					minDist = (int)graph[i][endIndex];
					nextHop = i;					
				}
			}
		}
		return nextHop;
		
	}	
	
	public void print(long [][] graph) {
		System.out.println("-------------------- switchToIndex --------------------");
		System.out.println(Arrays.asList(switchToIndex));
		System.out.println("----------------------- graph -------------------------");
		System.out.println(graphToString(graph));
	}
	
	public String graphToString(long [][] graph) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < graph.length; i++) {
			sb.append(Arrays.toString(graph[i]));
			sb.append("\n");
		}
		return sb.toString();
	}	
}
