/*       
 * LICENSE : GNU General Public License v3.0 (https://github.com/Saket-Upadhyay/ns3-cybersecurity-simulations/blob/master/LICENSE)
 * REPOSITORY : https://github.com/Saket-Upadhyay/ns3-cybersecurity-simulations
 * =================================================================================
 * 
 * In this we follow the following setup / node placement
 * 
 *    (n1)
 *      \
 *       \
 *         -------- (n2) -------- (n3)
 *                 / |  \
 *                /  |   \ 
 *               /   |    \
 *             (B0),(B2)...(Bn) 
 *                 
 *  N0 is legitimate user, communicating with server N2 (data server) via node N1 (maybe website server interface )
 *  B0-Bn are bots DDoS-ing the network.
 * 
 * NetAnim XML is saved as -> DDoSim.xml 
 *  
 */
#include <ns3/csma-helper.h>
#include "ns3/mobility-module.h"
#include "ns3/nstime.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/command-line.h"

#define TCP_SINK_PORT 9000
#define UDP_SINK_PORT 9001

// #define MAX_SIMULATION_TIME 10.0

bool fileExists(const std::string& filename);
void PrintFlowMonitorStats ();

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DDoSAttack");

//Global variables
FlowMonitorHelper flowmon;
Ptr<FlowMonitor> monitor;
std::ofstream myfile;
uint32_t rxBytesWarmup[100]={0}; //max_flows = 100
uint32_t rxBytesPrev=0;
uint32_t warmupTime = 0;
uint32_t interval = 1; //Interval for calculating instantaneous throughput [s]

int main(int argc, char *argv[])
{
    // Initialize default simulation parameters
    uint32_t nNodes = 1;
    bool pcap = false; 						// Generate a PCAP file from the AP
    bool useCsv = true; 						// Flag for saving output to CSV file
    bool useTcp = false;
    double simulationTime = 10;
    uint32_t max_bulk_bytes = 100000000;
    uint32_t number_of_bots = 3;
    uint32_t max_flows = 100;
    std::string ddosrate = "20480kb/s";
    CommandLine cmd;
    cmd.AddValue ("simulationTime", "Simulation time (seconds)", simulationTime);
    cmd.AddValue ("max_bulk_bytes", "Max bulk bytes", max_bulk_bytes);
    cmd.AddValue ("number_of_bots", "Number of bots for DDos (3)", number_of_bots);
    cmd.AddValue ("max_flows", "Max number of flows (100)", max_flows);
    cmd.AddValue ("ddos_rate", "DDoS rate (20480kb/s)", ddosrate);
    cmd.Parse(argc, argv);
    std::cout << "Simulation time: " << simulationTime << std::endl;
    std::cout << "Max bulk bytes: " << max_bulk_bytes << std::endl;
    std::cout << "Number of bots for DDos: " << number_of_bots << std::endl;
    std::cout << "Max number of flows: " << max_flows << std::endl;
    std::cout << "DDoS rate: " << ddosrate << std::endl;

    Time::SetResolution(Time::NS);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);


    //Legitimate connection bots
    NodeContainer nodes;
    nodes.Create(3);

    //Nodes for attack bots
    NodeContainer botNodes;
    botNodes.Create(number_of_bots);

    // Define the Point-To-Point Links and their Paramters
    PointToPointHelper pp1, pp2;
    pp1.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    pp1.SetChannelAttribute("Delay", StringValue("1ms"));

    pp2.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    pp2.SetChannelAttribute("Delay", StringValue("1ms"));

    // Install the Point-To-Point Connections between Nodes
    NetDeviceContainer d02, d12, botDeviceContainer[number_of_bots];
    d02 = pp1.Install(nodes.Get(0), nodes.Get(1));
    d12 = pp1.Install(nodes.Get(1), nodes.Get(2));

    for (int i = 0; i < number_of_bots; ++i)
    {
        botDeviceContainer[i] = pp2.Install(botNodes.Get(i), nodes.Get(1));
    }

    //Assign IP to bots
    InternetStackHelper stack;
    stack.Install(nodes);
    stack.Install(botNodes);
    Ipv4AddressHelper ipv4_n;
    ipv4_n.SetBase("10.0.0.0", "255.255.255.252");

    Ipv4AddressHelper a02, a12, a23, a34;
    a02.SetBase("10.1.1.0", "255.255.255.0");
    a12.SetBase("10.1.2.0", "255.255.255.0");

    for (int j = 0; j < number_of_bots; ++j)
    {
        ipv4_n.Assign(botDeviceContainer[j]);
        ipv4_n.NewNetwork();
    }

    //Assign IP to legitimate nodes
    Ipv4InterfaceContainer i02, i12;
    i02 = a02.Assign(d02);
    i12 = a12.Assign(d12);

    // DDoS Application Behaviour
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(i12.GetAddress(1), UDP_SINK_PORT)));
    onoff.SetConstantRate(DataRate(ddosrate));
    // onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    // onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
      
    // Set the "on" and "off" times to follow an exponential distribution
    // double lambda = 2.0; // average rate (packets per second)
    onoff.SetAttribute("OnTime", StringValue("ns3::ExponentialRandomVariable[Mean=3.14]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=3.14]"));
    ApplicationContainer onOffApp[number_of_bots];

    //Install application in all bots
    for (int k = 0; k < number_of_bots; ++k)
    {
        onOffApp[k] = onoff.Install(botNodes.Get(k));
        onOffApp[k].Start(Seconds(0.0));
        onOffApp[k].Stop(Seconds(simulationTime));
    }

    // Sender Application (Packets generated by this application are throttled)
    BulkSendHelper bulkSend("ns3::TcpSocketFactory", InetSocketAddress(i12.GetAddress(1), TCP_SINK_PORT));
    bulkSend.SetAttribute("MaxBytes", UintegerValue(max_bulk_bytes));
    ApplicationContainer bulkSendApp = bulkSend.Install(nodes.Get(0));
    bulkSendApp.Start(Seconds(0.0));
    bulkSendApp.Stop(Seconds(simulationTime - 10));

    // UDPSink on receiver side
    PacketSinkHelper UDPsink("ns3::UdpSocketFactory",
                             Address(InetSocketAddress(Ipv4Address::GetAny(), UDP_SINK_PORT)));
    ApplicationContainer UDPSinkApp = UDPsink.Install(nodes.Get(2));
    UDPSinkApp.Start(Seconds(0.0));
    UDPSinkApp.Stop(Seconds(simulationTime));

    // TCP Sink Application on server side
    PacketSinkHelper TCPsink("ns3::TcpSocketFactory",
                             InetSocketAddress(Ipv4Address::GetAny(), TCP_SINK_PORT));
    ApplicationContainer TCPSinkApp = TCPsink.Install(nodes.Get(2));
    TCPSinkApp.Start(Seconds(0.0));
    TCPSinkApp.Stop(Seconds(simulationTime));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    //Simulation NetAnim configuration and node placement
    MobilityHelper mobility;

    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX", DoubleValue(0.0), "MinY", DoubleValue(0.0), "DeltaX", DoubleValue(5.0), "DeltaY", DoubleValue(10.0),
                                  "GridWidth", UintegerValue(5), "LayoutType", StringValue("RowFirst"));

    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    mobility.Install(nodes);
    mobility.Install(botNodes);

    AnimationInterface anim("DDoSim.xml");

    ns3::AnimationInterface::SetConstantPosition(nodes.Get(0), 0, 0);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(1), 10, 10);
    ns3::AnimationInterface::SetConstantPosition(nodes.Get(2), 20, 10);

    uint32_t x_pos = 0;
    for (int l = 0; l < number_of_bots; ++l)
    {
        ns3::AnimationInterface::SetConstantPosition(botNodes.Get(l), x_pos++, 30);
    }

    //Install FlowMonitor
    monitor = flowmon.InstallAll ();

    // Prepare output CSV file
    if (useCsv) {
        std::string outputCsv;
        outputCsv = "DDoSIM-"+std::to_string(RngSeedManager::GetRun())+".csv";

        myfile.open (outputCsv);  
        myfile << "SimulationTime,";
        for(uint32_t i=0;i<number_of_bots;i++) {
        myfile << "Bot Flow" << i+1 << ",";
        }
        for(uint32_t i=0;i<2;i++) {
        myfile << "Client Flow" << i+1 << ",";
        }
        myfile << "InstantThr,TotalThr" << std::endl;
        Simulator::Schedule(Seconds(warmupTime), &PrintFlowMonitorStats); //Schedule printing stats to file
    }

    // Generate PCAP at AP
    // if (pcap) {
    //     phy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
    //     phy.EnablePcap ("ex6", apDevice);
    // }


    // Define simulation stop time
    Simulator::Stop (Seconds (simulationTime + 1));

    // Print information that the simulation will be executed
    std::clog << std::endl << "Starting simulation... " << std::endl;
    // Record start time
    auto start = std::chrono::high_resolution_clock::now();

    //Run the Simulation
    Simulator::Run();

    // Record stop time and count duration
    auto finish = std::chrono::high_resolution_clock::now();
    std::clog << ("done!") << std::endl;  
    std::chrono::duration<double> elapsed = finish - start;
    std::cout << "Elapsed time: " << elapsed.count() << " s\n\n";

    if (useCsv) myfile.close();

    ////////////////////////// TCP Sink ///////////////////////////////
    
    std::cout << "Calculating TCPSinkApp throughput\n";
    // Calculate network throughput
    double throughput = 0;
    for (uint32_t index = 0; index < TCPSinkApp.GetN(); ++index) // Loop over all traffic sinks
    {   
        // std::cout << "Nodes N: " << TCPSinkApp.GetN() << "\n\n";
        uint64_t totalBytesThrough = DynamicCast<PacketSink> (TCPSinkApp.Get (index))->GetTotalRx (); //Get amount of bytes received
        // std::cout << "Bytes received: " << totalBytesThrough << std::endl;
        throughput += ((totalBytesThrough * 8) / (simulationTime * 1000000.0)); //Mbit/s 
        std::cout << "Total throughput: " << throughput << " Mbit/s \n\n";
    }
    
    //Print results
    std::cout << "Results: " << std::endl;
    std::cout << "- network throughput: " << throughput << " Mbit/s" << std::endl;

    /////////////////////// UDP Sink //////////////////////////////////

    std::cout << "Calculating UDPSinkApp throughput\n";
    // Calculate network throughput
    double throughputUDP = 0;
    for (uint32_t index = 0; index < UDPSinkApp.GetN(); ++index) // Loop over all traffic sinks
    {   
        // std::cout << "Nodes N: " << UDPSinkApp.GetN() << "\n\n";
        uint64_t totalBytesThrough = DynamicCast<PacketSink> (UDPSinkApp.Get (index))->GetTotalRx (); //Get amount of bytes received
        // std::cout << "Bytes received: " << totalBytesThrough << std::endl;
        throughputUDP += ((totalBytesThrough * 8) / (simulationTime * 1000000.0)); //Mbit/s 
        std::cout << "Total throughput: " << throughputUDP << " Mbit/s \n\n";
    }

    //Print results
    std::cout << "Results: " << std::endl;
    std::cout << "- network throughput: " << throughputUDP << " Mbit/s" << std::endl;


    ///////////////////////////////////


    //Clean-up
    Simulator::Destroy();
    return 0;
}


bool fileExists(const std::string& filename)
{
    std::ifstream f(filename.c_str());
    return f.good();   
}


void PrintFlowMonitorStats () {  
  double flowThr=0;
  double totalThr=0;
  uint32_t rxBytes=0;

  // ns3::FlowMonitor::FlowStats::bytesDropped
  std::map<FlowId, FlowMonitor::FlowStats> flowStats = monitor->GetFlowStats ();	  
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());

  if (Simulator::Now().GetSeconds () == warmupTime) { //First function call, need to initialize rxBytesWarmup
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator stats = flowStats.begin (); stats != flowStats.end (); ++stats) {
      rxBytesWarmup[stats->first-1] = stats->second.rxBytes;
      rxBytesPrev += stats->second.rxBytes;
    }
  }
  else {
    myfile << Simulator::Now().GetSeconds () << ",";
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator stats = flowStats.begin (); stats != flowStats.end (); ++stats)
    {
      flowThr=(stats->second.rxBytes-rxBytesWarmup[stats->first-1]) * 8.0 / ((Simulator::Now().GetSeconds () - warmupTime) * 1e6);
      myfile<< flowThr << ", ";
      if (stats->second.rxBytes!=0) {
        rxBytes += stats->second.rxBytes;
        totalThr += flowThr;
      }
    }
    myfile << ((rxBytes-rxBytesPrev)*8/(interval*1e6)) << "," << totalThr << std::endl;
    rxBytesPrev = rxBytes;
  }

  Simulator::Schedule(Seconds(interval), &PrintFlowMonitorStats); //Schedule next stats printout
}
