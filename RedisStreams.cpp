/**
 * TcpReassembly application (hacked for redis streams by djbyrne)
 *
 *  Leaving in the description from the original PcapPlusPlus so you can get an
 *  understanding of what's going on.
 *
 *  All that I added was support to direclty parse out redis commands, in my
 *  pcaps I ended up with ~100Ks of connections. This is much faster.
 *
 *  I also estimated the times for the commands based on the start and end time of the flow (assumed unifrom distribution
 *  between the intervals).
 *
 *  It works for me so I hope it works for you.
 *
 *  Normally, I run something like './RedisStreams -r some_input_pcap -e "tcp dst port 6379" -o commands.csv
 *
 *  it outputs commands in tuple (time,srcIP,command,KEY,PARAM1,PARAM2,...)
 *
 * =========================
 * This is an application that captures data transmitted as part of TCP connections, organizes the data and stores it in a way that is convenient for protocol analysis and debugging.
 * This application reconstructs the TCP data streams and stores each connection in a separate file(s). TcpReassembly understands TCP sequence numbers and will correctly reconstruct
 * data streams regardless of retransmissions, out-of-order delivery or data loss.
 * TcpReassembly works more or less the same like tcpflow (https://linux.die.net/man/1/tcpflow) but probably with less options.
 * The main purpose of it is to demonstrate the TCP reassembly capabilities in PcapPlusPlus.
 * Main features and capabilities:
 *   - Captures packets from pcap/pcapng files or live traffic
 *   - Handles TCP retransmission, out-of-order packets and packet loss
 *   - Possibility to set a BPF filter to process only part of the traffic
 *   - Write each connection to a separate file
 *   - Write each side of each connection to a separate file
 *   - Limit the max number of open files in each point in time (to avoid running out of file descriptors for large files / heavy traffic)
 *   - Write a metadata file (txt file) for each connection with various stats on the connection: number of packets (in each side + total), number of TCP messages (in each side + total),
 *     number of bytes (in each side + total)
 *   - Write to console only (instead of files)
 *   - Set a directory to write files to (default is current directory)
 *
 * For more details about modes of operation and parameters run TcpReassembly -h
 */


#include <stdlib.h>
#include <stdio.h>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <getopt.h>
#include <hiredis/hiredis.h>
#include <pcapplusplus/TcpReassembly.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PlatformSpecificUtils.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/PcapPlusPlusVersion.h>
#include <pcapplusplus/LRUList.h>

using namespace pcpp;
using std::cout;
using std::endl;
using std::string;

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)


#if defined(WIN32) || defined(WINx64)
#define SEPARATOR '\\'
#else
#define SEPARATOR '/'
#endif


// unless the user chooses otherwise - default number of concurrent used file descriptors is 500
#define DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES 500


static struct option TcpAssemblyOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"input-file",  required_argument, 0, 'r'},
	{"output-dir", required_argument, 0, 'o'},
	{"list-interfaces", no_argument, 0, 'l'},
	{"filter", required_argument, 0, 'e'},
	{"write-metadata", no_argument, 0, 'm'},
	{"write-to-console", no_argument, 0, 'c'},
	{"separate-sides", no_argument, 0, 's'},
	{"max-file-desc", required_argument, 0, 'f'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
	{0, 0, 0, 0}
};

static std::fstream outputFile;
uint32_t flowKeyToCloseSet = 0;
uint32_t flowKeyToClose = 0;
bool do_LRU = false;

/**
 * A singleton class containing the configuration as requested by the user. This singleton is used throughout the application
 */
class GlobalConfig
{
private:

	/**
	 * A private c'tor (as this is a singleton)
	 */
	GlobalConfig() { writeMetadata = false; writeToConsole = false; separateSides = false; maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES; m_RecentConnsWithActivity = NULL; }

	// A least-recently-used (LRU) list of all connections seen so far. Each connection is represented by its flow key. This LRU list is used to decide which connection was seen least
	// recently in case we reached max number of open file descriptors and we need to decide which files to close
	LRUList<uint32_t>* m_RecentConnsWithActivity;

public:

	// a flag indicating whether to write a metadata file for each connection (containing several stats)
	bool writeMetadata;

	// the directory to write files to (default is current directory)
	std::string outputDir;

	// a flag indicating whether to write TCP data to actual files or to console
	bool writeToConsole;

	// a flag indicating whether to write both side of a connection to the same file (which is the default) or write each side to a separate file
	bool separateSides;

	// max number of allowed open files in each point in time
	size_t maxOpenFiles;


	/**
	 * A method getting connection parameters as input and returns a filename and file path as output.
	 * The filename is constructed by the IPs (src and dst) and the TCP ports (src and dst)
	 */
	std::string getFileName(ConnectionData connData, int side, bool separareSides)
	{
		std::stringstream stream;

		// if user chooses to write to a directory other than the current directory - add the dir path to the return value
		if (!outputDir.empty())
			stream << outputDir << SEPARATOR;

		std::string sourceIP = connData.srcIP.toString();
		std::string destIP = connData.dstIP.toString();

		// for IPv6 addresses, replace ':' with '_'
		std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
		std::replace(destIP.begin(), destIP.end(), ':', '_');

		// side == 0 means data is sent from client->server
		if (side <= 0 || separareSides == false)
			stream << sourceIP << '.' << connData.srcPort << '-' << destIP << '.' << connData.dstPort;
		else // side == 1 means data is sent from server->client
			stream << destIP << '.' << connData.dstPort << '-' << sourceIP << '.' << connData.srcPort;

		// return the file path
		return stream.str();
	}


	/**
	 * Open a file stream. Inputs are the filename to open and a flag indicating whether to append to an existing file or overwrite it.
	 * Return value is a pointer to the new file stream
	 */
	std::ostream* openFileStream(std::string fileName, bool reopen)
	{
		// if the user chooses to write only to console, don't open anything and return std::cout
		if (writeToConsole)
			return &std::cout;

		// open the file on the disk (with append or overwrite mode)
		if (reopen)
			return new std::ofstream(fileName.c_str(), std::ios_base::binary | std::ios_base::app);
		else
			return new std::ofstream(fileName.c_str(), std::ios_base::binary);
	}


	/**
	 * Close a file stream
	 */
	void closeFileSteam(std::ostream* fileStream)
	{
		// if the user chooses to write only to console - do nothing and return
		if (!writeToConsole)
		{
			// close the file stream
			std::ofstream* fstream = (std::ofstream*)fileStream;
			fstream->close();

			// free the memory of the file stream
			delete fstream;
		}
	}


	/**
	 * Return a pointer to the least-recently-used (LRU) list of connections
	 */
	LRUList<uint32_t>* getRecentConnsWithActivity()
	{
		// This is a lazy implementation - the instance isn't created until the user requests it for the first time.
		// the side of the LRU list is determined by the max number of open connectiosn, current 100K
		// but the user can choose another number
		if (m_RecentConnsWithActivity == NULL)
			m_RecentConnsWithActivity = new LRUList<uint32_t>(100000);

		// return the pointer
		return m_RecentConnsWithActivity;
	}


	/**
	 * The singleton implementation of this class
	 */
	static GlobalConfig& getInstance()
	{
		static GlobalConfig instance;
		return instance;
	}
	
	/**
	 * d'tor
	 */
	~GlobalConfig()
	{
		delete m_RecentConnsWithActivity;
	}
};


/**
 * A struct to contain all data save on a specific connection. It contains the file streams to write to and also stats data on the connection
 */
struct TcpReassemblyData
{

	// stats data: num of data packets on each side, bytes seen on each side and messages seen on each side
	int numOfDataPackets[2];
	int numOfMessagesFromSide[2];
	int bytesFromSide[2];
    int curSide;
    
    //redis data
    string redisData;
    
    //start and end time of stream
    timeval startTime;
    timeval endTime;

    //stream number, index
    int streamNum;
	/**
	 * the default c'tor
	 */
	TcpReassemblyData() { clear(); }

	/**
	 * The default d'tor
	 */
	~TcpReassemblyData()
	{
	}

	/**
	 * Clear all data (put 0, false or NULL - whatever relevant for each field)
	 */
	void clear()
	{
        streamNum = 0;
        redisData = "";
        startTime.tv_sec = 0;
        startTime.tv_usec = 0;
        endTime.tv_sec = 0;
        endTime.tv_usec = 0;
		numOfDataPackets[0] = 0;
		numOfDataPackets[1] = 0;
		numOfMessagesFromSide[0] = 0;
		numOfMessagesFromSide[1] = 0;
		bytesFromSide[0] = 0;
		bytesFromSide[1] = 0;
		curSide = -1;
	}
};


// typedef representing the connection manager and its iterator
typedef std::map<uint32_t, TcpReassemblyData> TcpReassemblyConnMgr;
typedef std::map<uint32_t, TcpReassemblyData>::iterator TcpReassemblyConnMgrIter;


/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage:\n"
			"------\n"
			"%s [-hvlc] [-r input_file] [-i interface] [-o output_dir] [-e bpf_filter] [-f max_files]\n"
			"\nOptions:\n\n"
			"    -r input_file : Input pcap/pcapng file to analyze. Required argument for reading from file\n"
			"    -i interface  : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address. Required argument for capturing from live interface\n"
			"    -o output_file : Specify output filename\n"
			"    -e bpf_filter : Apply a BPF filter to capture file or live interface, meaning TCP reassembly will only work on filtered packets\n"
			"    -m            : Remove the LRU connection if there are more than 100K open at a time\n"
			"    -c            : Write all output to console (nothing will be written to files)\n"
			"    -l            : Print the list of interfaces and exit\n"
			"    -v            : Display the current version and exit\n"
			"    -h            : Display this help message and exit\n\n", AppName::get().c_str());
	exit(0);
}


/**
 * Print application version
 */
void printAppVersion()
{
	printf("%s %s\n", AppName::get().c_str(), getPcapPlusPlusVersionFull().c_str());
	printf("Built: %s\n", getBuildDateTime().c_str());
	printf("Built from: %s\n", getGitInfo().c_str());
	exit(0);
}


/**
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
	const std::vector<PcapLiveDevice*>& devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	printf("\nNetwork interfaces:\n");
	for (std::vector<PcapLiveDevice*>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
	{
		printf("    -> Name: '%s'   IP address: %s\n", (*iter)->getName(), (*iter)->getIPv4Address().toString().c_str());
	}
	exit(0);
}


/**
 * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
 */
static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const TcpStreamData& tcpData, void* userCookie)
{
	// extract the connection manager from the user cookie
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	// check if this flow already appears in the connection manager. If not add it
	TcpReassemblyConnMgrIter iter = connMgr->find(tcpData.getConnectionData().flowKey);
	if (iter == connMgr->end())
	{
		connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyData()));
		iter = connMgr->find(tcpData.getConnectionData().flowKey);
        //record the start time
        iter->second.startTime = tcpData.getConnectionData().startTime; 
	}
		
    // add the flow key of this connection to the list of open connections. If the return value isn't NULL it means that there are too many open files
	// and we need to close the connection with least recently used file(s) in order to open a new one.
	// The connection with the least recently used file is the return value
    uint32_t lruFlowKey;
	int result = GlobalConfig::getInstance().getRecentConnsWithActivity()->put(tcpData.getConnectionData().flowKey, &lruFlowKey);

	// if result equals to 1 it means we need to close the           LRU connection (the one with the least recently used files)
	if (result == 1) 
    {
		TcpReassemblyConnMgrIter iter2 = connMgr->find(lruFlowKey);
		if (iter2 != connMgr->end())
		{ 
            flowKeyToCloseSet = 1;
            flowKeyToClose = lruFlowKey;
        }            

    }


	iter->second.numOfDataPackets[sideIndex]++;
	iter->second.bytesFromSide[sideIndex] += (int)tcpData.getDataLength();

	// write the data to the map
	iter->second.redisData += string((char*)tcpData.getData(), tcpData.getDataLength());
    

}


/**
 * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the connection to the connection manager
 */
static void tcpReassemblyConnectionStartCallback(const ConnectionData& connectionData, void* userCookie)
{
	// get a pointer to the connection manager
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	// look for the connection in the connection manager
	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

	// assuming it's a new connection
	if (iter == connMgr->end())
	{
		// add it to the connection manager
		connMgr->insert(std::make_pair(connectionData.flowKey, TcpReassemblyData()));
		iter = connMgr->find(connectionData.flowKey);
        //record the start time
        iter->second.startTime = connectionData.startTime; 
	}
}


static void parseRedisData(const char *redisData, size_t dataLen, timeval startTime, timeval endTime, string srcIP) 
{

    int status = 0;
    redisReader *rr = redisReaderCreate();
    if (dataLen > 8*1024)
        rr->maxbuf = dataLen+256;
    
    redisReaderFeed(rr, redisData, dataLen);
    unsigned int iter = 1;
    std::list<string> lines;
    do {
       void *reply;
       std::stringstream ss;
       string line;
       status = redisReaderGetReply(rr,&reply);
       if (reply != NULL) {
            redisReply *r = (redisReply*)reply;
            if (r->type == REDIS_REPLY_ARRAY) {
                for (unsigned int j = 0; j < r->elements; j++) {
                    redisReply *o = r->element[j];
                    if (o->type == REDIS_REPLY_ARRAY) {
                        cout << "NESTED DATA" << endl;
                    } else if (o->type == REDIS_REPLY_STRING) {
                        string rep = string(o->str,o->len);
                        if (o->len == 0) {
                             ss << "," << "nil";
                        }
                        else {
                             ss << "," << rep;
                        }
                    } else if (o->type == REDIS_REPLY_INTEGER) {
                        ss << "," << o->integer;
                    }
                }
                ss << endl;
                line = ss.str();
                lines.push_back(line);
            }
            else {
                cout << "ERROR DATA!!" << endl;
            }
            freeReplyObject(reply);
       } else {
           break;
       }
       iter++;
    } while (status == REDIS_OK);

    timeval interval;
    timersub(&endTime,&startTime,&interval);

    uint64_t elapsedTime = interval.tv_sec * 1000000 + interval.tv_usec;

    int numLines;
    if (lines.size() == 1)
        numLines = 1;
    else
        numLines = lines.size()-1;
    //this is in microsends right now, convert to timeval
    uint64_t normTime = elapsedTime/numLines;
    uint64_t normSecs = normTime / 1000000;
    uint64_t normUs = normTime % 1000000;
    timeval norm;
    norm.tv_sec = normSecs;
    norm.tv_usec = normUs;
   
    //time debugging
    //cout << "Stream Start: " << startTime.tv_sec << "." << startTime.tv_usec << endl;
    //cout << "Stream Norm: " << norm.tv_sec << "." << norm.tv_usec << " (nlines) " << numLines << endl;
    //cout << "Stream Int: " << interval.tv_sec << "." << interval.tv_usec << endl;
    //cout << "Stream End: " << endTime.tv_sec << "." << endTime.tv_usec << endl;
    std::list<string>::iterator it;
    for (it = lines.begin(); it != lines.end(); ++it) {

        timeval estTime;
        if (it == lines.begin()) {
            estTime.tv_sec = startTime.tv_sec;
            estTime.tv_usec = startTime.tv_usec;
        }
        else {
            timeradd(&startTime,&norm,&estTime);
        }
        string line = *it;
        outputFile << estTime.tv_sec << "." << estTime.tv_usec << "," << srcIP << line;
        outputFile.flush();
        startTime.tv_sec = estTime.tv_sec;
        startTime.tv_usec = estTime.tv_usec;
        
    }

    
    redisReaderFree(rr);

}

/**
 * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the connection from the connection manager and writes the metadata file if requested
 * by the user
 */
static void tcpReassemblyConnectionEndCallback(const ConnectionData& connectionData, TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
	// get a pointer to the connection manager
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	// find the connection in the connection manager by the flow key
	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

	// connection wasn't found - shouldn't get here
	if (iter == connMgr->end())
		return;

    //record end time
    iter->second.endTime = connectionData.endTime;

    const char *redisData = iter->second.redisData.c_str();
    size_t dataLen = strlen(redisData);
    string srcIP = connectionData.srcIP.toString();
    //parse the redis data
    if (dataLen > 0)
        parseRedisData(redisData,dataLen,iter->second.startTime,iter->second.endTime,srcIP);

    //cout << "END STREAM" << endl;
	// remove the connection from the connection manager
	connMgr->erase(iter);
}


/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
static void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
}


/**
 * packet capture callback - called whenever a packet arrives on the live device (in live device capturing mode)
 */
static void onPacketArrives(RawPacket* packet, PcapLiveDevice* dev, void* tcpReassemblyCookie)
{
	// get a pointer to the TCP reassembly instance and feed the packet arrived to it
	TcpReassembly* tcpReassembly = (TcpReassembly*)tcpReassemblyCookie;
	tcpReassembly->reassemblePacket(packet);
}


/**
 * The method responsible for TCP reassembly on pcap/pcapng files
 */
void doTcpReassemblyOnPcapFile(std::string fileName, TcpReassembly& tcpReassembly, std::string bpfFiler = "")
{
	// open input file (pcap or pcapng file)
	IFileReaderDevice* reader = IFileReaderDevice::getReader(fileName.c_str());

	// try to open the file device
	if (!reader->open())
		EXIT_WITH_ERROR("Cannot open pcap/pcapng file");

	// set BPF filter if set by the user
	if (!bpfFiler.empty())
	{
		if (!reader->setFilter(bpfFiler))
			EXIT_WITH_ERROR("Cannot set BPF filter to pcap file");
	}

    uint64_t packetno = 0;
	// run in a loop that reads one packet from the file in each iteration and feeds it to the TCP reassembly instance
	RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket))
	{
        packetno++;
		tcpReassembly.reassemblePacket(&rawPacket);
        if (flowKeyToCloseSet == 1 && do_LRU) {
            tcpReassembly.closeConnection(flowKeyToClose);
            flowKeyToCloseSet = 0;
            flowKeyToClose = 0;

            //bulk evict 1K while we are at it
            int i = 0;
            while (i < 999) {
                LRUList<uint32_t> *lruConn = GlobalConfig::getInstance().getRecentConnsWithActivity();
                uint32_t lruFlowKey = lruConn->getLRUElement(); 
                tcpReassembly.closeConnection(lruFlowKey);
                lruConn->eraseElement(lruFlowKey);
                i++;
            }
        }
        if (packetno % 10000000 == 0)
            cout << "processing packet " << packetno << endl;
	}

	// extract number of connections before closing all of them
	//size_t numOfConnectionsProcessed = tcpReassembly.getConnectionInformation().size();

	// after all packets have been read - close the connections which are still opened
	tcpReassembly.closeAllConnections();

	// close the reader and free its memory
	reader->close();
	delete reader;

	//printf("Done! processed %d connections\n", (int)numOfConnectionsProcessed);
}


/**
 * The method responsible for TCP reassembly on live traffic
 */
void doTcpReassemblyOnLiveTraffic(PcapLiveDevice* dev, TcpReassembly& tcpReassembly, std::string bpfFiler = "")
{
	// try to open device
	if (!dev->open())
		EXIT_WITH_ERROR("Cannot open interface");

	// set BPF filter if set by the user
	if (!bpfFiler.empty())
	{
		if (!dev->setFilter(bpfFiler))
			EXIT_WITH_ERROR("Cannot set BPF filter to interface");
	}

	printf("Starting packet capture on '%s'...\n", dev->getIPv4Address().toString().c_str());

	// start capturing packets. Each packet arrived will be handled by onPacketArrives method
	dev->startCapture(onPacketArrives, &tcpReassembly);

	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	// run in an endless loop until the user presses ctrl+c
	while(!shouldStop)
		PCAP_SLEEP(1);

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();

	// close all connections which are still opened
	tcpReassembly.closeAllConnections();

}


/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	AppName::init(argc, argv);

	std::string interfaceNameOrIP;
	std::string inputPcapFileName;
	std::string bpfFilter;
	std::string outputFilename;
	std::string outputDir;
	bool writeMetadata = false;
	bool writeToConsole = false;
	bool separateSides = false;
	size_t maxOpenFiles = DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES;

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "i:r:o:e:f:mcsvhl", TcpAssemblyOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'i':
				interfaceNameOrIP = optarg;
				break;
			case 'r':
				inputPcapFileName = optarg;
				break;
			case 'o':
				outputFilename = optarg;
				break;
			case 'e':
				bpfFilter = optarg;
				break;
			case 's':
				separateSides = true;
				break;
			case 'm':
				do_LRU = true;
				break;
			case 'c':
				writeToConsole = true;
				break;
			case 'f':
				maxOpenFiles = (size_t)atoi(optarg);
				break;
			case 'h':
				printUsage();
				break;
			case 'v':
				printAppVersion();
				break;
			case 'l':
				listInterfaces();
				break;
			default:
				printUsage();
				exit(-1);
		}
	}

    outputFile.open(outputFilename, std::fstream::out );

	// if no interface nor input pcap file were provided - exit with error
	if (inputPcapFileName.empty() && interfaceNameOrIP.empty())
		EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");

	// verify output dir exists
	if (!outputDir.empty() && !directoryExists(outputDir))
		EXIT_WITH_ERROR("Output directory doesn't exist");

	// set global config singleton with input configuration
	GlobalConfig::getInstance().outputDir = outputDir;
	GlobalConfig::getInstance().writeMetadata = writeMetadata;
	GlobalConfig::getInstance().writeToConsole = writeToConsole;
	GlobalConfig::getInstance().separateSides = separateSides;
	GlobalConfig::getInstance().maxOpenFiles = maxOpenFiles;

	// create the object which manages info on all connections
	TcpReassemblyConnMgr connMgr;

	// create the TCP reassembly instance
	TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &connMgr, tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback);

	// analyze in pcap file mode
	if (!inputPcapFileName.empty())
	{
		doTcpReassemblyOnPcapFile(inputPcapFileName, tcpReassembly, bpfFilter);
	}
	else // analyze in live traffic mode
	{
		// extract pcap live device by interface name or IP address
		PcapLiveDevice* dev = NULL;
		IPv4Address interfaceIP(interfaceNameOrIP);
		if (interfaceIP.isValid())
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
			if (dev == NULL)
				EXIT_WITH_ERROR("Couldn't find interface by provided IP");
		}
		else
		{
			dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
			if (dev == NULL)
				EXIT_WITH_ERROR("Couldn't find interface by provided name");
		}

		// start capturing packets and do TCP reassembly
		doTcpReassemblyOnLiveTraffic(dev, tcpReassembly, bpfFilter);
	}

    outputFile.close();
}
