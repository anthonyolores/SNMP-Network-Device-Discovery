//net-snmp
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/keytools.h>

//local
#include "HEADER.h";

//win
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char **listHosts;
char **head_listHost;
long totalNumHosts = 0;

int getDigitFromChar(char c)
{
	int ascii = (int) c;

	if(ascii > 47 && ascii < 58)
	{
		//0-9
		return ascii - 48;
	}
	else
	{
		//not digit
		return -1;
	}
}

int getSubnetTotal(char *subnet)
{
	int total = 0;
	int dotCounter = 0;
	int digitCounter = 0;
	int subnetLen = strlen(subnet);
	int charCounter = 0;
	int  num[3] = {-1,-1,-1};
	while(*subnet != '\0')
	{
		
		if(*subnet != '.')
		{
			int digit = getDigitFromChar(*subnet);	
			if(digit == -1)
			{
				total = -1;
				break;
			}
			else
			{
				num[digitCounter] = digit;
				digitCounter++;
			}
		}

		//add total
		if(*subnet == '.' || charCounter == (subnetLen-1))
		{
			for(int i = digitCounter-1; i >= 0; i--)
			{
				if(i == 2)
				{
					total += num[i];
				}
				else if(i == 1)
				{
					total +=  (num[i] * 10);
				}
				else if(i == 0)
				{
					//check if 1 digit only
					if(num[1] != -1 && num[2] != -1)
					{
						total += (num[i] * 100);
					}
					else
					{
						total += num[i];
					}

				}
			}
		
			digitCounter = 0;
			num[0] = -1;
			num[1] = -1;
			num[2] = -1;

			if(charCounter != (subnetLen-1))
			{
				dotCounter++;
				if(dotCounter == 4)
				{
					total = -1;
					break;
				}		
			}

		}

		subnet++;	
		charCounter++;
	}

	return total;
}

SUBNET_CLASS getSubNetworkClass(int subnetTotal)
{

	if(subnetTotal <= 255)
	{
		return CLASS_A;
	}
	else if(subnetTotal <=510)
	{
		return CLASS_B;
	}
	else if(subnetTotal <= 765)
	{
		return CLASS_C;
	}
	else
	{
		return CLASS_D;
	}
}

long getTotalNumHosts(int hostBits, long total)
{
	if(total == 0)
		total += 1;
	else
	{
		total *= 2;
	}

	//printf("host bit = %d, total = %d\n", hostBits, total);
	
	hostBits = hostBits-1;
	return hostBits==0?total-1: getTotalNumHosts(hostBits, total);
}

int getHosts(int subnetRange, SUBNET_CLASS subnetClass, char * ip_address, char **hosts, int hostBits)
{
	int len = strlen(ip_address);
	char *network = (char*)malloc(len);
	char *subnetwork = (char*)malloc(3);
	int subnetworkCounter = 0;
	int networkCounter = 0;

	int dotCounter = 0;
	int charCounter = 0;

	while(*ip_address != '\0')
	{
		if(*ip_address != '.' && getDigitFromChar(*ip_address) == -1)
		{
			return RESULT_INVALID_IP_ADDRESS;
		}
		else if(*ip_address == '.')
		{
			if(dotCounter == 3)
			{
				return RESULT_INVALID_IP_ADDRESS;
			}

			dotCounter++;
		}

		//get network 
		if(dotCounter < subnetClass-1)
		{
			network[charCounter] = *ip_address;
			networkCounter++;
		}

		//get subnetwork
		if(dotCounter == subnetClass-1)
		{
			//ip_address++;
			subnetwork[subnetworkCounter] = *ip_address;
			subnetworkCounter++;
		}

		ip_address++;
		charCounter++;
	}

	//network
	char *network_num = (char *)malloc(networkCounter);
	memset(network_num, 0, networkCounter);
	strncpy(network_num, network, networkCounter);
	network_num[networkCounter] = '\0';


	//subnetwork
	subnetwork++;//remove '.' or dot
	char *subnetwork_num = (char *)malloc(subnetworkCounter);
	memset(subnetwork_num, 0, sizeof(char)*subnetworkCounter);
	strncpy(subnetwork_num, subnetwork, subnetworkCounter);
	int subnet_int = atoi (subnetwork_num);
	
	//network ID and Broadcast ID
	int networkId = (subnet_int/subnetRange)*subnetRange;
	int broadCastId = networkId + (subnetRange-1);

	totalNumHosts = 255 * subnetRange;//getTotalNumHosts(hostBits,0);
	//long sample = totalNumHosts*(subnetClass==CLASS_C?255:1);
	listHosts = (char **) malloc((sizeof(char*)*HOST_LEN) * totalNumHosts);
	head_listHost = listHosts;
	bool reachNetWorkAdd = false;

	//first 8bit
	for(int b1 = networkId; b1 <= broadCastId; b1++)
	{

		if(subnetClass == CLASS_D)
		{	
			//concatenate
			*listHosts = (char *) malloc(sizeof(char)*HOST_LEN);
			snprintf(*listHosts, HOST_LEN, "%s.%d\0", network_num, b1);		
			listHosts++;//next address
		}
		else
		{
			//set only 1 network 
			//b1 = 256;
			//2nd 8bit
			for(int b2 = 1; b2 < 256; b2++)
			{
				if(subnetClass == CLASS_C)
				{
					//concatenate
					*listHosts = (char *) malloc(sizeof(char)*HOST_LEN);
					snprintf(*listHosts, HOST_LEN, "%s.%d.%d\0", network_num, b1, b2);		
					listHosts++;//next address
				}
				#ifdef SUPPORT CLASS B/A NETWORK
				else
				{			
					//3rd 8bit
					for(int b3 = 1; b3 < 256; b3++)
					{
						if(subnetClass == CLASS_B)
						{
							//concatenate
							*listHosts = (char *) malloc(sizeof(char)*HOST_LEN);
							snprintf(*listHosts, HOST_LEN, "%s.%d.%d.%d\0", network_num,b1, b2, b3);		
							listHosts++;//next address
						}
						else
						{
							//4th 8bit
							for(int b4 = 1; b4 < 256; b4++)
							{
								//concatenate
								*listHosts = (char *) malloc(sizeof(char)*HOST_LEN);
								snprintf(*listHosts, HOST_LEN, "%d.%d.%d.%d\0", network_num,b1, b2, b3,b4);		
								listHosts++;//next address
							}					
						}

					}			
				}
				#endif
			}
		}

		
		
	}

		
	
}

int getSubnetRange(int subnetTotal)
{
	int range = 0;
	int mod = subnetTotal%255;
	range = mod==0?1:(255-mod)+1; //1 to max range
	
	return range;
}


int getHostBits(int subnetTotal, SUBNET_CLASS subnetClass)
{
	int range = 0;
	int mod = subnetTotal%255;
	range = (255-mod)+1; //1 to max range

	int bitCounter = 0;
	for(int i = 128; i>=1; i/=2)
	{
		bitCounter++;
		if(range == i)
		{
			break;
		}
	}
	
	return (8-bitCounter) + (8*(4-subnetClass));
}


int setHostList(char *ip_address, char *subnet_mask)
{
	//get subnet range
	int subnetTotal = getSubnetTotal(subnet_mask);
	SUBNET_CLASS subnetClass;
	int subnetRange=0;
	int hostBits = 0;
	if(subnetTotal != -1)
	{
		subnetClass = getSubNetworkClass(subnetTotal);

		if(subnetClass == CLASS_A || subnetClass == CLASS_B)
		{
			return RESULT_INVALID_SUBNET_MASK;
		}

		subnetRange = getSubnetRange(subnetTotal);
	}
	else
	{
		//subnet mask input is invalid
		return -1;	
	}

	//get hosts
	char **hosts = NULL;
	hostBits = getHostBits(subnetTotal, subnetClass);
	int ret = getHosts(subnetRange, subnetClass, ip_address, hosts, hostBits);

	if(ret == RESULT_INVALID_IP_ADDRESS)
	{
		return ret;
	}

	return 0;
}


HANDLE Init()
{
	return (HANDLE)0x01;
}

void Exit(HANDLE i_Handler)
{
	i_Handler = NULL;
}

int checkParameters(DiscoverDeviceReq i_Req)
{

	//check string parameters
	if(i_Req.ipAddress == NULL || strlen(i_Req.ipAddress) < 7 || i_Req.ipAddress[strlen(i_Req.ipAddress)-1] == '.')
	{
		return RESULT_INVALID_IP_ADDRESS;
	}
	else if(i_Req.subnetMask == NULL || strlen(i_Req.subnetMask) < 9 || i_Req.subnetMask[strlen(i_Req.subnetMask)-1] == '.')
	{
		return RESULT_INVALID_SUBNET_MASK;
	}
	else if(i_Req.snmpVersion == KMSNMP_VERSION_1_2)
	{
		if(i_Req.snmpv21Info.communityName == NULL || strlen(i_Req.snmpv21Info.communityName) == 0)
		{
			return RESULT_INVALID_SNMPV2_1_COMM_NAME;
		}
	}
	else if(i_Req.snmpVersion == KMSNMP_VERSION_3)
	{
		if(i_Req.snmpv3Info.username == NULL || strlen(i_Req.snmpv3Info.username) == 0)
		{
			return RESULT_INVALID_SNMPV3_USERNAME;
		}
		else if(i_Req.snmpv3Info.password == NULL || strlen(i_Req.snmpv3Info.password) == 0)
		{
			return RESULT_INVALID_SNMPV3_PASSWORD;
		}
	}
	else if(!i_Req.snmpVersion != KMSNMP_VERSION_3 || i_Req.snmpVersion != KMSNMP_VERSION_1_2)
	{
		return RESULT_SNMP_VERSION_NOT_SET;
	}

	return 0;	
}

int DiscoverDevice(HANDLE i_Handle, DiscoverDeviceReq i_Req, DiscoverDeviceRes* o_Res)
{

	if(!i_Handle)
		RESULT_INVALID_HANDLE;

	int check_param_result = checkParameters(i_Req);
	if(check_param_result != 0)
		return check_param_result;	

	//set number of host/s into the list
	int ret = setHostList(i_Req.ipAddress, i_Req.subnetMask);

	//invalid subnet mask
	if(ret == -1 || ret == RESULT_INVALID_SUBNET_MASK)
	{
		return RESULT_INVALID_SUBNET_MASK;
	}
	//invalid ip address
	else if(ret == RESULT_INVALID_IP_ADDRESS)
	{
		return RESULT_INVALID_IP_ADDRESS;
	}

	netsnmp_session session, *ss;
	netsnmp_pdu *pdu;
	netsnmp_pdu *response;
	netsnmp_variable_list *vars;

    //Initialize the SNMP library 
    init_snmp("snmp discovery");

	//set head pointer
	listHosts = head_listHost;

	TempDiscovery *tempDiscovery = (TempDiscovery *) malloc(sizeof(TempDiscovery));
	TempDiscovery *headDescovery = tempDiscovery;

	//initialize number of sesssions to be sent
	netsnmp_session ** session_list = (netsnmp_session **)malloc(sizeof(netsnmp_session *) * totalNumHosts);
	netsnmp_session ** temp_list = session_list;

	int status = 0;
	
	int deviceCounter = 0;
	for(int i = 0 ; i < totalNumHosts; i++)
	{

		//Initialize a "session" that defines who we're going to talk to
		snmp_sess_init( &session ); 

		//set session basic values
		session.peername = strdup(listHosts[i]);
		session.timeout = 1;
		session.retries = 1;

		/* set up the authentication parameters for talking to the server */	
		if(i_Req.snmpVersion == KMSNMP_VERSION_3)
		{
			///* Use SNMPv3 to talk to the experimental server */

			///* set the SNMP version number */
			session.version=SNMP_VERSION_3;
			session.securityModel = 3; 

			///* set the SNMPv3 user name */
			session.securityName = strdup("deviceusername");
			session.securityNameLen = strlen(session.securityName);

			///* set the security level to authenticated, but not encrypted */
			session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;

			/* authentication */
			if(i_Req.snmpv3Info.auth == SNMPV3_SHA1)
			{
				//SHA1
				session.securityAuthProto = usmHMACSHA1AuthProtocol; 
				session.securityAuthProtoLen = sizeof(usmHMACSHA1AuthProtocol)/sizeof(oid);
				session.securityAuthKeyLen = USM_AUTH_KU_LEN;
			}
			else
			{
				///MD5
				session.securityAuthProto = usmHMACMD5AuthProtocol;
				session.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol)/sizeof(oid);
				session.securityAuthKeyLen = USM_AUTH_KU_LEN;		
			}

		
			/*privilege */
			if(i_Req.snmpv3Info.priv == SNMPV3_DES)
			{
				//DES
				session.securityPrivProto = usmDESPrivProtocol;
				session.securityPrivProtoLen = sizeof(usmDESPrivProtocol)/sizeof(oid);
				session.securityPrivKeyLen = USM_PRIV_KU_LEN;		
			}
			else
			{
				//AES
				session.securityPrivProto = usmAESPrivProtocol;
				session.securityPrivProtoLen = sizeof(usmAESPrivProtocol)/sizeof(oid);
				session.securityPrivKeyLen = USM_PRIV_KU_LEN;
				session.securityAuthKey[0] = (u_char)strdup(i_Req.snmpv3Info.username);		
			}


			/* generate encrypted keys */
			if (generate_Ku(session.securityAuthProto,
							session.securityAuthProtoLen,
							(u_char *) i_Req.snmpv3Info.password, strlen(i_Req.snmpv3Info.password),
							session.securityAuthKey,
							&session.securityAuthKeyLen) != SNMPERR_SUCCESS) 
			{
				return RESULT_INVALID_SNMPV3_AUTH;
			}
			if (generate_Ku(session.securityAuthProto,
						session.securityAuthProtoLen,
						(u_char *) i_Req.snmpv3Info.password, strlen(i_Req.snmpv3Info.password),
						session.securityPrivKey,
						&session.securityPrivKeyLen) != SNMPERR_SUCCESS) 
			{
				RESULT_INVALID_SNMPV3_PRIV;
			}	
		}
		else
		{
			/* set the SNMP version number */
			session.version = SNMP_VERSION_2c;

			/* set the SNMPv1 community name used for authentication */
			session.community = (u_char*)strdup(i_Req.snmpv21Info.communityName);
			session.community_len = strlen((const char*)session.community);	
		}

		/*
		* Open the session
		*/
		SOCK_STARTUP;
		ss = snmp_open(&session);              

		if (!ss) 
		{
			snmp_sess_perror("ack", &session);
			SOCK_CLEANUP;
			exit(1);
		}

		size_t host_oid_len = MAX_OID_LEN;
		size_t model_oid_len = MAX_OID_LEN;
		size_t serial_oid_len = MAX_OID_LEN;
		size_t manufacturer_oid_len = MAX_OID_LEN;

		oid hostOID[MAX_OID_LEN];
		oid modelOID[MAX_OID_LEN];
		oid serialOID[MAX_OID_LEN];
		oid manufacturerOID[MAX_OID_LEN];

		pdu = snmp_pdu_create(SNMP_MSG_GET);

		//PARSE OIDs
		if (!snmp_parse_oid(OID_KM_HOSTNAME, hostOID, &host_oid_len)) 
		{
			snmp_perror(OID_KM_HOSTNAME);
			SOCK_CLEANUP;
			return RESULT_INTERNAL_ERROR;
		}
		if (!snmp_parse_oid(OID_MODEL, modelOID, &model_oid_len)) 
		{
			snmp_perror(OID_MODEL);
			SOCK_CLEANUP;
			return RESULT_INTERNAL_ERROR;
		}
		if (!snmp_parse_oid(OID_SERIAL_NUM, serialOID, &serial_oid_len)) 
		{
			snmp_perror(OID_SERIAL_NUM);
			SOCK_CLEANUP;
			return RESULT_INTERNAL_ERROR;
		}
		if (!snmp_parse_oid(OID_MANUFACTURER, manufacturerOID, &manufacturer_oid_len)) 
		{
			snmp_perror(OID_MANUFACTURER);
			SOCK_CLEANUP;
			return RESULT_INTERNAL_ERROR;
		}


		snmp_add_null_var(pdu, hostOID, host_oid_len);
		snmp_add_null_var(pdu, modelOID, model_oid_len);
		snmp_add_null_var(pdu, manufacturerOID, manufacturer_oid_len);
		snmp_add_null_var(pdu, serialOID, serial_oid_len);
		/*
		* Send the Request out.
		*/
		status = snmp_synch_response(ss, pdu, &response);

		/*
		* Process the response.
		*/
		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {

			//default values
			tempDiscovery->device.ipAddress = session.peername;
			tempDiscovery->device.printerName = "XXXXXXXXXXXXXXXX";	
			tempDiscovery->device.modelName = "XXXXXXXXXXXXXXXX";	
			tempDiscovery->device.destination = -1;
			tempDiscovery->device.serialNumber = "XXXXXXXXXXXXXXXX";

			int varCounter = 0;
			/* manipuate the information ourselves */
			for(vars = response->variables; vars; vars = vars->next_variable) 
			{
				int varSize = sizeof(vars->val.string);
				if(varCounter == 0)
				{
								
					if(vars->val.string)
					{
						tempDiscovery->device.printerName = NULL;
						tempDiscovery->device.printerName = (char *)malloc(1 + vars->val_len);
						memcpy(tempDiscovery->device.printerName, vars->val.string, vars->val_len);
						tempDiscovery->device.printerName[vars->val_len] = '\0';

						if(tempDiscovery->device.printerName[0] == '\0')
						{
							tempDiscovery->device.printerName = "XXXXXXXXXXXXXXXX";
						}
					}
				}
				else if(varCounter == 1)
				{
					if(vars->val.string)
					{
						tempDiscovery->device.modelName = NULL;
						tempDiscovery->device.modelName = (char *)malloc(1 + vars->val_len);
						memcpy(tempDiscovery->device.modelName, vars->val.string, vars->val_len);
						tempDiscovery->device.modelName[vars->val_len] = '\0';		

						if(tempDiscovery->device.modelName[0] == '\0')
						{
							tempDiscovery->device.modelName = "XXXXXXXXXXXXXXXX";
						}
					}
				}
				else if(varCounter == 2)
				{
					if(vars->val.integer)
					{

						tempDiscovery->device.destination = (int)*vars->val.integer;
					}
				}
				else if(varCounter == 3)
				{
					if(vars->val.string)
					{
						tempDiscovery->device.serialNumber = NULL;
						tempDiscovery->device.serialNumber = (char *)malloc(1 + vars->val_len);
						memcpy(tempDiscovery->device.serialNumber, vars->val.string, vars->val_len);
						tempDiscovery->device.serialNumber[vars->val_len] = '\0';	

						if(tempDiscovery->device.serialNumber[0] == '\0')
						{
							tempDiscovery->device.serialNumber = "XXXXXXXXXXXXXXXX";
						}
					}

				}

				varCounter++;
          
			}//end var loop

			//add device that suppports SNMP; devices that doesnt support SNMP are skipped
			if(varCounter == 4)
			{
				//init next node
				tempDiscovery->nextDevice = (TempDiscovery *) malloc(sizeof(TempDiscovery));
				tempDiscovery = tempDiscovery->nextDevice;
				deviceCounter++;
			}

		}
	
		//close all 63 sessions after opened 
		if(i % NUM_SESSION_TIMEOUT == 0 && i > 0)
		{
			session_list = temp_list;
			for(int x = ((i/NUM_SESSION_TIMEOUT) -1) * NUM_SESSION_TIMEOUT; x < i; x++)
			{
				snmp_close(*session_list);
				//printf("%d - close result: %d\n",x,snmp_close(*session_list));
				session_list++;
			}

			//set temp_list to last address visited from the loop
			temp_list = session_list;
		}


		*session_list = ss;
		session_list++;


		if (response)
			snmp_free_pdu(response);

	}//end for loop


	tempDiscovery->nextDevice = NULL;
	tempDiscovery = headDescovery;

	if(deviceCounter == 0)
	{
		free(tempDiscovery);
		snmp_close_sessions();
		return RESULT_NO_DEVICE_FOUND;
	}

	int listCounter = 1;
	o_Res->numDeviceInfo = deviceCounter;
	o_Res->deviceInfo = (DeviceInfo*)malloc(sizeof(DeviceInfo)*deviceCounter);

	DeviceInfo *deviceInfoHead = o_Res->deviceInfo;

	while(tempDiscovery != NULL)
	{

		DeviceInfo info;
		info = tempDiscovery->device;

		//printer name
		o_Res->deviceInfo->printerName = (char*)malloc(sizeof(char)*strlen(info.printerName) + 1);
		snprintf(o_Res->deviceInfo->printerName, strlen(info.printerName)+1, "%s\0", info.printerName);

		//ipaddress
		o_Res->deviceInfo->ipAddress = (char*)malloc(sizeof(char)*strlen(info.ipAddress) + 1);
		snprintf(o_Res->deviceInfo->ipAddress, strlen(info.ipAddress)+1, "%s\0", info.ipAddress);

		//model name
		o_Res->deviceInfo->modelName = (char*)malloc(sizeof(char)*strlen(info.modelName) + 1);
		snprintf(o_Res->deviceInfo->modelName, strlen(info.modelName)+1, "%s\0", info.modelName);

		//serial number
		o_Res->deviceInfo->serialNumber = (char*)malloc(sizeof(char)*strlen(info.serialNumber) + 1);
		snprintf(o_Res->deviceInfo->serialNumber, strlen(info.serialNumber)+1, "%s\0", info.serialNumber);

		//destination
		o_Res->deviceInfo->destination = info.destination;


		if(tempDiscovery->nextDevice->nextDevice != NULL)
		{
			tempDiscovery = tempDiscovery->nextDevice;
			o_Res->deviceInfo++;
			listCounter++;
		}
		else
		{
			tempDiscovery = NULL;
		}
				
		
	}

	//set response
	o_Res->numDeviceInfo = listCounter;
	o_Res->deviceInfo = deviceInfoHead;

	 /*
     * Clean up:
     *  1) free the response.
     *  2) close the session.
     */

	SOCK_CLEANUP;
	//free list
	free(tempDiscovery);
	snmp_close_sessions();

	return (0);
}