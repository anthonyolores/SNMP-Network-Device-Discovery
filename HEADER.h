
/* ----------- OIDs --------------------------*/
//SPECIFIC TO KYOCERA DEVICES
#define OID_MODEL               "1.3.6.1.4.1.1347.43.5.1.1.1.1"
#define OID_SERIAL_NUM			"1.3.6.1.2.1.43.5.1.1.17.1"
#define OID_LOCATION            "1.3.6.1.2.1.1.6.0"
#define OID_KM_HOSTNAME         "1.3.6.1.4.1.1347.40.10.1.1.5.1"
#define OID_MANUFACTURER		"1.3.6.1.4.1.1347.42.5.1.1.29.1"

/* Return code */
typedef enum
{
	RESULT_OK								= 0,
	RESULT_NO_DEVICE_FOUND					= 1,
	RESULT_INVALID_IP_ADDRESS				= 2,
	RESULT_INVALID_SUBNET_MASK				= 3,
	RESULT_INVALID_SNMP_VERSION				= 4,
	RESULT_INVALID_SNMPV3_USERNAME			= 5,
	RESULT_INVALID_SNMPV3_PASSWORD			= 6,
	RESULT_INVALID_SNMPV3_AUTH				= 7,
	RESULT_INVALID_SNMPV3_PRIV				= 9,
	RESULT_INVALID_SNMPV2_1_COMM_NAME		= 10,
	RESULT_INTERNAL_ERROR					= 11,
	RESULT_INVALID_HANDLE					= 12,
	RESULT_SNMP_VERSION_NOT_SET				= 13
} RESULT;


/* ----------- SNMPv3 --------------------------*/

//MD5
#define USM_AUTH_PROTO_MD5_LEN 10
static oid usmHMACMD5AuthProtocol[]  = { 1,3,6,1,6,3,10,1,1,2 };
//SHA1
#define USM_AUTH_PROTO_SHA_LEN 10
static oid usmHMACSHA1AuthProtocol[] = { 1,3,6,1,6,3,10,1,1,3 };
//DES
#define USM_PRIV_PROTO_DES_LEN 10
static oid usmDESPrivProtocol[]      = { 1,3,6,1,6,3,10,1,2,2 };
//AES
#define USM_PRIV_PROTO_AES_LEN 10
static oid usmAESPrivProtocol[] = { 1, 3, 6, 1, 6, 3, 10, 1, 2, 4 };

#define NUM_SESSION_TIMEOUT 63


typedef void* HANDLE;	
typedef void* DV_HANDLE;	

#define HOST_LEN 16
typedef enum
{
	CLASS_A = 1,
	CLASS_B = 2,
	CLASS_C = 3,
	CLASS_D = 4
}SUBNET_CLASS;


typedef enum
{
	KMSNMP_VERSION_1_2 = 0,
    KMSNMP_VERSION_3 = 1
} VERSION;

typedef enum
{
	SNMPV3_SHA1 = 0,
    SNMPV3_MD5,
} SNMPV3_AUTH;

typedef enum
{
	SNMPV3_DES = 0,
    SNMPV3_AES,
} SNMPV3_PRIV;

typedef struct SNMPV3Info
{
	SNMPV3_AUTH auth;
	SNMPV3_PRIV priv;
	char *username;
	char *password;
};

typedef struct SNMPV1_2Info
{
	char * communityName;
};

/* Structures */
typedef struct
{
	char * printerName;			/* Printer name (host name) */
	char * ipAddress;			/* IP address (IPv4 and IPv6) */
	char * modelName;			/* Model name */
	char * serialNumber;		/* Serial number */
	int destination;			/* Reserved value */
} DeviceInfo;

typedef struct TempDiscovery
{
	DeviceInfo device;
	struct TempDiscovery *nextDevice;
};

typedef struct DiscoverDeviceReq
{
	VERSION snmpVersion;
	SNMPV3Info snmpv3Info;
	SNMPV1_2Info snmpv21Info;
	char * subnetMask;
	char * ipAddress;
};

typedef struct
{
	int numDeviceInfo;				/* Number of devices found */
	DeviceInfo* deviceInfo;	/* Device information */
} DiscoverDeviceRes;


DllExport 
HANDLE Init();

DllExport
int DiscoverDevice(HANDLE i_Handle, DiscoverDeviceReq i_Req, DiscoverDeviceRes* o_Res);

DllExport
void StopDiscovery(HANDLE i_Handle);

DllExport 
void Exit(HANDLE i_Handler);

