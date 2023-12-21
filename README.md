# Nmap Scripting Engine scripts

In this repository, scripts for NMap based on Nmap Scripting Engine (NSE) are provided.

<!-- TOC depthfrom:2 depthto:3 -->
- [Script for Profinet](#script-for-profinet)
  - [Endpoint Mapper](#endpoint-mapper)
  - [Discovery and Configuration Protocol](#discovery-and-configuration-protocol)
- [IEC 61850 Manufacturing Messaging Specification](#iec-61850-manufacturing-messaging-specification)
- [HART-IP](#hart-ip)
- [Contributors](#contributors)
- [License](#license)
  - [Profinet License](#profinet-license)
  - [IEC 61850 MMS License](#iec-61850-mms-license)
  - [HART-IP License](#hart-ip-license)
<!-- /TOC -->

## Script for Profinet

Two scripts are available for scanning Profinet devices.
 One script sends a Lookup Request through the DCE/RPC Endpoint Mapper (EPM), providing the device name, article number, and firmware version.
The second script sends an Identify Request through Profinet Discovery and basic Configuration Protocol (DCP).

### Endpoint Mapper

Execute the script with the following command:

```text
nmap -sU <target_ip> -p 34964 --script ./dce_rpc_pnio.nse
```

The script has been successfully tested on the following devices:

- Siemens Simatic 1515SP
- Siemens Simatic ET200-1512SP-1PN
- Siemens Simatic 1212C
- Phoneix Contact AXL F BK PN 2701815
- Bosch Rexroth R-IL PN BK DI87 DO4-PAC
- JVL-MOTOR MIS340C12EPH285

### Discovery and Configuration Protocol

There is already a script available for retrieving device information via DCP: [Profinet DCP Scanning Script](https://github.com/Eiwanger/nmapProfinet)
However, this script uses the now obsolete "bin" library.
The script new `pnio_dcp.nse` script in this repository replaces this deprecated library. The script was further changed by intel of Nmap
.

Execute the script with the following command:

```string
nmap --script ./pn_discovery.nse
```

This script was successfully tested within the _POC_ (BSI Project 369).

[(back to top)](#nmap-scripting-engine-scripts)

## IEC 61850 Manufacturing Messaging Specification

The nmap script for actively requesting device information from IEC 61850 Manufacturing Messaging Specification
 (MMS) servers is based on an available script that has been extended with additional read requests.
The script used is available online: [IEC 61850 MMS Identify Script](https://github.com/atimorin/scada-tools/blob/master/mms-identify.nse).

The existing Identify request was further used and the decoding of the response was optimized.
In addition, the script `iec61850_mms.nse` in this repository actively queries and outputs attributes of the IEC 61850 MMS data model via a Read request.
The following six attributes of the base nodes of the data model are queried, which basically contain device information and are mapped to the output parameters as follows:

- productFamily: `LLN0$DC$NamPlt$d`
- vendorName: `LLN0$DC$NamPlt$vendor`
- serialNumber: `LPHD1$DC$PhyNam$serNum`
- modelNumber: `LPHD1$DC$PhyNam$model`
- firmwareVersion: `LLN0$DC$NamPlt$swRev`
- configuration: `LLN0$DC$NamPlt$configRev`

The output is extended by the detected information from the Identify request and marked with the name suffix `_identfy` in the output.

The requests are created via a separately written encoder, which is based on the ASN.1 notation and assembled via an additional Query script.
The responses of the devices are evaluated via a separate decoding script and assigned to the output attributes.
The repository for the MMS requests thus contains the following scripts:

- iec61850_mms.nse
- mmsDecoder.lua
- mmsEncoder.lua
- mmsQueries.lua

Execute the nse script with the following command:

```text
nmap --script iec61850_mms.nse -p 102 <target>
```

When interpreting the data, it is important to note that the information obtained is qualitatively very dependent on the user or manufacturer inputs in the data model.
The reliability of the information is therefore partly questionable, as the attributes in the data model can be set and changed at will.
Accordingly, the documented test devices showed that the information obtained is sometimes difficult to interpret.
According to the manufacturers' care, information from the communication stack used is sometimes still stored in the attributes instead of the manufacturer of the device, or the data model is incomplete or without stored information.
If attributes of the data model do not exist, the ASN.1-based error code `DataAccessError: object-non-existent` is displayed in the output, and `<EMPTY_STRING>` is added for a missing entry of an existing attribute.

In cases that occurred during the tests, it was found that some components react to the read request of the six attributes with fewer return values if the attributes are not present.
For this case, an alternative path was added to the nse script so that the six attributes are queried via individual requests.
A hint is given as print output.

This script was successfully tested within Substation Demonstrator at Frauhofer IOSB-AST, Ilmenau, on the following devices:

- ABB RED670
- ABB REX640
- a-Eberle REG-D(A)
- Schneider Electric Power Logic PM8000
- WAGO 750-880

[(back to top)](#nmap-scripting-engine-scripts)

## HART-IP

In this repository, the script scans HART-IP based devices.
The NSE script is used to send a HART-IP packet to a HART device that has TCP 5094 open.
The script establishes Session with HART device, then Read Unique Identifier, Read Long Tag and Read Sub-Device Identity Summary packets are sent to parse the required HART device information.

Execute the script with the following command:

```text
nmap <target_ip> -p 5094 --script ./hartip-info.nse
```

This script has been successfully tested on the HART-IP Demonstrator at Frauhofer IOSB, Karlsruhe.

[(back to top)](#nmap-scripting-engine-scripts)

## Contributors

The IEC 61850 MMS script was intensivly tested by Christoph Rheinberger, Burak Tahincioglu, and André Komes from [OMICRON](https://omicroncybersecurity.com).\
The Profinet, HART-IP and IEC 61850 MMS should satisfy the coding guidelines of NMAP thanks to feedback from [NMAP](https://nmap.org/).

[(back to top)](#nmap-scripting-engine-scripts)

## License

Since license is not the same, every script is described separately.

### Profinet License

The script pn_discovery.nse in this repository is an adaptation from [Profinet DCP Scanning Script](https://github.com/Eiwanger/nmapProfinet), replacing the deprecated library and revise the script by Nmap intel. The original script was published under the GPL-3 license. However, the author Stefan Eiwanger agreed that the revised script is published under [BSD-2-Clause Plus Patent License](https://spdx.org/licenses/BSD-2-Clause-Patent.html).

### IEC 61850 MMS License

The script follows Nmap Public Source License (NPSL), which is based on the GNU GPLv2. For further details, please refer <https://nmap.org/book/man-legal.html>. The script bases on the [mms-identify.nse](https://github.com/atimorin/scada-tools/blob/master/mms-identify.nse) script by Aleksandr Timorin which is also based on the Nmap Public Source License (NPSL).

### HART-IP License

The script follows Nmap Public Source License (NPSL), which is based on the GNU GPLv2. For further details, please refer <https://nmap.org/book/man-legal.html>.

[(back to top)](#nmap-scripting-engine-scripts)
