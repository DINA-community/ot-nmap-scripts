local mmsDecoder = require "mmsDecoder"
local mmsEncoder = require "mmsEncoder"
local mmsQueries = require "mmsQueries"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
    Active Scanning of IEC 61850-8-1 MMS Server. Send Initate-Request, Identify-Request and Read-Request to LN0 and LPHD.
    Output contain following attributes:
    
    modelName_identify:   Identify-Response attribute model_name
    productFamily:        Read-Response attribute 'LLN0$DC$NamPlt$d'
    vendorName:           Read-Response attribute 'LPHD$DC$PhyNam$vendor' (old: 'LLN0$DC$NamPlt$vendor')
    vendorName_identify:  Identify-Response attribute vendor_name
    serialNumber:         Read-Response attribute 'LPHD$DC$PhyNam$serNum'
    modelNumber:          Read-Response attribute 'LPHD$DC$PhyNam$model'
    modelNumber_identify: Identify-Response attribute revision
    firmwareVersion:      Read-Response attribute 'LPHD$DC$PhyNam$swRev' (old: 'LLN0$DC$NamPlt$swRev')
    configuration:        Read-Response attribute 'LLN0$DC$NamPlt$configRev'
]]

---
-- @usage
-- nmap --script iec61850_mms.nse -p 102 <target>
--

-- @output
-- 102/tcp open  iso-tsap
--|	iec61850_mms.nse:
--|   modelName_identify  : MMS-LITE-80X-001
--|   productFamily       : High End Meter
--|   vendorName          : Schneider Electric
--|   vendorName_identify : SISCO
--|   serialNumber        : ME-1810A424-02
--|   modelNumber         : 8000
--|   modelNumber_identify: 6.0000.3
--|   firmwareVersion     : 001.004.003
--|_  configuration       : 2022-08-19 08:27:20

-- @args
--
---

categories = {"discovery", "intrusive", "version"}
author = "DINa community"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

-- Helpers
function replaceEmptyStrings(tbl)
  for key, value in pairs(tbl) do
    if type(value) == "table" then
      replaceEmptyStrings(value)  
    elseif type(value) == "string" and value == "" then
      tbl[key] = "<EMPTY_STRING>" 
    end
  end
end

-- Rules
portrule = shortport.portnumber(102, "tcp")

-- Actions
action = function(host, port)
  timeout = 500

  local status, recv
  local output = {}
  local socket = nmap.new_socket()

  local decoder = mmsDecoder.MMSDecoder:new()
  local encoder = mmsEncoder.MMSEncoder:new()
  local query = mmsQueries.MMSQueries:new()

  socket:set_timeout(timeout)

  status, recv = socket:connect(host, port, "tcp")
  if not status then
    return nil
  end

  local CR_TPDU = "\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x00\x00\xc2\x02\x00\x01\xc0\x01\x0a"
  status = socket:send( CR_TPDU )
  if not status then
    return nil
  end
  status, recv = socket:receive_bytes(1024)
  stdnse.print_debug(1, "cr_tpdu recv: %s", stdnse.tohex(recv) )
  
  local MMS_INITIATE = "\x03\x00\x00\xd3\x02\xf0\x80\x0d\xca\x05\x06\x13\x01\x00\x16\x01\x02\x14\x02\x00\x02\x33\x02" ..
    "\x00\x01\x34\x02\x00\x01\xc1\xb4\x31\x81\xb1\xa0\x03\x80\x01\x01" ..
    "\xa2\x81\xa9\x81\x04\x00\x00\x00\x01\x82\x04\x00\x00\x00\x01\xa4" ..
    "\x23\x30\x0f\x02\x01\x01\x06\x04\x52\x01\x00\x01\x30\x04\x06\x02" ..
    "\x51\x01\x30\x10\x02\x01\x03\x06\x05\x28\xca\x22\x02\x01\x30\x04" ..
    "\x06\x02\x51\x01\x61\x76\x30\x74\x02\x01\x01\xa0\x6f\x60\x6d\xa1" ..
    "\x07\x06\x05\x28\xca\x22\x02\x03\xa2\x07\x06\x05\x29\x01\x87\x67" ..
    "\x01\xa3\x03\x02\x01\x0c\xa4\x03\x02\x01\x00\xa5\x03\x02\x01\x00" ..
    "\xa6\x06\x06\x04\x29\x01\x87\x67\xa7\x03\x02\x01\x0c\xa8\x03\x02" ..
    "\x01\x00\xa9\x03\x02\x01\x00\xbe\x33\x28\x31\x06\x02\x51\x01\x02" ..
    "\x01\x03\xa0\x28\xa8\x26\x80\x03\x00\xfd\xe8\x81\x01\x0a\x82\x01" ..
    "\x0a\x83\x01\x05\xa4\x16\x80\x01\x01\x81\x03\x05\xf1\x00\x82\x0c" ..
    "\x03\xee\x1c\x00\x00\x00\x00\x00\x00\x00\xed\x18"
  
  status = socket:send( MMS_INITIATE )
  if not status then
    return nil
  end
  status, recv = socket:receive_bytes(1024)
  stdnse.print_debug(1, "mms_initiate recv: %s", stdnse.tohex(recv) )

  local MMS_IDENTIFY = "\x03\x00\x00\x1b\x02\xf0\x80\x01\x00\x01\x00\x61\x0e\x30\x0c\x02" .. 
    "\x01\x03\xa0\x07\xa0\x05\x02\x01\x01\x82\x00"  

  status = socket:send( MMS_IDENTIFY )
  if not status then
    return nil
  end
  status, recv = socket:receive_bytes(2048)
  stdnse.print_debug(1, "mms_identify recv: %s", stdnse.tohex(recv) )

  if ( status and recv ) then
    local mmsIdentstruct = decoder:unpackAndDecode(recv)
    replaceEmptyStrings(mmsIdentstruct)

    vendor_name = mmsIdentstruct.confirmed_ResponsePDU.identify.vendorName
    model_name = mmsIdentstruct.confirmed_ResponsePDU.identify.modelName
    revision = mmsIdentstruct.confirmed_ResponsePDU.identify.revision

    stdnse.print_debug(1, "vendor_name: %s", vendor_name )
    stdnse.print_debug(1, "model_name: %s", model_name )
    stdnse.print_debug(1, "revision: %s", revision )
  else
    return nil
  end    

  local MMS_GETNAMELIST_vmdspecific = "\x03\x00\x00\x24\x02\xf0\x80\x01\x00\x01\x00\x61\x17\x30\x15\x02"..
    "\x01\x03\xa0\x10\xa0\x0e\x02\x01\x01\xa1\x09\xa0\x03\x80\x01\x09"..
    "\xa1\x02\x80\x00"

  status = socket:send( MMS_GETNAMELIST_vmdspecific )
  if not status then
    return nil
  end

  status, recv = socket:receive_bytes(1024)
  stdnse.print_debug(1, "mms_getnamelist recv: %s", stdnse.tohex(recv) )

  if ( status and recv ) then
    local mmsNLTab = decoder:unpackAndDecode(recv)
    replaceEmptyStrings(mmsNLTab)
    vmd_name = mmsNLTab.confirmed_ResponsePDU.getNameList.listOfIdentifier[1]
    stdnse.print_debug(1, "vmd_name: %s", vmd_name )
  else
    return nil
  end    

  --local attributes = {'LLN0$DC$NamPlt$d', 'LLN0$DC$NamPlt$vendor', 'LPHD1$DC$PhyNam$serNum', 'LPHD1$DC$PhyNam$model', 'LLN0$DC$NamPlt$swRev', 'LLN0$DC$NamPlt$configRev'}
  local attributes = {'LLN0$DC$NamPlt$d', 'LPHD1$DC$PhyNam$vendor', 'LPHD1$DC$PhyNam$serNum', 'LPHD1$DC$PhyNam$model', 'LPHD1$DC$PhyNam$swRev', 'LLN0$DC$NamPlt$configRev'}

  local domain = vmd_name
  local invokeID = 54

  local mmsRequest = query:askfor(invokeID, domain, attributes)
  local MMS_READREQUEST = encoder:packmmsInTPKT(mmsRequest)

  status = socket:send( MMS_READREQUEST )
  if not status then
    return nil
  end

  status, recv = socket:receive_bytes(1024)
  stdnse.print_debug(1, "mms_read recv: %s", stdnse.tohex(recv) )
  
  if ( status and recv ) then 
    mmsstruct = decoder:unpackAndDecode(recv)
    replaceEmptyStrings(mmsstruct)
  else
    return nil
  end

  local attNum = #attributes
  local rplNum = #mmsstruct.confirmed_ResponsePDU.Read_Response.listOfAccessResult
  if rplNum == attNum then
    mmsoutput = mmsstruct.confirmed_ResponsePDU.Read_Response.listOfAccessResult
  else
    
    print(string.format("\nReply from Host %s at port %d was not compliant with standard", host["ip"], port["number"]))
    print(string.format("Request for %d attributes has been replied with %d values", attNum, rplNum))
    print("attempting individual queries...\n")
    mmsoutput = {}
    for i = 1, attNum do
      local mmsRequest = query:askfor(i, domain, attributes[i])
      local MMS_READREQUEST = encoder:packmmsInTPKT(mmsRequest)

      status = socket:send( MMS_READREQUEST )
      if not status then
        return nil
      end

      status, recv = socket:receive_bytes(1024)
      stdnse.print_debug(1, "mms_read recv: %s", stdnse.tohex(recv) )
      
      if ( status and recv ) then 
        local mmsstruct = decoder:unpackAndDecode(recv)
        replaceEmptyStrings(mmsstruct)
        table.insert(mmsoutput, {})
        mmsoutput[i][1] = mmsstruct.confirmed_ResponsePDU.Read_Response.listOfAccessResult[1][1]
      else
        return nil
      end
    end
  end 


  -- create table for output
  local output = stdnse.output_table()
  output["modelName_identify  "] = model_name
  output["productFamily       "] = mmsoutput[1][1]
  output["vendorName          "] = mmsoutput[2][1]
  output["vendorName_identify "] = vendor_name
  output["serialNumber        "] = mmsoutput[3][1]
  output["modelNumber         "] = mmsoutput[4][1]
  output["modelNumber_identify"] = revision
  output["firmwareVersion     "] = mmsoutput[5][1]
  output["configuration       "] = mmsoutput[6][1]
  return output
  
end