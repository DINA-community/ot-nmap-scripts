local stdnse = require "stdnse"

_ENV = stdnse.module("mmsDecoder", stdnse.seeall)

function stringToHex(str)
  local hex = ""
  for i = 1, #str do
    hex = hex .. string.format("\\x%02x", string.byte(str, i))
  end
  return hex
end

MMSDecoder = {

  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  unpackmmsFromTPKT = function(self, tpktStr)
    -- unpack TPKT and COTP
    local TPKT_pos = 1
    local COTP_pos = 5
    local COTP_last = false
    local TPKT_ver, TPKT_res, TPKT_len
    local COPT_len, COTP_type, COTP_tpdu
    local OSI_Session = ""

    while not COTP_last do
      TPKT_ver, TPKT_res, TPKT_len = string.unpack("i1c1>i2", tpktStr, TPKT_pos)
      COTP_len, COTP_type, COTP_tpdu = string.unpack("i1c1c1", tpktStr, COTP_pos)
      COTP_last = COTP_tpdu == "\x80"

      OSI_Session = OSI_Session .. string.sub(tpktStr, TPKT_pos + 7, TPKT_pos + TPKT_len - 1)


      if not COTP_last then
        TPKT_pos = TPKT_pos + TPKT_len
        COTP_pos = TPKT_pos + 4
      end
    end    


    local newpos = 5 -- start of ISO 8823
    local type, len, dummy

    -- ISO 8823 OSI
    type, newpos = string.unpack("c1", OSI_Session, newpos)
    if type ~= "\x61" then
      stdnse.debug(1,"not ISO 8823 OSI type is %s: ", stringToHex(type))
      return nil
    end  
    len, newpos = self.decodeLength(OSI_Session, newpos)

    -- presentation-context-identifier
    type, newpos = string.unpack("c1", OSI_Session, newpos)
    if type ~= "\x30" then
      stdnse.debug(1,"not presentation-context-identifier type is %s: ", stringToHex(type))
      return nil
    end  
    len, newpos = self.decodeLength(OSI_Session, newpos)

    -- fully-encoded-data
    type, newpos = string.unpack("c1", OSI_Session, newpos)
    if type ~= "\x02" then
      stdnse.debug(1,"not fully-encoded-data type is %s: ", stringToHex(type))
      return nil
    end  
    len, newpos = self.decodeLength(OSI_Session, newpos)
    dummy, newpos = self.decodeInt(OSI_Session, len, newpos)

    -- single-ASN1-type
    type, newpos = string.unpack("c1", OSI_Session, newpos)
    if type ~= "\xa0" then
      stdnse.debug(1,"not single-ASN1-type type is %s: ", stringToHex(type))
      return nil
    end  
    len, newpos = self.decodeLength(OSI_Session, newpos)



    return string.sub(OSI_Session, newpos)
  end,  

  unpackAndDecode = function(self, tpktStr)
    local mmsStr = self.unpackmmsFromTPKT(self, tpktStr)
    if not mmsStr then
      stdnse.debug(1, "mmsString is nil")
      return nil
    end
    return(self.mmsPDU(self, mmsStr))
  end,  

  mmsPDU = function(self, mmsStr)
    local CHOICE = {}
    CHOICE["\xa0"] = "confirmed_RequestPDU"
    CHOICE["\xa1"] = "confirmed_ResponsePDU"
    CHOICE["\xa8"] = "initiate_RequestPDU"

    local PDUType, PDUlen
    local newpos = 1

    PDUType, newpos = string.unpack("c1", mmsStr, newpos)
    PDUlen, newpos = self.decodeLength(mmsStr, newpos)

    local retval
    if CHOICE[PDUType] then
      retval =  self[CHOICE[PDUType]](self, mmsStr, PDUlen, newpos)
    else
      stdnse.debug(1,"mmsPDU: no option for type %s", stringToHex(PDUType))
      retval, newpos = self.unknown(self, mmsStr, PDUlen, newpos)
      return retval
    end

    local tab = {}
    tab[CHOICE[PDUType]] = retval
    return tab
  end,

  confirmed_RequestPDU = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    -- invokeID
    if type ~= "\x02" then
      stdnse.debug(1,"no invokeID in RequestPDU")
      return nil
    end

    local invokeID
    invokeID, newpos = self.decodeInt(str, len, newpos)

    -- service
    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local CHOICE = {}
    CHOICE["\xa4"] = "Read_Request"

    local confirmedServiceRequest
    if CHOICE[type] then
      confirmedServiceRequest =  self[CHOICE[type]](self, str, len, newpos)
    else
      stdnse.debug(1,"unknown confirmedServiceRequest")
      confirmedServiceRequest = nil
    end

    -- bulid return value
    local tab = {}
    tab["invokeID"] = invokeID
    tab[CHOICE[type]] = confirmedServiceRequest

    local retpos = pos + elen
    return tab, retpos
  end,

  confirmed_ResponsePDU = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    -- invokeID
    if type ~= "\x02" then
      stdnse.debug(1,"no invokeID")
      return nil
    end

    local invokeID
    invokeID, newpos = self.decodeInt(str, len, newpos)

    -- service
    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local CHOICE = {}
    CHOICE["\xa1"] = "getNameList"
    CHOICE["\xa2"] = "identify"
    CHOICE["\xa4"] = "Read_Response"

    local confirmedServiceResponse
    if CHOICE[type] then
      confirmedServiceResponse =  self[CHOICE[type]](self, str, len, newpos)
    else
      stdnse.debug(1,"unknown confirmedServiceResponse")
      confirmedServiceResponse = nil
    end

    -- bulid return value
    local tab = {}
    tab["invokeID"] = invokeID
    tab[CHOICE[type]] = confirmedServiceResponse

    local retpos = pos + elen
    return tab, pos + elen
  end,

  identify = function(self, str, elen, pos)
    local CHOICE = {}
    CHOICE["\x80"] = "vendorName"
    CHOICE["\x81"] = "modelName"
    CHOICE["\x82"] = "revision"

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos

    while (newpos < pos + elen) do
      type, newpos = string.unpack("c1", str, newpos)
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self.decodeStr( str, len, newpos)
      sNum = sNum + 1
      seq[CHOICE[type]] = sValue
    end

    return seq, pos + elen
  end,

  getNameList = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    -- listofidentifier
    if type ~= "\xa0" then
      stdnse.debug(1,"no list of identifier")
      return nil
    end

    local idvlist
    idvlist, newpos = self.listOfIdentifier(self, str, len, newpos)
    local tab = {}
    tab["listOfIdentifier"] = idvlist

    if pos+elen-newpos == 3 then
      type, newpos = string.unpack("c1", str, newpos)
      len, newpos = self.decodeLength(str, newpos)
      local morefollows
      morefollows, newpos = self.decodeBool(str, len, newpos)
      tab["moreFollows"] = morefollows
    else
      tab["moreFollows"] = true
    end

    return tab, pos + elen
  end,

  listOfIdentifier = function(self, str, elen, pos)
    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos

    while (newpos < pos + elen) do
      type, newpos = string.unpack("c1", str, newpos)
      if type ~= "\x1a" then
        stdnse.debug(1,"no identifier type")
      end
      
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self.decodeStr( str, len, newpos)
      sNum = sNum + 1
      table.insert(seq, sValue)
      
    end

    return seq, pos + elen
  end,

  initiate_RequestPDU = function(self, str, elen, pos)
    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos

    while (newpos < pos + elen) do
      type, newpos = string.unpack("c1", str, newpos)
      if CHOICE[type] == nil then
        stdnse.debug(1,"no type for %s", stringToHex(type))
      end
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self[CHOICE[type]](self, str, len, newpos)
      sNum = sNum + 1
      seq[CHOICE[type]] = sValue
    end

    return seq, pos + elen
  end,

  localDetailCalling = function(self, str, elen, pos)
    return self.integer(self, str, elen, pos)
  end,

  proposedMaxServOutstandingCalling = function(self, str, elen, pos)
    return self.integer(self, str, elen, pos)
  end,

  proposedMaxServOutstandingCalled = function(self, str, elen, pos)
    return self.integer(self, str, elen, pos)
  end,

  proposedDataStructureNestingLevel = function(self, str, elen, pos)
    return self.integer(self, str, elen, pos)
  end,

  initRequestDetail = function(self, str, elen, pos)
    local CHOICE = {}
    CHOICE["\x80"] = "proposedVersionNumber"
    CHOICE["\x81"] = "parameterSupportOptions"
    CHOICE["\x82"] = "servicesSupportedCalling"

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos

    while (newpos < pos + elen) do
      type, newpos = string.unpack("c1", str, newpos)
      if CHOICE[type] == nil then
        stdnse.debug(1,"no type for %s", stringToHex(type))
      end
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self[CHOICE[type]](self, str, len, newpos)
      sNum = sNum + 1
      seq[CHOICE[type]] = sValue
    end

    return seq, pos + elen
  end,

  parameterSupportOptions = function(self, str, elen, pos)
    local NAMES = {
      "array support",
      "structure support",
      "named variable support",
      "structure support",
      "alternate access support",
      "unnamed variable support",
      "scattered access support",
      "third party operations support",
      "named variable list support",
      "condition event support"
    }

    return bit_string(self, str, elen, pos, NAMES)
  end,

  proposedVersionNumber = function(self, str, elen, pos)
    return self.integer(self, str, elen, pos)
  end,

  Read_Response = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    -- listOfAccessResult
    local listOfAccessResult
    if type ~= "\xa1" then
      stdnse.debug(1,"no listOfAccessResult")
      return nil, pos + elen
    end

    listOfAccessResult, newpos = self.listOfAccessResult(self, str, len, newpos)

    -- bulid return value
    local tab = {}
    tab["listOfAccessResult"] = listOfAccessResult
    return tab, pos + elen
  end,

  Read_Request = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local specificationWithResult
    if type ~= "\x80" then
      stdnse.debug(1,"no specificationWithResult")
      specificationWithResult = nil
    end
    specificationWithResult, newpos = self.decodeBool(str, len, newpos)

    -- variableAccessSpecification
    local variableAccessSpecification
    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)
    if type ~= "\xa1" then
      stdnse.debug(1,"no variableAccessSpecification")
      return nil, pos + elen
    end

    variableAccessSpecification, newpos = self.variableAccessSpecification(self, str, len, newpos)

    -- bulid return value
    local tab = {}
    tab["specificationWithResult"] = specificationWithResult
    tab["variableAccessSpecification"] = variableAccessSpecification

    local retpos = pos + elen
    return tab, retpos
  end,

  listOfAccessResult = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue

    while (newpos < pos + elen) do
      type, newpos = string.unpack("c1", str, newpos)
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self.accessResult(self, str, len, newpos, type)
      sNum = sNum + 1
      table.insert(seq, sValue)
    end

    return seq, pos + elen
  end,

  accessResult = function(self, str, elen, pos, type)
    local CHOICE = {}
    CHOICE["\xa2"] = "structure"
    CHOICE["\x80"] = "dataAccessError"
    CHOICE["\x83"] = "bool"
    CHOICE["\x84"] = "bit_string"
    CHOICE["\x85"] = "integer"
    CHOICE["\x86"] = "unsigned"
    CHOICE["\x89"] = "octet_string"
    CHOICE["\x8a"] = "string"
    CHOICE["\x8c"] = "binaryTime"
    CHOICE["\x91"] = "utc_Time"

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos

    if elen == 0 and CHOICE[type] == "string" then
      table.insert(seq, "")
    end

    while (newpos < pos + elen) do
      if CHOICE[type] == nil then
        stdnse.debug(1,"no type for", stringToHex(type))
      end
      sValue, newpos = self[CHOICE[type]](self, str, elen, newpos)
      sNum = sNum + 1
      table.insert(seq, sValue)
    end

    return seq, pos + elen
  end,

  dataAccessError = function(self, str, elen, pos)
    local CHOICE = {}
    CHOICE["\x00"] = "object-invalidated"
    CHOICE["\x01"] = "hardware-fault"
    CHOICE["\x02"] = "temporarily-unavalible"
    CHOICE["\x03"] = "object-access-denied"
    CHOICE["\x04"] = "object-undefined"
    CHOICE["\x05"] = "invalid-address"
    CHOICE["\x06"] = "type-unsupported"
    CHOICE["\x07"] = "type-inconsistent"
    CHOICE["\x08"] = "object-attribute-inconsistent"
    CHOICE["\x09"] = "object-access-unsupported"
    CHOICE["\x0a"] = "object-non-existent"
    CHOICE["\x0b"] = "object-value-invalid"

    local num, newpos = string.unpack("c" .. elen, str, pos)
    local retval = "DataAccessError: " .. CHOICE[num]
    return retval, pos + elen
  end,

  structure = function(self, str, elen, pos)
    local CHOICE = {}
    CHOICE["\xa2"] = "structure"
    CHOICE["\x83"] = "bool"
    CHOICE["\x84"] = "bit_string"
    CHOICE["\x85"] = "integer"
    CHOICE["\x86"] = "unsigned"
    CHOICE["\x89"] = "octet_string"
    CHOICE["\x8a"] = "string"
    CHOICE["\x8c"] = "binaryTime"
    CHOICE["\x91"] = "utc_Time"

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue
    local newpos = pos

    while (newpos < pos + elen) do
      type, newpos = string.unpack("c1", str, newpos)
      if CHOICE[type] == nil then
        stdnse.debug(1,"no type for", stringToHex(type))
      end
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self[CHOICE[type]](self, str, len, newpos)
      sNum = sNum + 1
      table.insert(seq, sValue)
    end

    return seq, pos + elen
  end,

  bool = function(self, str, elen, pos)
    return "TODO: bool", pos + elen
  end,

  bit_string = function(self, str, elen, pos, names)
    local padding, newpos = self.decodeInt(str, 1, pos)

    return "TODO: bit_string", pos + elen
  end,

  integer = function(self, str, elen, pos)
    return self.decodeInt(str, elen, pos)
  end,

  unsigned = function(self, str, elen, pos)
    return "TODO: unsigned", pos + elen
  end,

  octet_string = function(self, str, elen, pos)
    return "TODO: string", pos + elen
  end,

  string = function(self, str, elen, pos)
    return string.unpack("c" .. elen, str, pos)
  end,

  binaryTime = function(self, str, elen, pos)
    return "TODO: string", pos + elen
  end,

  utc_Time= function(self, str, elen, pos)
    return "TODO: utc_Time", pos + elen
  end,

  unknown = function(self, str, elen, pos)
    local hex = ""
      for i = 1, #str do
        hex = hex .. string.format("\\x%02x", string.byte(str, i))
      end
      stdnse.debug(1,"Decoder: got an unknown Type")
      stdnse.debug(1,"ebeded String in hex:\n", hex)
      stdnse.debug(1,"length of string given to coder: ", #str)
      stdnse.debug(1,"Current position of coder: ", pos)

    return str
  end,

  variableAccessSpecification = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local listOfVariable
    if type ~= "\xa0" then
      stdnse.debug(1,"no listOfVariable")
      listOfVariable = nil
    end
    listOfVariable, newpos = self.listOfVariable(self, str, len, newpos)

    local tab = {}
    tab["listOfVariable"] = listOfVariable

    return tab, pos + elen
  end,

  listOfVariable = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    local seq = {}
    local sPos = 1
    local sNum = 0
    local sValue

    while (newpos < pos + elen) do
      type, newpos = string.unpack("c1", str, newpos)
      len, newpos = self.decodeLength(str, newpos)
      sValue, newpos = self.variableSpecification(self, str, len, newpos)
      sNum = sNum + 1
      table.insert(seq, sValue)
    end

    return seq, pos + elen
  end,

  variableSpecification = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local CHOICE = {}
    CHOICE["\xa0"] = "objectName"


    local retval
    if CHOICE[type] then
      retval =  self[CHOICE[type]](self, str, len, newpos)
    else
      retval = nil
    end

    local tab = {}

    tab[CHOICE[type]] = retval
    return tab, pos + elen
  end,

  objectName = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local CHOICE = {}
    CHOICE["\xa1"] = "domain_specific"

    local retval
    if CHOICE[type] then
      retval =  self[CHOICE[type]](self, str, len, newpos)
    else
      retval = nil
    end

    local tab = {}
    tab[CHOICE[type]] = retval
    return tab, pos + elen
  end,

  domain_specific = function(self, str, elen, pos)
    local type, len
    local newpos = pos

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    local domainID, itemID
    domainID, newpos = self.decodeStr(str, len, newpos)

    type, newpos = string.unpack("c1", str, newpos)
    len, newpos = self.decodeLength(str, newpos)

    itemID, newpos = self.decodeStr(str, len, newpos)

    local tab = {}
    tab["domainID"] = domainID
    tab["itemID"] = itemID

    return tab, pos + elen
  end,

  decodeLength = function(encStr, pos)
    local elen, newpos = string.unpack('B', encStr, pos)
    if (elen > 128) then
      elen = elen - 128
      local elenCalc = 0
      local elenNext
      for i = 1, elen do
        elenCalc = elenCalc * 256
        elenNext, newpos = string.unpack('B', encStr, newpos)
        elenCalc = elenCalc + elenNext
      end
      elen = elenCalc
    end
    return elen, newpos
  end,

  decodeInt = function(encStr, len, pos)
    if len > 16 then
      return nil, pos
    end
    return string.unpack(">i" .. len, encStr, pos)
  end,

  decodeBool = function( str, elen, pos )
    local val = string.byte(str, pos)
    return val ~= 0, pos + 1
  end,

  decodeStr = function(encStr, elen, pos )
    return string.unpack("c" .. elen, encStr, pos)
  end
}

return _ENV;
