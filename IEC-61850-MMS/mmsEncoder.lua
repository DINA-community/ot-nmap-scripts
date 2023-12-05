local stdnse = require "stdnse"

_ENV = stdnse.module("mmsEncoder", stdnse.seeall)

MMSEncoder = {

    new = function(self,o)
      o = o or {}
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    packmmsInTPKT = function(self, mmsStr)
      local sendstr = mmsStr
      sendstr = "\xa0"..self.encodeLength(#sendstr)..sendstr
      sendstr = "\x02\x01\x03"..sendstr
      sendstr = "\x30"..self.encodeLength(#sendstr)..sendstr
      sendstr = "\x61"..self.encodeLength(#sendstr)..sendstr --ISO8823
      sendstr = "\x01\x00\x01\x00"..sendstr                  --ISO8327 2x
      sendstr = "\x02\xf0\x80"..sendstr                      --ISO8073
      local final_len = #sendstr+4
      sendstr = "\x03\x00"..string.char(math.floor(final_len / 256), final_len % 256)..sendstr
      return sendstr
    end,  

    encodeAndPack = function(self, mmsTab)
      local mmsStr = self.mmsPDU(self, mmsTab)
      return self.packmmsInTPKT(self, mmsStr)
    end,  

    mmsPDU = function(self, message)
      local CHOICE = {}
      CHOICE["confirmed_RequestPDU"] = "\xa0"
      CHOICE["confirmed_ResponsePDU"] = "\xa1"

      local type = type(message)

      if type ~= 'table' then
        stdnse.print_debug(1,"mmsPDU: must be a table")
        return nil
      end

      if self.tabElementCount(message) ~= 1 then
        stdnse.print_debug(1,"mmsPDU: table muss have exactly one element")
        return nil
      end

      local key, val = next(message)
      if not CHOICE[key] then
        stdnse.print_debug(1,"mmsPDU: no PDU type ", key)
        return nil
      end

      local pdustr = self[key](self, message[key])
      local retstr = CHOICE[key].. self.encodeLength(#pdustr) .. pdustr
      return retstr

    end,

    confirmed_RequestPDU = function(self, message)
      local CHOICE = {}
      CHOICE["Read_Request"] = "\xa4"
      CHOICE["getNameList"] = "\xa1"

      if type(message) ~= 'table' then
        stdnse.print_debug(1,"confirmed_RequestPDU: must be a table")
        return ""
      end

      local tablen = self.tabElementCount(message)
      if tablen < 2 or tablen > 4 then
        stdnse.print_debug(1,"confirmed_RequestPDU: table must have between 2 and 4 elements")
        return ""
      end

      if not message["invokeID"] then
        stdnse.print_debug(1,"confirmed_RequestPDU: message must contain invokeID ")
        return ""
      end

      local confServReqKey = self.tabContainsKeyOfTab(message, CHOICE)
      if not confServReqKey then
        stdnse.print_debug(1,"confirmed_RequestPDU: message must contain confirmedServiceRequest")
        return ""
      end

      local invokeID = self.encodeInt(message["invokeID"])
      local retstr = "\x02" .. self.encodeLength(#invokeID) .. invokeID

      local confirmedServiceRequest = self[confServReqKey](self, message[confServReqKey])
      retstr = retstr .. CHOICE[confServReqKey] .. self.encodeLength(#confirmedServiceRequest) .. confirmedServiceRequest

      return retstr
    end,

    getNameList = function(self, message)
      if type(message) ~= 'table' then
        stdnse.debug(1,"getNameList: must be a table")
        return ""
      end

      if message["objectClass"] == nil then
        stdnse.debug(1,"getNameList: message must contain objectClass")
        return ""
      end

      local oC = self.objectClass(self, message["objectClass"])
      local retstr = "\xa0" .. self.encodeLength(#oC) .. oC

      if message["objectScope"] == nil then
        stdnse.debug(1,"getNameList: message must contain objectScope")
        return ""
      end

      local oS = self.objectScope(self, message["objectScope"])
      retstr = retstr .. "\xa1" .. self.encodeLength(#oS) .. oS

      if message["continueAfter"] ~= nil then
        local continueAfter = self.encodeStr(message["continueAfter"])
        retstr = retstr .. "\x82" .. self.encodeLength(#continueAfter) .. continueAfter
      end

      return retstr
    end,

    objectClass = function(self, message)
      if type(message) ~= 'string' then
        stdnse.debug(1,"objectClass: must be a String")
        return ""
      end

      CHOICE = {}
      CHOICE["namedVariable"] = 0
      CHOICE["domain"] = 9

      if CHOICE[message] == nil then
        stdnse.debug(1,"objectClass: message not valid")
        return ""
      end
      local res = self.encodeInt(CHOICE[message])
      local retstr = "\x80" .. self.encodeLength(#res) .. res

      return retstr
    end,

    objectScope = function(self, message)
      if type(message) ~= 'table' then
        stdnse.debug(1,"objectScope: must be a table")
        return ""
      end

      local tablen = self.tabElementCount(message)
      if tablen ~= 1 then
        stdnse.print_debug(1,"objectScope: table must have 1 element")
        return ""
      end

      CHOICE = {}
      CHOICE["vmdSpecific"] = "\x80"
      CHOICE["domainSpecific"] = "\x81"

      local Key = self.tabContainsKeyOfTab(message, CHOICE)
      if not Key then
        stdnse.print_debug(1,"objectScope: message must contain valid element")
        return ""
      end

      local res = self[Key](self, message[Key])
      local retstr = CHOICE[Key] .. self.encodeLength(#res) .. res

      return retstr
    end,

    domainSpecific = function(self, message)
      return self.encodeStr(message)
    end,

    vmdSpecific = function(self, message)
      return ""
    end,

    Read_Request = function(self, message)
      local type = type(message)

      if type ~= 'table' then
        stdnse.print_debug(1,"Read_Request: must be a table")
        return ""
      end

      local tablen = self.tabElementCount(message)
      if tablen ~= 2  then
        stdnse.print_debug(1,"Read_Request: table must have 2 elements")
        return ""
      end

      if message["specificationWithResult"] == nil then
        stdnse.print_debug(1,"Read_Request: message must contain specificationWithResult")
        return ""
      end

      if message["variableAccessSpecification"] == nil then
        stdnse.print_debug(1,"Read_Request: message must contain variableAccessSpecification")
        return ""
      end

      local specificationWithResult = self.encodeBool(message["specificationWithResult"])
      local retstr = "\x80" .. self.encodeLength(#specificationWithResult) .. specificationWithResult

      local variableAccessSpecification = self.variableAccessSpecification(self, message["variableAccessSpecification"] )
      retstr = retstr .. "\xa1" .. self.encodeLength(#variableAccessSpecification) .. variableAccessSpecification

      return retstr
    end,

    variableAccessSpecification = function(self, message)
      local type = type(message)

      if type ~= 'table' then
        stdnse.print_debug(1,"variableAccessSpecification: must be a table")
        return ""
      end

      local tablen = self.tabElementCount(message)
      if tablen ~= 1  then
        stdnse.print_debug(1,"variableAccessSpecification: table must have 1 element")
        return ""
      end

      if message["listOfVariable"] == nil then
        stdnse.print_debug(1,"variableAccessSpecification: message must contain listOfVariable")
        return ""
      end
      local listOfVariable = self.listOfVariable(self, message["listOfVariable"])
      local retstr = "\xa0" .. self.encodeLength(#listOfVariable) .. listOfVariable

      return retstr
    end,

    listOfVariable = function(self, message)
      local type = type(message)

      if type ~= 'table' then
        stdnse.print_debug(1,"listOfVariable: must be a table")
        return ""
      end

      local retstr = ""
      local value
      for k, v in pairs(message) do
        value = self.variableSpecification(self, v)
        retstr = retstr .. "\x30".. self.encodeLength(#value) .. value
      end

      return retstr
    end,

    variableSpecification = function (self, message)
      local CHOICE = {}
      CHOICE["objectName"] = "\xa0"

      local type = type(message)

      if type ~= 'table' then
        stdnse.print_debug(1,"variableSpecification: must be a table")
        return ""
      end

      local tablen = self.tabElementCount(message)
      if tablen ~= 1  then
        stdnse.print_debug(1,"variableSpecification: table must have 1 element")
        return ""
      end

      local varSpec = self.tabContainsKeyOfTab(message, CHOICE)
      if not varSpec then
        stdnse.print_debug(1,"variableSpecification: message must contain variableSpecification")
        return ""
      end

      local specstr = self[varSpec](self, message[varSpec])
      local retstr = CHOICE[varSpec] .. self.encodeLength(#specstr) .. specstr

      return retstr
    end,

    objectName = function (self, message)
      local CHOICE = {}
      CHOICE["vmd_specific"] = "\xa0"
      CHOICE["domain_specific"] = "\xa1"
      CHOICE["aa_specific"] = "\xa2"

      local type = type(message)

      if type ~= 'table' then
        stdnse.print_debug(1,"objectName: must be a table")
        return ""
      end

      local tablen = self.tabElementCount(message)
      if tablen ~= 1  then
        stdnse.print_debug(1,"objectName: table must have 1 element")
        return ""
      end

      local key = self.tabContainsKeyOfTab(message, CHOICE)
      if not key then
        stdnse.print_debug(1,"objectName: must contain objectName")
        return ""
      end

      local value = self[key](self, message[key])
      local retstr = CHOICE[key] .. self.encodeLength(#value) .. value
      return retstr
    end,

    domain_specific = function(self, message)
      local type = type(message)

      if type ~= 'table' then
        stdnse.print_debug(1,"domain_specific: must be a table")
        return ""
      end

      local tablen = self.tabElementCount(message)
      if tablen ~= 2  then
        stdnse.print_debug(1,"objectName: table must have 2 elements")
        return ""
      end

      if message["domainID"] == nil then
        stdnse.print_debug(1,"domain_specific: message must contain domainID")
        return ""
      end

      if message["itemID"] == nil then
        stdnse.print_debug(1,"domain_specific: message must contain itemID")
        return ""
      end

      local retstr = ""
      local valstr

      valstr = self.encodeStr(message["domainID"])
      retstr = retstr .. "\x1a" .. self.encodeLength(#valstr) .. valstr

      valstr = self.encodeStr(message["itemID"])
      retstr = retstr .. "\x1a" .. self.encodeLength(#valstr) .. valstr

      return retstr
    end,

    tabContainsKeyOfTab = function(tab, source)
      local retval = nil
      for key, val in pairs(source) do
        if tab[key] then
          retval = key
          break
        end
      end
      return retval
    end,

    tabElementCount = function(tab)
      local count = 0
      for _ in pairs(tab) do count = count + 1 end
      return count
    end,

    encodeLength = function(len)
      if len < 128 then
        return string.char(len)
      else
        local parts = {}

        while len > 0 do
          parts[#parts + 1] = string.char(len % 256)
          len = len >> 8
        end

        assert(#parts < 128)
        return string.char(#parts + 0x80) .. string.reverse(table.concat(parts))
      end
    end,

    encodeInt = function(val)
      local lsb = 0
      if val > 0 then
        local valStr = ""
        while (val > 0) do
          lsb = math.fmod(val, 256)
          valStr = valStr .. string.pack("B", lsb)
          val = math.floor(val/256)
        end
        if lsb > 127 then -- two's complement collision
          valStr = valStr .. "\0"
        end

        return string.reverse(valStr)
      elseif val < 0 then
        local i = 1
        local tcval = val + 256 -- two's complement
        while tcval <= 127 do
          tcval = tcval + 256^i * 255
          i = i+1
        end
        local valStr = ""
        while (tcval > 0) do
          lsb = math.fmod(tcval, 256)
          valStr = valStr .. string.pack("B", lsb)
          tcval = math.floor(tcval/256)
        end
        return string.reverse(valStr)
      else -- val == 0
        return '\0'
      end
    end,

    encodeBool = function(val)
      if val then
        return '\xFF'
      else
        return '\x00'
      end
    end,

    encodeStr = function(str)
      return str
    end
}

return _ENV;