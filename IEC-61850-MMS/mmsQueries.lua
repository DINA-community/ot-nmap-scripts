local mmsEncoder = require "mmsEncoder"

local stdnse = require "stdnse"

_ENV = stdnse.module("mmsQueries", stdnse.seeall)

MMSQueries = {
  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  askfor = function(self, invokeID, domainID, itemIDs)
    local iIdType = type(itemIDs)

    -- make table if we got a single value
    if type(itemIDs) ~= 'table' then
        itemIDs = {itemIDs}
    end

    -- check if all elements are strings
    for _, value in pairs(itemIDs) do
        if type(value) ~= 'string' then
          stdnse.print_debug(1,"All itemIDs must be strings!")
            return nil
        end
    end

    --create structure
    local tab = {}
    for k, v in pairs(itemIDs) do
        local objName = {objectName = {domain_specific = {itemID = v, domainID = domainID}}}
        table.insert(tab, objName)
    end
    local rr = {
        variableAccessSpecification = {listOfVariable = tab},
        specificationWithResult = false
    }

    local structure = {confirmed_RequestPDU = { Read_Request = rr, invokeID = invokeID}}

    -- encode and return
    local encoder = mmsEncoder.MMSEncoder:new()
    local result = encoder:mmsPDU(structure)
    return result
  end,

  nameList = function(self, invokeID, objectScope, continueAfter)
    if invokeID == nil then
      stdnse.debug(1, "no invokeID setting to 1")
      invokeID = 1
    end

    local oC
    local oS
    if objectScope == nil then
      oC = "domain"
      oS = {vmdSpecific = ""}
    else
      oC = "namedVariable"
      oS = {domainSpecific = objectScope}
    end
    local cA = continueAfter 

    
    local cSR = {objectClass = oC, objectScope = oS}
    if cA ~= nil and cA ~= "" then
      cSR["continueAfter"] = cA
    end  
    local structure = {confirmed_RequestPDU = { getNameList = cSR, invokeID = invokeID}}
    return structure
  end  
}

return _ENV;