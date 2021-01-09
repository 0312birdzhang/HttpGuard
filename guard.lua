local Guard = {}

--debug日志
function Guard:debug(data,ip,reqUri)
  if _Conf.debug then
    local date = os.date("%Y-%m-%d")
    local filename = _Conf.logPath.."/debug-"..date..".log"
    local file = io.open(filename,"a+")
    file:write(os.date('%Y-%m-%d %H:%M:%S').." [DEBUG] "..data.." IP "..ip.." GET "..reqUri.."\n")
    file:close()
  end
end

--攻击日志
function Guard:log(data)
  local date = os.date("%Y-%m-%d")
  local filename = _Conf.logPath.."/attack-"..date..".log"
  local file = io.open(filename,"a+")
  file:write(os.date('%Y-%m-%d %H:%M:%S').." [WARNING] "..data.."\n")
  file:close()
end

--获取真实ip
function Guard:getRealIp(remoteIp,headers)
  if _Conf.realIpFromHeaderIsOn then
    readIp = headers[_Conf.realIpFromHeader.header]
    if readIp then
      self:debug("[getRealIp] realIpFromHeader is on.return ip "..readIp,remoteIp,"")
      return headers[_Conf.realIpFromHeader.header]
    else
      return remoteIp
    end
  else
    return remoteIp
  end
end

--白名单模块
function Guard:ipInWhiteList(ip)
  if _Conf.whiteIpModulesIsOn then
    -- self:debug("[ipInWhiteList] whiteIpModules is on. ",ip,"")
    if _Conf.whiteIpList ~= nil then
      for _,rule in pairs(_Conf.whiteIpList) do
        rule = string.gsub(rule, "*","")
        if rule ~= "" and string.sub(ip,1,string.len(rule)) == rule then
          self:debug("[ipInWhiteList] ip "..ip.. " match white list ","","")
          return true
        end
      end
    end
    return false
  end
end

-- 黑名单模块
function Guard:ipInFileBlackList(ip)
  if _Conf.fileBlackIpModulesIsOn then
    -- self:debug("[IpInFileBlackList] fileBlackIpModules is on. ",ip,"")
    if _Conf.fileBlackIpList ~= nil then
      for _,rule in pairs(_Conf.fileBlackIpList) do
        rule = string.gsub(rule, "*","")
        if rule ~= "" and string.sub(ip,1,string.len(rule)) == rule then
          self:debug("[ipInFileBlackList] ip "..ip.. " match black list ","","")
          return true
        end
      end
    end
    return false
  end
end



--收集不在白名单中的蜘蛛ip
function Guard:collectSpiderIp(ip, headers)
  local spiderPattern = "baiduspider|360spider|sogou web spider|sogou inst spider|mediapartners|adsbot-google|googlebot"
  local userAgent = headers["user-agent"]
  if userAgent then
    userAgent = string.lower(headers["user-agent"])
  end
  if userAgent and ngx.re.match(userAgent, spiderPattern) then
    local filename = _Conf.logPath.."/spider_ip.log"
    local file = io.open(filename, "a+")
    file:write(os.date('%Y-%m-%d %H:%M:%S').." IP "..ip.." UA "..userAgent.."\n")
    file:close()
  end
end

-- 内存黑名单模块
function Guard:blackListModules(domain,ip, reqUri, headers,address)
  local uriMd5 = ngx.md5(address)
  local blackKey = domain..ip..uriMd5.."black"
  if _Conf.dict:get(blackKey) then --判断ip是否存在黑名单字典
    self:debug("[IpblackListModules] ip "..ip.." in blacklist",ip,reqUri)
    self:takeAction(domain,ip,reqUri) --存在则执行相应动作
  end

  if _Conf.limitUaModulesIsOn then
    local userAgent = headers["user-agent"]
    --不存在UA直接抛验证码
    if not userAgent then
      self:debug("[limitUaModules] ip "..ip.." not have ua", ip, reqUri)
      self:takeAction(domain,ip,reqUri) --存在则执行相应动作
    end

    local uaMd5 = ngx.md5(userAgent)
    local blackUaKey = domain .. uaMd5 .. 'BlackUAKey'
    if _Conf.dict:get(blackUaKey) then --判断ua是否存在黑名单字典
      self:debug("[UablackListModules] ip "..ip.." in ua blacklist".." "..userAgent, ip, reqUri)
      self:takeAction(domain,ip,reqUri) --存在则执行相应动作
    end
  end
end

--限制UA请求速率模块
function Guard:limitUaModules(domain,ip, reqUri, address, headers)
  local domainRule = getDomainRule(domain)
  local domainLocationRule = getDomainLocationRule(domain,address,_Conf.limitUaState)
  if self:isMatch(domainRule,domainLocationRule,_Conf.limitUaModulesIsOn, address,address) then
    local userAgent = headers["user-agent"]
    --不存在UA直接抛验证码
    if not userAgent then
      self:debug("[limitUaModules] ip "..ip.." not have ua", ip, reqUri)
      self:takeAction(domain,ip,reqUri) --不存在则执行相应动作
    end

    local amongTime = _Conf.limitUaModules.amongTime
    local maxReqs = _Conf.limitUaModules.maxReqs
    local blockTime = _Conf.blockTime
    if domainLocationRule then
      -- 如果存在自定义的则使用自定义的
      maxReqs = domainLocationRule.maxReqs
      amongTime = domainLocationRule.amongTime
      blockTime = domainLocationRule.blockTime
    end

    local uaMd5 = ngx.md5(userAgent)
    local blackUaKey = domain .. uaMd5 .. 'BlackUAKey'
    local limitUaKey = domain .. uaMd5 .. 'LimitUaKey'
    local uaTimes = _Conf.dict:get(limitUaKey) --获取此ua请求的次数

    --增加一次请求记录
    if uaTimes then
      _Conf.dict:incr(limitUaKey, 1)
    else
      _Conf.dict:set(limitUaKey, 1, amongTime)
      uaTimes = 0
    end

    local newUaTimes  = uaTimes + 1
    self:debug("[limitUaModules] newUaTimes " .. newUaTimes .. "  " .. userAgent, ip, reqUri)

    --判断请求数是否大于阀值,大于则添加黑名单
    if newUaTimes > maxReqs then --判断是否请求数大于阀值
      self:debug("[limitUaModules] ip "..ip.. " request exceed ".. maxReqs .." "..userAgent, ip, reqUri)
      _Conf.dict:set(blackUaKey, 0,blockTime) --添加此ip到黑名单
      self:log("[limitUaModules] "..ip.." visit ".. domain .. " ".. userAgent .. " " .. newUaTimes.." times, block")
    end
  end
end


--限制IP请求速率模块
function Guard:limitReqModules(domain,ip,reqUri,address)
  local domainRule = getDomainRule(domain)
  local domainLocationRule = getDomainLocationRule(domain,address,_Conf.limitIpState)
  if self:isMatch(domainRule,domainLocationRule,_Conf.limitReqModulesIsOn,address,_Conf.limitUrlProtect) then
    self:debug("[limitReqModules] address "..address.." match reg or location",ip,reqUri)
    local uriMd5 = ngx.md5(address)
    local blackKey = domain .. ip..uriMd5.."black"
    local limitReqKey = domain .. ip..uriMd5.."limitreqkey" --定义limitreq key
    local reqTimes = _Conf.dict:get(limitReqKey) --获取此ip访问此域名的次数

    local maxReqs = _Conf.limitReqModules.maxReqs
    local blockTime = _Conf.blockTime
    local amongTime = _Conf.limitReqModules.amongTime
    if domainLocationRule then
      maxReqs = domainLocationRule.maxReqs
      amongTime = domainLocationRule.amongTime
      blockTime = domainLocationRule.blockTime

    end

    self:debug("[limitReqModules] domain "..domain,ip,reqUri)
    -- 如果存在自定义的则使用自定义的
    -- 即便没有匹配location然后总的开关开了，那么按照全局规则来
    self:debug("[limitReqModules] limit rule maxReqs:".. string.format("%s",maxReqs),ip,reqUri)
    --增加一次请求记录
    if reqTimes then
      _Conf.dict:incr(limitReqKey, 1)
    else
      self:debug("[limitReqModules] ip ".. ip.." visit " .. domain.." ",ip,reqUri)
      _Conf.dict:set(limitReqKey, 1,amongTime)
      reqTimes = 0
    end

    local newReqTimes  = reqTimes + 1
    self:debug("[limitReqModules] newReqTimes "..newReqTimes,ip,reqUri)
    --判断请求数是否大于阀值,大于则添加黑名单
    if newReqTimes > maxReqs then --判断是否请求数大于阀值
      self:debug("[limitReqModules] ip "..ip.. " request exceed "..maxReqs,ip,reqUri)
      _Conf.dict:set(blackKey,0,blockTime) --添加此ip到黑名单
      self:log("[limitReqModules] "..ip.." visit " .. domain .. " ".. address .." ".. newReqTimes.." times, block")
      --大于20次的特别记录下来
      --			if newReqTimes > 20 then
      --				local filename = _Conf.logPath.."/large_flow.log"
      --				local file = io.open(filename, "a+")
      --				file:write(os.date('%Y-%m-%d %H:%M:%S').." IP "..ip.." Domain " .. domain.. "\n")
      --				file:close()
      --			end
    end
  end
end

--302转向模块
function Guard:redirectModules(domain,ip,reqUri,address)
  local domainRule = getDomainRule(domain)
  local domainLocationRule = getDomainLocationRule(domain,address,_Conf.redirectState)
  if self:isMatch(domainRule,domainLocationRule,_Conf.redirectModulesIsOn,address,_Conf.redirectUrlProtect) then
    self:debug("[redirectModules] address "..address.." match location ",ip,reqUri)
    local uriMd5 = ngx.md5(address)
    local blackKey = domain..ip..uriMd5.."black"
    local whiteKey = domain..ip.."white302"
    local inWhiteList = _Conf.dict:get(whiteKey)

    local verifyMaxFail = _Conf.redirectModules.verifyMaxFail
    local blockTime = _Conf.blockTime
    local amongTime = _Conf.redirectModules.amongTime
    if domainLocationRule then
      verifyMaxFail = domainLocationRule.maxReqs
      amongTime = domainLocationRule.amongTime
      blockTime = domainLocationRule.blockTime
    end
    if inWhiteList then --如果在白名单
      self:debug("[redirectModules] in white ip list",ip,reqUri)
      return
    else
      --如果不在白名单,再检测是否有cookie凭证
      local now = ngx.time() --当前时间戳
      local challengeTimesKey = table.concat({ip,"challenge302"})
      local challengeTimesValue = _Conf.dict:get(challengeTimesKey)

      local cookie_key = ngx.var["cookie_key302"] --获取cookie密钥
      local cookie_expire = ngx.var["cookie_expire302"] --获取cookie密钥过期时间

      if cookie_key and cookie_expire then
        local key_make = ngx.md5(table.concat({ip,_Conf.redirectModules.keySecret,cookie_expire}))
        local key_make = string.sub(key_make,"1","10")
        --判断cookie是否有效
        if tonumber(cookie_expire) > now and cookie_key == key_make then
          self:debug("[redirectModules] cookie key is valid.",ip,reqUri)
          if challengeTimesValue then
            _Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
          end
          _Conf.dict:set(whiteKey,0,_Conf.whiteTime) --添加到白名单
          return
        else
          self:debug("[redirectModules] cookie key is invalid.",ip,reqUri)
          local expire = now + _Conf.keyExpire
          local key_new = ngx.md5(table.concat({ip,_Conf.redirectModules.keySecret,expire}))
          local key_new = string.sub(key_new,"1","10")
          --定义转向的url
          local newUrl = ''
          local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
          if newReqUri then
            local reqUriNoneArgs = newReqUri[1]
            local args = newReqUri[2]
            --删除cckey和keyexpire
            local newArgs = ngx.re.gsub(args, "[&?]?key302=[^&]+&?|expire302=[^&]+&?", "", "i")
            if newArgs == "" then
              newUrl = table.concat({reqUriNoneArgs,"?key302=",key_new,"&expire302=",expire})
            else
              newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&key302=",key_new,"&expire302=",expire})
            end
          else
            newUrl = table.concat({reqUri,"?key302=",key_new,"&expire302=",expire})

          end

          --验证失败次数加1
          if challengeTimesValue then
            _Conf.dict:incr(challengeTimesKey,1)
            if challengeTimesValue + 1> verifyMaxFail then
              self:debug("[redirectModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
              self:log("[redirectModules] "..ip.." challenge-cookie-failed " .. domain .. " ".. address .. " " .. challengeTimesValue.." times, block")
              _Conf.dict:set(blackKey,0, blockTime) --添加此ip到黑名单
            end
          else
            _Conf.dict:set(challengeTimesKey,1,amongTime)
          end

          --删除cookie
          ngx.header['Set-Cookie'] = {"key302=; path=/", "expire302=; expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/"}
          return ngx.redirect(newUrl, 302) --发送302转向
        end
      else
        --如果没有找到cookie,则检测是否带cckey参数
        local ccKeyValue = ngx.re.match(reqUri, "key302=([^&]+)","i")
        local expire = ngx.re.match(reqUri, "expire302=([^&]+)","i")

        if ccKeyValue and expire then --是否有cckey和keyexpire参数
          local ccKeyValue = ccKeyValue[1]
          local expire = expire[1]
          local key_make = ngx.md5(table.concat({ip,_Conf.redirectModules.keySecret,expire}))
          local key_make = string.sub(key_make,"1","10")
          self:debug("[redirectModules] ccKeyValue "..ccKeyValue,ip,reqUri)
          self:debug("[redirectModules] expire "..expire,ip,reqUri)
          self:debug("[redirectModules] key_make "..key_make,ip,reqUri)
          self:debug("[redirectModules] ccKeyValue "..ccKeyValue,ip,reqUri)
          if key_make == ccKeyValue and now < tonumber(expire) then--判断传过来的cckey参数值是否等于字典记录的值,且没有过期
            self:debug("[redirectModules] ip "..ip.." arg key302 "..ccKeyValue.." is valid.add ip to write list.",ip,reqUri)

            if challengeTimesValue then
              _Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
            end
            _Conf.dict:set(whiteKey,0,_Conf.whiteTime) --添加到白名单
            ngx.header['Set-Cookie'] = {"key302="..key_make.."; path=/", "expire302="..expire.."; path=/"} --发送cookie凭证
            return
          else --如果不相等，则再发送302转向
            self:debug("[redirectModules] ip "..ip.." arg key302 is invalid.",ip,reqUri)
            local expire = now + _Conf.keyExpire
            local key_new = ngx.md5(table.concat({ip,_Conf.redirectModules.keySecret,expire}))
            local key_new = string.sub(key_new,"1","10")

            --验证失败次数加1
            if challengeTimesValue then
              _Conf.dict:incr(challengeTimesKey,1)
              if challengeTimesValue + 1 > verifyMaxFail then
                self:debug("[redirectModules] client "..ip.." challenge 302key failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
                self:log("[redirectModules] "..ip.." challenge-302key-failed ".. domain .. " " .. address .. " " ..challengeTimesValue.." times, block")
                _Conf.dict:set(blackKey,0, blockTime) --添加此ip到黑名单
              end
            else
              _Conf.dict:set(challengeTimesKey,1,amongTime)
            end
            --定义转向的url
            local newUrl = ''
            local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
            if newReqUri then
              local reqUriNoneArgs = newReqUri[1]
              local args = newReqUri[2]
              --删除cckey和keyexpire
              local newArgs = ngx.re.gsub(args, "[&?]?key302=[^&]+&?|expire302=[^&]+&?", "", "i")
              if newArgs == "" then
                newUrl = table.concat({reqUriNoneArgs,"?key302=",key_new,"&expire302=",expire})
              else
                newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&key302=",key_new,"&expire302=",expire})
              end
            else
              newUrl = table.concat({reqUri,"?key302=",key_new,"&expire302=",expire})

            end

            return ngx.redirect(newUrl, 302) --发送302转向
          end
        else
          --验证失败次数加1
          if challengeTimesValue then
            _Conf.dict:incr(challengeTimesKey,1)
            if challengeTimesValue +1 > verifyMaxFail then
              self:debug("[redirectModules] client "..ip.." challenge 302key failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
              self:log("[redirectModules] "..ip.." challenge-302key-failed ".. domain .. " " .. address .. " " ..challengeTimesValue.." times, block")
              _Conf.dict:set(blackKey,0,blockTime) --添加此ip到黑名单
            end
          else
            _Conf.dict:set(challengeTimesKey,1,amongTime)
          end

          local expire = now + _Conf.keyExpire
          local key_new = ngx.md5(table.concat({ip,_Conf.redirectModules.keySecret,expire}))
          local key_new = string.sub(key_new,"1","10")

          --定义转向的url
          local newUrl = ''
          local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
          if newReqUri then
            local reqUriNoneArgs = newReqUri[1]
            local args = newReqUri[2]
            --删除cckey和keyexpire
            local newArgs = ngx.re.gsub(args, "[&?]?key302=[^&]+&?|expire302=[^&]+&?", "", "i")
            if newArgs == "" then
              newUrl = table.concat({reqUriNoneArgs,"?key302=",key_new,"&expire302=",expire})
            else
              newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&key302=",key_new,"&expire302=",expire})
            end
          else
            newUrl = table.concat({reqUri,"?key302=",key_new,"&expire302=",expire})
          end

          return ngx.redirect(newUrl, 302) --发送302转向
        end
      end
    end
  end
end

--js跳转模块
function Guard:JsJumpModules(domain,ip,reqUri,address)
  local domainRule = getDomainRule(domain)
  local domainLocationRule = getDomainLocationRule(domain,address,_Conf.jsJumpState)
  if self:isMatch(domainRule,domainLocationRule,_Conf.JsJumpModulesIsOn,address,_Conf.JsJumpUrlProtect) then
    self:debug("[JsJumpModules] address "..address.." match location or reg ",ip,reqUri)
    local uriMd5 = ngx.md5(address)
    local whiteKey = domain .. ip.."whitejs"	-- TODO
    local blackKey = domain .. ip.. uriMd5 .."black"
    local inWhiteList = _Conf.dict:get(whiteKey)

    local verifyMaxFail = _Conf.JsJumpModules.verifyMaxFail
    local blockTime = _Conf.blockTime
    local amongTime = _Conf.JsJumpModules.amongTime
    if domainLocationRule then
      verifyMaxFail = domainLocationRule.maxReqs
      blockTime = domainLocationRule.blockTime
      amongTime = domainLocationRule.amongTime
    end
    if inWhiteList then --如果在白名单
      self:debug("[JsJumpModules] in white ip list",ip,reqUri)
      return
    else
      --如果不在白名单,检测是否有cookie凭证
      local cookie_key = ngx.var["cookie_keyjs"] --获取cookie密钥
      local cookie_expire = ngx.var["cookie_expirejs"] --获取cookie密钥过期时间
      local now = ngx.time() --当前时间戳
      local challengeTimesKey = table.concat({ip,"challengejs"})
      local challengeTimesValue = _Conf.dict:get(challengeTimesKey)

      local cookie_key = ngx.var["cookie_keyjs"] --获取cookie密钥
      local cookie_expire = ngx.var["cookie_expirejs"] --获取cookie密钥过期时间

      if cookie_key and cookie_expire then
        local key_make = ngx.md5(table.concat({ip,_Conf.JsJumpModules.keySecret,cookie_expire}))
        local key_make = string.sub(key_make,"1","10")
        if tonumber(cookie_expire) > now and cookie_key == key_make then
          if challengeTimesValue then
            _Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
          end
          self:debug("[JsJumpModules] cookie key is valid.",ip,reqUri)
          _Conf.dict:set(whiteKey,0,_Conf.whiteTime) --添加ip到白名单
          return
        else
          --验证失败次数加1
          if challengeTimesValue then
            _Conf.dict:incr(challengeTimesKey,1)
            if challengeTimesValue +1 > verifyMaxFail then
              self:debug("[JsJumpModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
              self:log("[JsJumpModules] "..ip.." challenge-cookie-failed ".. domain .. " ".. address .." "..challengeTimesValue.." times, block")
              _Conf.dict:set(blackKey,0,blockTime) --添加此ip到黑名单
            end
          else
            _Conf.dict:set(challengeTimesKey,1,amongTime)
          end

          self:debug("[JsJumpModules] cookie key is invalid.",ip,reqUri)
          local expire = now + _Conf.keyExpire
          local key_new = ngx.md5(table.concat({ip,_Conf.JsJumpModules.keySecret,expire}))
          local key_new = string.sub(key_new,"1","10")

          --定义转向的url
          local newUrl = ''
          local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
          if newReqUri then
            local reqUriNoneArgs = newReqUri[1]
            local args = newReqUri[2]
            --删除cckey和keyexpire
            local newArgs = ngx.re.gsub(args, "[&?]?keyjs=[^&]+&?|expirejs=[^&]+&?", "", "i")
            if newArgs == "" then
              newUrl = table.concat({reqUriNoneArgs,"?keyjs=",key_new,"&expirejs=",expire})
            else
              newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&keyjs=",key_new,"&expirejs=",expire})
            end
          else
            newUrl = table.concat({reqUri,"?keyjs=",key_new,"&expirejs=",expire})

          end

          local jsJumpCode=table.concat({"<script>window.location.href='",newUrl,"';</script>"}) --定义js跳转代码
          ngx.header.content_type = "text/html"
          --删除cookie
          ngx.header['Set-Cookie'] = {"keyjs=; path=/", "expirejs=; expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/"}
          ngx.print(jsJumpCode)
          ngx.exit(200)
        end
      else
        --如果没有cookie凭证,检测url是否带有cckey参数
        local ccKeyValue = ngx.re.match(reqUri, "keyjs=([^&]+)","i")
        local expire = ngx.re.match(reqUri, "expirejs=([^&]+)","i")

        if ccKeyValue and expire then
          local ccKeyValue = ccKeyValue[1]
          local expire = expire[1]

          local key_make = ngx.md5(table.concat({ip,_Conf.JsJumpModules.keySecret,expire}))
          local key_make = string.sub(key_make,"1","10")

          if key_make == ccKeyValue and now < tonumber(expire) then--判断传过来的cckey参数值是否等于字典记录的值,且没有过期
            self:debug("[JsJumpModules] ip "..ip.." arg keyjs "..ccKeyValue.." is valid.add ip to white list.",ip,reqUri)
            if challengeTimesValue then
              _Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
            end
            _Conf.dict:set(whiteKey,0,_Conf.whiteTime) --添加ip到白名单
            ngx.header['Set-Cookie'] = {"keyjs="..key_make.."; path=/", "expirejs="..expire.."; path=/"} --发送cookie凭证
            return
          else --如果不相等，则再发送302转向
            --验证失败次数加1
            if challengeTimesValue then
              _Conf.dict:incr(challengeTimesKey,1)
              if challengeTimesValue + 1 > verifyMaxFail then
                self:debug("[JsJumpModules] client "..ip.." challenge jskey failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
                self:log("[JsJumpModules] "..ip.." challenge-jskey-failed ".. domain .. " ".. address .." "..challengeTimesValue.." times, block")
                _Conf.dict:set(blackKey,0,blockTime) --添加此ip到黑名单
              end
          else
            _Conf.dict:set(challengeTimesKey,1,amongTime)
          end

          self:debug("[JsJumpModules] ip "..ip.." arg keyjs is invalid.",ip,reqUri)
          local expire = now + _Conf.keyExpire
          local key_new = ngx.md5(table.concat({ip,_Conf.JsJumpModules.keySecret,expire}))
          local key_new = string.sub(key_new,"1","10")
          --定义转向的url
          local newUrl = ''
          local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
          if newReqUri then
            local reqUriNoneArgs = newReqUri[1]
            local args = newReqUri[2]
            --删除cckey和keyexpire
            local newArgs = ngx.re.gsub(args, "[&?]?keyjs=[^&]+&?|expirejs=[^&]+&?", "", "i")
            if newArgs == "" then
              newUrl = table.concat({reqUriNoneArgs,"?keyjs=",key_new,"&expirejs=",expire})
            else
              newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&keyjs=",key_new,"&expirejs=",expire})
            end
          else
            newUrl = table.concat({reqUri,"?keyjs=",key_new,"&expirejs=",expire})

          end
          local jsJumpCode=table.concat({"<script>window.location.href='",newUrl,"';</script>"}) --定义js跳转代码
          ngx.header.content_type = "text/html"
          ngx.print(jsJumpCode)
          ngx.exit(200)
          end
        else
          --验证失败次数加1
          if challengeTimesValue then
            _Conf.dict:incr(challengeTimesKey,1)
            if challengeTimesValue + 1 > verifyMaxFail then
              self:debug("[JsJumpModules] client "..ip.." challenge jskey failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
              self:log("[JsJumpModules] "..ip.." challenge-jskey-failed ".. domain .. " ".. address .." "..challengeTimesValue.." times, block")
              _Conf.dict:set(blackKey,0,blockTime) --添加此ip到黑名单
            end
          else
            _Conf.dict:set(challengeTimesKey,1,amongTime)
          end

          --定义转向的url
          local expire = now + _Conf.keyExpire
          local key_new = ngx.md5(table.concat({ip,_Conf.JsJumpModules.keySecret,expire}))
          local key_new = string.sub(key_new,"1","10")

          --定义转向的url
          local newUrl = ''
          local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
          if newReqUri then
            local reqUriNoneArgs = newReqUri[1]
            local args = newReqUri[2]
            --删除cckey和keyexpire
            local newArgs = ngx.re.gsub(args, "[&?]?keyjs=[^&]+&?|expirejs=[^&]+&?", "", "i")
            if newArgs == "" then
              newUrl = table.concat({reqUriNoneArgs,"?keyjs=",key_new,"&expirejs=",expire})
            else
              newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&keyjs=",key_new,"&expirejs=",expire})
            end
          else
            newUrl = table.concat({reqUri,"?keyjs=",key_new,"&expirejs=",expire})

          end

          local jsJumpCode=table.concat({"<script>window.location.href='",newUrl,"';</script>"}) --定义js跳转代码
          ngx.header.content_type = "text/html"
          ngx.print(jsJumpCode)
          ngx.exit(200)
        end
      end
    end
  end
end

--cookie验证模块
function Guard:cookieModules(domain,ip,reqUri,address)
  local domainRule = getDomainRule(domain)
  local domainLocationRule = getDomainLocationRule(domain,address,_Conf.cookieState)
  if self:isMatch(domainRule,domainLocationRule,_Conf.cookieModulesIsOn,address,_Conf.cookieUrlProtect) then
    self:debug("[cookieModules] address "..address.." match reg or location ",ip,reqUri)
    local uriMd5 = ngx.md5(address)
    local blackKey = domain..ip.. uriMd5 .."black"
    local whiteKey = domain .. ip.."whitecookie"
    local inWhiteList = _Conf.dict:get(whiteKey)

    local verifyMaxFail = _Conf.cookieModules.verifyMaxFail
    local blockTime = _Conf.blockTime
    local amongTime = _Conf.cookieModules.amongTime
    if domainLocationRule then
      verifyMaxFail = domainLocationRule.maxReqs
      blockTime = domainLocationRule.blockTime
      amongTime = domainLocationRule.amongTime
    end

    if inWhiteList then --如果在白名单
      self:debug("[cookieModules] in white ip list.",ip,reqUri)
      return
    else
      local cookie_key = ngx.var["cookie_keycookie"] --获取cookie密钥
      local cookie_expire = ngx.var["cookie_expirecookie"] --获取cookie密钥过期时间
      local now = ngx.time() --当前时间戳
      local challengeTimesKey = table.concat({ip,"challengecookie"})
      local challengeTimesValue = _Conf.dict:get(challengeTimesKey)
      if cookie_key and cookie_expire then --判断是否有收到cookie
        local key_make = ngx.md5(table.concat({ip,_Conf.cookieModules.keySecret,cookie_expire}))
        local key_make = string.sub(key_make,"1","10")
        if tonumber(cookie_expire) > now and cookie_key == key_make then
          if challengeTimesValue then
            _Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
          end
          self:debug("[cookieModules] cookie key is valid.add to white ip list",ip,reqUri)
          _Conf.dict:set(whiteKey,0,_Conf.whiteTime) --添加ip到白名单
          return
        else
          self:debug("[cookieModules] cookie key is invalid",ip,reqUri)
          --验证失败次数加1
          if challengeTimesValue then
            _Conf.dict:incr(challengeTimesKey,1)
            if challengeTimesValue +1 > verifyMaxFail then
              self:debug("[cookieModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
              self:log("[cookieModules] "..ip.." challenge-cookie-failed ".. domain .. " ".. address .." "..challengeTimesValue.." times, block")
              _Conf.dict:set(blackKey,0,blockTime) --添加此ip到黑名单
            end
          else
            _Conf.dict:set(challengeTimesKey,1,amongTime)
          end

          ngx.header['Set-Cookie'] = {"keycookie=; path=/", "expirecookie=; expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/"} --删除cookie
        end
      else --找不到cookie
        self:debug("[cookieModules] cookie not found.",ip,reqUri)
        --验证失败次数加1
        if challengeTimesValue then
          _Conf.dict:incr(challengeTimesKey,1)
          if challengeTimesValue +1 > verifyMaxFail then
            self:debug("[cookieModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
            self:log("[cookieModules] "..ip.." challenge-cookie-failed ".. domain .. " ".. address .." "..challengeTimesValue.." times, block")
            _Conf.dict:set(blackKey,0,blockTime) --添加此ip到黑名单
          end
        else
          _Conf.dict:set(challengeTimesKey,1,amongTime)
        end

        local expire = now + _Conf.keyExpire
        local key_new = ngx.md5(table.concat({ip,_Conf.cookieModules.keySecret,expire}))
        local key_new = string.sub(key_new,"1","10")

        self:debug("[cookieModules] send cookie to client.",ip,reqUri)
        ngx.header['Set-Cookie'] = {"keycookie="..key_new.."; path=/", "expirecookie="..expire.."; path=/"} --发送cookie凭证
      end
    end
  end
end

--获取验证码
function Guard:getCaptcha()
  math.randomseed(ngx.now()) --随机种子
  local random = math.random(1,10000) --生成1-10000之前的随机数
  self:debug("[getCaptcha] get random num "..random,"","")
  local captchaValue = _Conf.dict_captcha:get(random) --取得字典中的验证码
  self:debug("[getCaptcha] get captchaValue "..captchaValue,"","")
  local captchaImg = _Conf.dict_captcha:get(captchaValue) --取得验证码对应的图片
  --返回图片
  ngx.header.content_type = "image/jpeg"
  ngx.header['Set-Cookie'] = table.concat({"captchaNum=",random,"; path=/"})
  ngx.print(captchaImg)
  ngx.exit(200)
end

--验证验证码
function Guard:verifyCaptcha(domain,ip)
  ngx.req.read_body()
  local captchaNum = ngx.var["cookie_captchaNum"] --获取cookie captchaNum值
  local preurl = ngx.var["cookie_preurl"] --获取上次访问url
  self:debug("[verifyCaptcha] get cookie captchaNum "..captchaNum,ip,"")
  local args = ngx.req.get_post_args() --获取post参数
  local postValue = args["response"] --获取post value参数
  postValue = string.lower(postValue)
  self:debug("[verifyCaptcha] get post arg response "..postValue,ip,"")
  local captchaValue = _Conf.dict_captcha:get(captchaNum) --从字典获取post value对应的验证码值
  if captchaValue == postValue then --比较验证码是否相等
    self:debug("[verifyCaptcha] captcha is valid.delete from blacklist",ip,"")

    _Conf.dict:delete(ip.."black") --从黑名单删除
    _Conf.dict:delete(ip.."limitreqkey") --访问记录删除

    if _Conf.limitUaModulesIsOn then
      local headers = ngx.req.get_headers()
      local userAgent = headers["user-agent"]
      --不存在UA直接抛验证码
      if not userAgent then
        self:debug("[limitUaModules] ip "..ip.." not have ua", ip)
        self:takeAction(domain,ip,"") --存在则执行相应动作
      end

      local uaMd5 = ngx.md5(userAgent)
      local blackUaKey = uaMd5 .. 'BlackUAKey'
      local limitUaKey = uaMd5 .. 'LimitUaKey'

      _Conf.dict:delete(blackUaKey) --从黑名单删除
      _Conf.dict:delete(limitUaKey) --访问记录删除
    end

    local expire = ngx.time() + _Conf.keyExpire
    local captchaKey = ngx.md5(table.concat({ip,_Conf.captchaKey,expire}))
    local captchaKey = string.sub(captchaKey,"1","10")
    self:debug("[verifyCaptcha] expire "..expire,ip,"")
    self:debug("[verifyCaptcha] captchaKey "..captchaKey,ip,"")
    ngx.header['Set-Cookie'] = {"captchaKey="..captchaKey.."; path=/", "captchaExpire="..expire.."; path=/"}
    return ngx.redirect(preurl) --返回上次访问url
  else
    --重新发送验证码页面
    self:debug("[verifyCaptcha] captcha invalid",ip,"")
    ngx.header.content_type = "text/html"
    ngx.print(_Conf.reCaptchaPage)
    ngx.exit(200)
  end
end

--拒绝访问动作
function Guard:forbiddenAction()
  ngx.header.content_type = "text/html"
  ngx.exit(403)
end

--展示验证码页面动作
function Guard:captchaAction(reqUri)
  ngx.header.content_type = "text/html"
  ngx.header['Set-Cookie'] = table.concat({"preurl=",reqUri,"; path=/"})
  ngx.print(_Conf.captchaPage)
  ngx.exit(200)
end


-- 抽取出的执行验证码动作
function Guard:takeCaptchaAction(domain,ip,reqUri)
  local cookie_key = ngx.var["cookie_captchaKey"] --获取cookie captcha密钥
  local cookie_expire = ngx.var["cookie_captchaExpire"] --获取cookie captcha过期时间
  if cookie_expire and cookie_key then
    local now = ngx.time()
    local key_make = ngx.md5(table.concat({ip,_Conf.captchaKey,cookie_expire}))
    local key_make = string.sub(key_make,"1","10")
    self:debug("[takeAction] cookie_expire "..cookie_expire,ip,reqUri)
    self:debug("[takeAction] cookie_key "..cookie_key,ip,reqUri)
    self:debug("[takeAction] now "..now,ip,reqUri)
    self:debug("[takeAction] key_make "..key_make,ip,reqUri)
    if tonumber(cookie_expire) > now and cookie_key == key_make then
      self:debug("[takeAction] cookie key is valid.",ip,reqUri)
      return
    else
      self:debug("[takeAction] cookie key is invalid",ip,reqUri)
      self:captchaAction(reqUri)
    end
  else
    self:debug("[takeAction] return captchaAction",ip,reqUri)
    self:captchaAction(reqUri)
  end
end

--执行相应动作
function Guard:takeAction(domain,ip,reqUri)
  -- 自定义禁用动作
  local blockAction = getDBrule(domain)
  if blockAction then
    if blockAction == "forbidden" then
      self:forbiddenAction()
    elseif blockAction == "captcha" then
      self:takeCaptchaAction(domain,ip,reqUri)
    elseif blockAction == "iptables" then

      ngx.thread.spawn(Guard.addToIptables,Guard,ip)
    end
  elseif _Conf.captchaAction then
    self:takeCaptchaAction(domain,ip,reqUri)
  elseif _Conf.forbiddenAction then
    self:debug("[takeAction] return forbiddenAction",ip,reqUri)
    self:forbiddenAction()
  elseif _Conf.iptablesAction then
    ngx.thread.spawn(Guard.addToIptables,Guard,ip)
  end
end

--添加进iptables drop表
function Guard:addToIptables(ip)
  local cmd = "echo ".._Conf.sudoPass.." | sudo -S /sbin/iptables -I INPUT -p tcp -s "..ip.." --dport 80 -j DROP"
  os.execute(cmd)
end

--自动开启或关闭防cc功能
function Guard:autoSwitch()
  if not _Conf.dict_captcha:get("monitor") then
    _Conf.dict_captcha:set("monitor",0,_Conf.autoEnable.interval)
    local f=io.popen(_Conf.autoEnable.ssCommand.." -tan state established '( sport = :".._Conf.autoEnable.protectPort.." or dport = :".._Conf.autoEnable.protectPort.." )' | wc -l")
    local result=f:read("*all")
    local connection=tonumber(result)
    Guard:debug("[autoSwitch] current connection for port ".._Conf.autoEnable.protectPort.." is "..connection,"","")
    if _Conf.autoEnable.enableModule == "redirectModules" then
      local redirectOn = _Conf.dict_captcha:get("redirectOn")
      if redirectOn == 1 then
        _Conf.dict_captcha:set("exceedCount",0) --超限次数清0
        --如果当前连接在最大连接之下,为正常次数加1
        if connection < _Conf.autoEnable.maxConnection then
          _Conf.dict_captcha:incr("normalCount",1)
        end

        --如果正常次数大于_Conf.autoEnable.normalTimes,关闭redirectModules
        local normalCount = _Conf.dict_captcha:get("normalCount")
        if normalCount > _Conf.autoEnable.normalTimes then
          Guard:log("[autoSwitch] turn redirectModules off.")
          _Conf.dict_captcha:set("redirectOn",0)
        end
      else
        _Conf.dict_captcha:set("normalCount",0) --正常次数清0
        --如果当前连接在最大连接之上,为超限次数加1
        if connection > _Conf.autoEnable.maxConnection then
          _Conf.dict_captcha:incr("exceedCount",1)
        end

        --如果超限次数大于_Conf.autoEnable.exceedTimes,开启redirectModules
        local exceedCount = _Conf.dict_captcha:get("exceedCount")
        if exceedCount > _Conf.autoEnable.exceedTimes then
          Guard:log("[autoSwitch] turn redirectModules on.")
          _Conf.dict_captcha:set("redirectOn",1)
        end
      end

    elseif 	_Conf.autoEnable.enableModule == "JsJumpModules" then
      local jsOn = _Conf.dict_captcha:get("jsOn")
      if jsOn == 1 then
        _Conf.dict_captcha:set("exceedCount",0) --超限次数清0
        --如果当前连接在最大连接之下,为正常次数加1
        if connection < _Conf.autoEnable.maxConnection then
          _Conf.dict_captcha:incr("normalCount",1)
        end

        --如果正常次数大于_Conf.autoEnable.normalTimes,关闭JsJumpModules
        local normalCount = _Conf.dict_captcha:get("normalCount")
        if normalCount > _Conf.autoEnable.normalTimes then
          Guard:log("[autoSwitch] turn JsJumpModules off.")
          _Conf.dict_captcha:set("jsOn",0)
        end
      else
        _Conf.dict_captcha:set("normalCount",0) --正常次数清0
        --如果当前连接在最大连接之上,为超限次数加1
        if connection > _Conf.autoEnable.maxConnection then
          _Conf.dict_captcha:incr("exceedCount",1)
        end

        --如果超限次数大于_Conf.autoEnable.exceedTimes,开启JsJumpModules
        local exceedCount = _Conf.dict_captcha:get("exceedCount")
        if exceedCount > _Conf.autoEnable.exceedTimes then
          Guard:log("[autoSwitch] turn JsJumpModules on.")
          _Conf.dict_captcha:set("jsOn",1)
        end
      end

    elseif 	_Conf.autoEnable.enableModule == "cookieModules" then
      local cookieOn = _Conf.dict_captcha:get("cookieOn")
      if cookieOn == 1 then
        _Conf.dict_captcha:set("exceedCount",0) --超限次数清0
        --如果当前连接在最大连接之下,为正常次数加1
        if connection < _Conf.autoEnable.maxConnection then
          _Conf.dict_captcha:incr("normalCount",1)
        end

        --如果正常次数大于_Conf.autoEnable.normalTimes,关闭cookieModules
        local normalCount = _Conf.dict_captcha:get("normalCount")
        if normalCount > _Conf.autoEnable.normalTimes then
          Guard:log("[autoSwitch] turn cookieModules off.")
          _Conf.dict_captcha:set("cookieOn",0)
        end
      else
        _Conf.dict_captcha:set("normalCount",0) --正常次数清0
        --如果当前连接在最大连接之上,为超限次数加1
        if connection > _Conf.autoEnable.maxConnection then
          _Conf.dict_captcha:incr("exceedCount",1)
        end

        --如果超限次数大于_Conf.autoEnable.exceedTimes,开启cookieModules
        local exceedCount = _Conf.dict_captcha:get("exceedCount")
        if exceedCount > _Conf.autoEnable.exceedTimes then
          Guard:log("[autoSwitch] turn cookieModules on.")
          _Conf.dict_captcha:set("cookieOn",1)
        end
      end
    end
  end
end

-- a and b or c and d true
function Guard:isMatch(a,b,c,d,e)
  if a then
    if b then
      return true
    end
  end
  if c then
    if e == nil or e == "" then
      return false
    end
    if ngx.re.match(d,e,"i") then
      return true
    end
  end
  return false
end

return Guard
