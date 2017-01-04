---
--如果是静态文件则直接放行
--如果IP在黑名单，则禁用
--如果匹配到没有UA，则直接加入黑名单
--如果请求次数达到默认或自定义的规则，则放入黑名单
--



local Guard = require "guard"
local remoteIp = ngx.var.remote_addr
local headers = ngx.req.get_headers()

local ip = Guard:getRealIp(remoteIp,headers)
local domain = ngx.unescape_uri(ngx.var.http_host)
local reqUri = ngx.var.request_uri
local uri = ngx.var.uri
local address = ''

--去掉域名中的符号
local function trim(s) return (string.gsub(s, "%p", ""))end

--判断是某种url匹配模式
if _Conf.uriMode then
  address = uri
elseif _Conf.requestUriMode then
  address = reqUri
end

  --获取验证码
if ngx.re.match(uri,"/get-captcha.jpg$","i") then
    Guard:getCaptcha()
  
  --验证验证码
elseif ngx.re.match(uri,"/verify-captcha.jpg$","i") then
    Guard:verifyCaptcha(domain,ip)
-- 过滤掉静态文件
elseif ngx.re.match(uri,_Conf.staticRegex) then
    Guard:debug("static file",ip,reqUri)
else    
    --定时检查连接数
    if _Conf.autoEnableIsOn then
      ngx.timer.at(0,Guard.autoSwitch)
    end
  
    --永久黑名单
    if Guard:ipInFileBlackList(ip) then
      ngx.exit(404)
    end
  
    --白名单模块
    if not Guard:ipInWhiteList(ip) then
      --收集不在白名单库里面的蜘蛛
      -- Guard:collectSpiderIp(ip, headers)
  
      --黑名单模块
      Guard:blackListModules(domain,ip, reqUri, headers)
  
      --限制UA请求速率模块
      if _Conf.limitUaModulesIsOn then
        Guard:debug("[limitUaModules] limitUaModules is on.",ip,reqUri)
        Guard:limitUaModules(domain,ip, reqUri, address, headers)
      end
  
      --限制IP请求速率模块
      if getDrule(domain) or _Conf.limitReqModulesIsOn then --limitReq模块是否开启
        Guard:debug("[limitReqModules] limitReqModules is on.",ip,reqUri)
        Guard:limitReqModules(domain,ip,reqUri,address)
      end
  
      --302转向模块
      local redirectOn = _Conf.dict_captcha:get("redirectOn")
      if redirectOn == 1 then --判断转向模块是否开启
        Guard:debug("[redirectModules] redirectModules is on.",ip,reqUri)
        Guard:redirectModules(domain,ip,reqUri,address)
      end 
  
      --js跳转模块
      local jsOn = _Conf.dict_captcha:get("jsOn")
      if jsOn == 1 then --判断js跳转模块是否开启
        Guard:debug("[JsJumpModules] JsJumpModules is on.",ip,reqUri)
        Guard:JsJumpModules(domain,ip,reqUri,address)
      end
      
      --cookie验证模块
      local cookieOn = _Conf.dict_captcha:get("cookieOn")
      if cookieOn == 1 then --判断是否开启cookie模块
        Guard:debug("[cookieModules] cookieModules is on.",ip,reqUri)
        Guard:cookieModules(domain,ip,reqUri,address)
      end
        
    end 
  end
