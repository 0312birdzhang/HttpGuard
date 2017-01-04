local Config = require("config")
local cjson_safe = require "cjson.safe"

--开关转换为true或false函数
local function optionIsOn(options)
	local options = string.lower(options)
	if options == "on" then
		return true
	else
		return false
	end	
end

--生成密码
local function makePassword()
	local string="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	math.randomseed(os.time()) --随机种子
	local r1 = math.random(1,62) --生成1-62之间的随机数
	local r2 = math.random(1,62) --生成1-62之间的随机数
	local r3 = math.random(1,62) --生成1-62之间的随机数
	local r4 = math.random(1,62) --生成1-62之间的随机数
	local r5 = math.random(1,62) --生成1-62之间的随机数
	local r6 = math.random(1,62) --生成1-62之间的随机数
	local r7 = math.random(1,62) --生成1-62之间的随机数
	local r8 = math.random(1,62) --生成1-62之间的随机数

	local s1 = string.sub(string,r1,r1)
	local s2 = string.sub(string,r2,r2)
	local s3 = string.sub(string,r3,r3)
	local s4 = string.sub(string,r4,r4)
	local s5 = string.sub(string,r5,r5)
	local s6 = string.sub(string,r6,r6)
	local s7 = string.sub(string,r7,r7)
	local s8 = string.sub(string,r8,r8)

	return s1..s2..s3..s4..s5..s6..s7..s8
end

--解析文件到正则字符串函数
local function parseRuleFile(filePath)
	local list = ''
	local rfile = assert(io.open(filePath,'r'))
	for line in rfile:lines() do
		if not (string.match(line,"^ *$")) then
			list = list.."|"..line
		end
	end
	list = string.gsub(list,"^%|",'')
	rfile:close()
	return list
end

--解析动作
local function actionIsOn1(action)
	if action == "captcha" then
		return true	
	else
		return false
	end	
end

local function actionIsOn2(action)
	if action == "forbidden" then
		return true
	else
		return false
	end	
end

local function actionIsOn3(action)
	if action == "iptables" then
		return true
	else
		return false
	end	
end

--解析uri匹配模式
local function urlMode1(mode)
	if mode == "uri" then
		return true
	else
		return false
	end
end

local function urlMode2(mode)
	if mode == "requestUri" then
		return true
	else
		return false
	end	
end


--读取文件到内存
local function readFile2Mem(file)
	local fp = io.open(file,"r")
	if fp then
		return fp:read("*all")
	end
end

--读取验证码到字典
local function readCaptcha2Dict(dir,dict) 
	local i = 0
	for path in io.popen('ls -a '..dir..'*.png'):lines() do
		if i < 10000 then
			i = i + 1
			local fp = io.open(path,"rb")
			local img = fp:read("*all")
			local captcha = string.gsub(path,".*/(.*)%.png","%1")
			captcha = string.lower(captcha)
			dict:set(i,captcha)
			dict:set(captcha,img)
		else
			break
		end	
	end	
end


-- 载入JSON文件
-- loadConfig()调用
local function loadjson(_path_name)
  local x = readFile2Mem(_path_name)
  local json = cjson_safe.decode(x) or {}
  return json
end

-- 读取自定义域名配置
local function loadDLreg(_json_path,dict)
  local regJson = loadjson(_json_path)
  for i,v in ipairs(regJson)  do
    for k,j in pairs(v) do
     if k then
     -- 存储域名跟域名的配置
     success, err, forcible = dict:set(k,cjson_safe.encode(j))
     -- ngx.log(ngx.ERR,cjson_safe.encode(dict:get(k)))
     end
    end
 end
end

-- 处理请求uri为location
-- 判断str是否以substr开头
local function startswith(str,substr)
  if str == nil or substr == nil then
      return nil
  end
  if string.find(str, substr) ~= 1 then
      return false
  else
      return true
  end
end

-- 比较字符串长度
local function tab_cmp(a,b)
  return string.len(a) > string.len(b)
end

_Conf = {
	
	--引入原始设置
	limitUaModules = Config.limitUaModules,
	limitReqModules = Config.limitReqModules,
	redirectModules = Config.redirectModules,
	JsJumpModules = Config.JsJumpModules,
	cookieModules = Config.cookieModules,
	whiteIpModules = Config.whiteIpModules,
	realIpFromHeader = Config.realIpFromHeader,
	autoEnable = Config.autoEnable,
	debug = Config.debug,
	logPath = Config.logPath,
	blockTime = Config.blockTime,
	keyExpire = Config.keyExpire,
	sudoPass = Config.sudoPass,
	whiteTime = Config.whiteTime,
	captchaKey = Config.captchaKey,
	staticRegex = Config.staticRegex,

	--解析开关设置
	limitUaModulesIsOn = optionIsOn(Config.limitUaModules.state),
	limitReqModulesIsOn = optionIsOn(Config.limitReqModules.state),
	whiteIpModulesIsOn = optionIsOn(Config.whiteIpModules.state),
	fileBlackIpModulesIsOn = optionIsOn(Config.blackIpModules.state),
	realIpFromHeaderIsOn = optionIsOn(Config.realIpFromHeader.state),
	autoEnableIsOn = optionIsOn(Config.autoEnable.state),
	redirectModulesIsOn = optionIsOn(Config.redirectModules.state),
	JsJumpModulesIsOn = optionIsOn(Config.JsJumpModules.state),
	cookieModulesIsOn = optionIsOn(Config.cookieModules.state),

	--解析文件到正则
	redirectUrlProtect = parseRuleFile(Config.redirectModules.urlProtect),
	JsJumpUrlProtect = parseRuleFile(Config.JsJumpModules.urlProtect),
	limitUrlProtect = parseRuleFile(Config.limitReqModules.urlProtect),
	cookieUrlProtect = parseRuleFile(Config.cookieModules.urlProtect),
	whiteIpList = parseRuleFile(Config.whiteIpModules.ipList),
	fileBlackIpList = parseRuleFile(Config.blackIpModules.ipList),

	--读取文件到内存
	captchaPage = readFile2Mem(Config.captchaPage),
	reCaptchaPage = readFile2Mem(Config.reCaptchaPage),

	--新建字典(用于记录ip访问次数及黑名单)
	dict = ngx.shared.guard_dict,

	--新建字典(只用于记录验证码,防止丢失)
	dict_captcha = ngx.shared.dict_captcha,

  -- 新建字典(记录自定义域名规则)
  dict_domain = ngx.shared.dict_domain,
  
	--验证码图片路径
	captchaDir = Config.captchaDir,

	captchaAction = actionIsOn1(Config.blockAction),
	forbiddenAction = actionIsOn2(Config.blockAction),
	iptablesAction = actionIsOn3(Config.blockAction),

	--解析url匹配模式
	uriMode = urlMode1(Config.urlMatchMode),
	requestUriMode = urlMode2(Config.urlMatchMode),

	normalCount = 0,
	exceedCount = 0,
	
	dJsonDir = Config.dJsonDir
  	
}

--读取验证码到字典
readCaptcha2Dict(_Conf.captchaDir,_Conf.dict_captcha)

--判断redirectModules是否开启
if _Conf.redirectModulesIsOn then
	_Conf.dict_captcha:set("redirectOn",1)
else
	_Conf.dict_captcha:set("redirectOn",0)
end

--判断JsJumpModules是否开启
if _Conf.JsJumpModulesIsOn then
	_Conf.dict_captcha:set("jsOn",1)
else
	_Conf.dict_captcha:set("jsOn",0)
end

--判断cookieModules是否开启
if _Conf.cookieModulesIsOn then
	_Conf.dict_captcha:set("cookieOn",1)
else
	_Conf.dict_captcha:set("cookieOn",0)
end

--设置自动开启防cc相关变量
if _Conf.autoEnableIsOn then
	_Conf.dict_captcha:set("normalCount",0)
	_Conf.dict_captcha:set("exceedCount",0)
end	


--判断是否key是动态生成
if Config.keyDefine == "dynamic" then
	_Conf.redirectModules.keySecret = makePassword()
	_Conf.JsJumpModules.keySecret = makePassword()
	_Conf.cookieModules.keySecret = makePassword()
	_Conf.captchaKey = makePassword()
end	


-- 读取域名自定义限速 
function getDomainModule(domain)
  if Config.domainDefine[domain]  ~= nil and optionIsOn(Config.domainDefine[domain].state) then
    return Config.domainDefine[domain]
  else
    return nil
  end
end





-- 载入到共享内存
loadDLreg(_Conf.dJsonDir,_Conf.dict_domain)

-- 获取域名是否存在或开启规则
function getDrule(domain)
  local domainRule = _Conf.dict_domain:get(domain)
   -- ngx.log(ngx.ERR,domainRule)
  if domainRule and optionIsOn(cjson_safe.decode(domainRule).state) then
    return true
  end
  return false
end

-- 获取域名的blockAction
function getDBrule(domain)
  local domainRule = _Conf.dict_domain:get(domain)
  if domainRule then
    return cjson_safe.decode(domainRule).blockAction
  end
  return nil
end


-- 获取域名的规则
-- 支持nginx location匹配规则
function getDLrule(domain,address)
  local domainRule =  cjson_safe.decode(_Conf.dict_domain:get(domain)).locations
  if domainRule then
    local locations = {}
    for k,j in pairs(domainRule) do
      -- =前缀的指令严格匹配这个查询
      if startswith(k,"=") and "= ".. address == k and optionIsOn(j.state) then
        -- ngx.log(ngx.ERR,"location =")
        return j
      -- 普通字符匹配
      elseif startswith(k,"^ ~") or startswith(k,"^~")  then
        k = string.gsub(k,"%~","")
        k = string.gsub(k,"% ","")
        if string.find(address,k) and optionIsOn(j.state) then
        -- ngx.log(ngx.ERR,"location ^~")
          return j
        end
      -- 正则匹配
      elseif startswith(k,"~") then
        k = string.gsub(k,"%(","([")
        k = string.gsub(k,"%)","])")
        k = string.gsub(k,"%~ ","")
        if string.find(address,k) and optionIsOn(j.state) then
        -- ngx.log(ngx.ERR,"location ~")
          return j
        end
      end
      -- 字符串匹配
      if string.find(address,k) and optionIsOn(j.state) then
        table.insert(locations,k)
      end
    end
    -- 取出匹配最多的location,并且
    -- 排序最长的
    table.sort(locations,tab_cmp)
    k = locations[1]
    -- ngx.log(ngx.ERR,"location ".. k)
    return domainRule[k]
  end
  return nil
end
