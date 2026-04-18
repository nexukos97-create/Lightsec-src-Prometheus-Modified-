local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local RandomStrings = require("prometheus.randomStrings")
local Parser = require("prometheus.parser");
local Enums = require("prometheus.enums");
local logger = require("logger");

local AntiTamper = Step:extend();
AntiTamper.Description = "vghvcfg";
AntiTamper.Name = "Anti Tamper";

AntiTamper.SettingsDescriptor = {
    UseDebug = {
        type = "boolean",
        default = false,
        description = "Use debug library."
    }
}

function AntiTamper:init(settings)
end

function AntiTamper:apply(ast, pipeline)
    if pipeline.PrettyPrint then
        logger:warn(string.format("\"%s\" cannot be used with PrettyPrint, ignoring \"%s\"", self.Name, self.Name));
        return ast;
    end

    local protocol = tostring(math.random(1000, 9999));

    local function randStr(len)
        local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        local s = ""
        for i = 1, len do
            local idx = math.random(1, #chars)
            s = s .. chars:sub(idx, idx)
        end
        return s
    end

    local fakeStr1 = randStr(math.random(6, 12))
    local fakeStr2 = randStr(math.random(6, 12))
    local fakeStr3 = randStr(math.random(3, 5))
    local fakeStr4 = randStr(math.random(6, 12)):upper()
    local fakeStr5 = fakeStr1:sub(1, math.random(2, 4))
    local fakeNum1 = math.random(10000, 99999)
    local fakeNum2 = math.random(100, 999)
    local fakeAbs = math.random(2, 15)
    local fakeFloorIn = math.random(11, 49) / 10 + 0.7
    local fakeCeilIn = math.random(11, 49) / 10 + 0.2
    local fakeFloorOut = math.floor(fakeFloorIn)
    local fakeCeilOut = math.ceil(fakeCeilIn)
    local fakeWord = randStr(math.random(3, 6))
    local fakeSentence = randStr(math.random(4, 8)) .. " " .. fakeWord
    local fakeSubEnd = math.random(2, 4)
    local fakeSubResult = fakeStr1:sub(1, fakeSubEnd)
    local fakePairsCount = math.random(2, 5)
    local fakeSum = fakePairsCount * math.random(10, 30)
    local fakePerPart = fakeSum / fakePairsCount
    local fakeTonum = math.random(10, 99)
    local fakeSelectCount = math.random(2, 5)
    local fakeGuiLen = 36
    local fakeRandA = math.random(1, 50)
    local fakeRandB = math.random(51, 100)
    local fakeRandC = math.random(1, 50)
    local fakeRandD = math.random(51, 100)
    local fakeCharCode = math.random(65, 90)
    local fakeSortA = math.random(5, 9)
    local fakeSortB = math.random(1, 4)
    local fakeSortC = math.random(10, 15)

    local fakePairsTable = ""
    for i = 1, fakePairsCount do
        fakePairsTable = fakePairsTable .. string.char(96 + i) .. " = " .. i
        if i < fakePairsCount then fakePairsTable = fakePairsTable .. ", " end
    end

    local fakeInsertA = randStr(2)
    local fakeInsertB = randStr(2)
    local fakeConcatResult = fakeInsertA .. "," .. fakeInsertB
    local fakeMtKey = randStr(math.random(1, 3))
    local fakeRawKey = randStr(math.random(1, 3))
    local fakeRawVal = randStr(math.random(1, 3))

    local selectArgs = ""
    for i = 1, fakeSelectCount do
        selectArgs = selectArgs .. tostring(i)
        if i < fakeSelectCount then selectArgs = selectArgs .. ", " end
    end

    local sumArgs = ""
    for i = 1, fakePairsCount do
        sumArgs = sumArgs .. tostring(fakePerPart)
        if i < fakePairsCount then sumArgs = sumArgs .. ", " end
    end

    local fakeFindPos = fakeSentence:find(fakeWord, 1, true) or 1
    local fakeStr1Lower = fakeStr1:lower()
    local fakeStr1Upper = fakeStr1:upper()
    local fakeStr3Byte = fakeStr3:byte(1)
    local fakeStr3First = fakeStr3:sub(1,1)

    local code = [[
do
    local _rawget = rawget
    local _rawset = rawset
    local _rawequal = rawequal
    local _rawlen = rawlen
    local _type = type
    local _pcall = pcall
    local _setmt = setmetatable
    local _getmt = getmetatable
    local _tostring = tostring
    local _error = error
    local _select = select
    local _ipairs = ipairs
    local _pairs = pairs
    local _tonumber = tonumber
    local _unpack = unpack or table.unpack
    local _strfind = string.find
    local _strsub = string.sub
    local _strupper = string.upper
    local _strformat = string.format
    local _strbyte = string.byte
    local _strchar = string.char
    local _strlen = string.len
    local _strlower = string.lower
    local _strgmatch = string.gmatch
    local _strgsub = string.gsub
    local _strrep = string.rep
    local _strmatch = string.match
    local _strreverse = string.reverse
    local _mathabs = math.abs
    local _mathfloor = math.floor
    local _mathceil = math.ceil
    local _mathsqrt = math.sqrt
    local _mathmax = math.max
    local _mathmin = math.min
    local _mathrandom = math.random
    local _tableinsert = table.insert
    local _tableremove = table.remove
    local _tableconcat = table.concat
    local _tablesort = table.sort
    local _tablemove = table.move
    local _coroutinecreate = coroutine.create
    local _coroutineresume = coroutine.resume
    local _coroutinestatus = coroutine.status
    local _taskwait = task.wait
    local _newproxy = newproxy
    local _typeof = typeof

    local _protocol = "]] .. protocol .. [["

    local _crash = function()
        _error("Suspicious thing has been detected | Protocol " .. _protocol .. " | Trying to dump/decompile/env logging is not allowed | lightsec v2.1")
    end

    local _isExec = false
    _pcall(function()
        if getgenv ~= nil then _isExec = true end
        if syn ~= nil then _isExec = true end
        if fluxus ~= nil then _isExec = true end
        if XENO_LOADED ~= nil then _isExec = true end
        if solara ~= nil then _isExec = true end
        if is_solara_closure ~= nil then _isExec = true end
        if ronix ~= nil then _isExec = true end
        if getexecutorname ~= nil then _isExec = true end
        if identifyexecutor ~= nil then _isExec = true end
        if Synapse ~= nil then _isExec = true end
        if KRNL_LOADED ~= nil then _isExec = true end
        if is_sirhurt_closure ~= nil then _isExec = true end
    end)
    if not _isExec then return end

    local _fk1 = _strfind("]] .. fakeSentence .. [[", "]] .. fakeWord .. [[")
    local _fk2 = _strsub("]] .. fakeStr1 .. [[", 1, ]] .. fakeSubEnd .. [[)
    local _fk3 = _strupper("]] .. fakeStr1Lower .. [[")
    local _fk4 = _mathabs(-]] .. fakeAbs .. [[)
    local _fk5 = _mathfloor(]] .. string.format("%.1f", fakeFloorIn) .. [[)
    local _fk6 = _mathceil(]] .. string.format("%.1f", fakeCeilIn) .. [[)
    local _fk7 = _tostring(]] .. fakeNum1 .. [[)
    local _fk8 = _tonumber("]] .. tostring(fakeTonum) .. [[")
    local _fk9 = _select("#", ]] .. selectArgs .. [[)
    local _fk10 = _mathrandom(1, 100)
    local _fk11 = _strlen("]] .. fakeStr2 .. [[")
    local _fk12 = _strlower("]] .. fakeStr4 .. [[")
    local _fk13 = _strrep("]] .. fakeStr3 .. [[", 2)
    local _fk14 = _strreverse("]] .. fakeStr2 .. [[")
    local _fk15 = _mathmax(]] .. math.random(1,5) .. [[, ]] .. math.random(6,10) .. [[)
    local _fk16 = _mathmin(]] .. math.random(1,5) .. [[, ]] .. math.random(6,10) .. [[)
    local _fk17 = _mathsqrt(]] .. math.random(1,10)*math.random(1,10) .. [[)
    local _fk18 = _tableconcat({"]] .. fakeInsertA .. [[", "]] .. fakeInsertB .. [["}, ",")
    local _fkp = _newproxy(true)
    local _fkm = _getmt(_fkp)
    _fkm.__tostring = function() return "]] .. randStr(8) .. [[" end
    local _fkstr = _tostring(_fkp)

    local _envPassed = false
    _pcall(function()
        local _logSvc = game:GetService("LogService")
        local _randMsg = "[" .. _tostring(_mathrandom()) .. "]"
        local _conn
        _conn = _logSvc.MessageOut:Connect(function(msg, msgType)
            if msg == _randMsg and msgType == Enum.MessageType.MessageOutput then
                _envPassed = true
                _conn:Disconnect()
            end
        end)
        print(_randMsg)
        local _t = 0
        repeat
            _taskwait()
            _t = _t + 1
        until _envPassed or _t > 30
    end)
    if not _envPassed then _crash() end

    local _check = function()
        local _valid = true

        _pcall(function()
            local _suspicious = {
                "hookfunction","replaceclosure","getscriptbytecode",
                "decompile","getscripts","getsenv",
                "getscriptenviroment","getloadedmodules",
                "getrunningscripts","getconnections",
                "firesignal","getspecialinfo",
                "checkclosure","getcallingscript",
                "dumpstring","pebc","carbon",
                "getproto","getprotos","getupvalue",
                "getupvalues","setupvalue","getinfo",
                "getregistry","getstack"
            }
            for _, k in _ipairs(_suspicious) do
                if _rawget(_G, k) ~= nil then _valid = false end
            end
        end)

        _pcall(function()
            if _type(game) ~= "userdata" then _valid = false end
        end)

        _pcall(function()
            if game.ClassName ~= "DataModel" then _valid = false end
        end)

        _pcall(function()
            local _rs = game:GetService("RunService")
            if _typeof(_rs) ~= "Instance" then _valid = false end
        end)

        _pcall(function()
            if _type(workspace) ~= "userdata" then _valid = false end
        end)

        _pcall(function()
            if workspace.ClassName ~= "Workspace" then _valid = false end
        end)

        _pcall(function()
            local _fk = _newproxy(true)
            if _type(_fk) == _type(game) then
                local _cn = game.ClassName
                if not _cn or _cn == "" then _valid = false end
            end
        end)

        _pcall(function()
            local _strFuncs = {"byte","char","find","format","gmatch","gsub","len","lower","match","rep","reverse","sub","upper"}
            for _, k in _ipairs(_strFuncs) do
                if _type(string[k]) ~= "function" then _valid = false end
            end
        end)

        _pcall(function()
            local _mathFuncs = {"abs","ceil","floor","max","min","sqrt","random"}
            for _, k in _ipairs(_mathFuncs) do
                if math[k] == nil then _valid = false end
            end
        end)

        _pcall(function()
            local _sn = _tostring(_mathrandom(100000, 999999))
            local _mt = {}
            local _mtt = {__index = function(t, k) return _sn end}
            _setmt(_mt, _mtt)
            if _mt["]] .. fakeMtKey .. [["] ~= _sn then _valid = false end
            if _getmt(_mt) ~= _mtt then _valid = false end
        end)

        _pcall(function()
            local _pct = false
            local _pco = _pcall(function() _pct = true end)
            if not _pco or not _pct then _valid = false end
        end)

        _pcall(function()
            local _players = game:GetService("Players")
            if _typeof(_players) ~= "Instance" then _valid = false end
            if _players.ClassName ~= "Players" then _valid = false end
        end)

        _pcall(function()
            local _lighting = game:GetService("Lighting")
            if _typeof(_lighting) ~= "Instance" then _valid = false end
        end)

        _pcall(function()
            local _guid = game:GetService("HttpService"):GenerateGUID(false)
            if _type(_guid) ~= "string" then _valid = false end
            if #_guid ~= ]] .. fakeGuiLen .. [[ then _valid = false end
        end)

        _pcall(function()
            local _t = {}
            _rawset(_t, "]] .. fakeRawKey .. [[", "]] .. fakeRawVal .. [[")
            if _rawget(_t, "]] .. fakeRawKey .. [[") ~= "]] .. fakeRawVal .. [[" then _valid = false end
        end)

        _pcall(function()
            local _re = _rawequal("]] .. fakeStr3 .. [[", "]] .. fakeStr3 .. [[")
            if _re ~= true then _valid = false end
            local _re2 = _rawequal("]] .. fakeStr3 .. [[", "]] .. fakeStr5 .. [[")
            if _re2 ~= false then _valid = false end
        end)

        _pcall(function()
            local _n = _tonumber("]] .. tostring(fakeTonum) .. [[")
            if _n ~= ]] .. fakeTonum .. [[ then _valid = false end
            local _n2 = _tonumber("ff", 16)
            if _n2 ~= 255 then _valid = false end
        end)

        _pcall(function()
            local _s = _select("#", ]] .. selectArgs .. [[)
            if _s ~= ]] .. fakeSelectCount .. [[ then _valid = false end
        end)

        _pcall(function()
            local _arr = {]] .. sumArgs .. [[}
            local _sum = 0
            for _, v in _ipairs(_arr) do _sum = _sum + v end
            if _sum ~= ]] .. fakeSum .. [[ then _valid = false end
        end)

        _pcall(function()
            local _tbl = {]] .. fakePairsTable .. [[}
            local _cnt = 0
            for _ in _pairs(_tbl) do _cnt = _cnt + 1 end
            if _cnt ~= ]] .. fakePairsCount .. [[ then _valid = false end
        end)

        _pcall(function()
            local _uv = _unpack({1, 2, 3})
            if _uv ~= 1 then _valid = false end
        end)

        _pcall(function()
            local _ts = _tostring(]] .. fakeNum1 .. [[)
            if _ts ~= "]] .. tostring(fakeNum1) .. [[" then _valid = false end
        end)

        _pcall(function()
            local _camera = workspace.CurrentCamera
            if _typeof(_camera) ~= "Instance" then _valid = false end
            if _camera.ClassName ~= "Camera" then _valid = false end
        end)

        _pcall(function()
            local _f = Instance.new("Folder")
            if _typeof(_f) ~= "Instance" then _valid = false end
            if _f.ClassName ~= "Folder" then _valid = false end
            _f:Destroy()
        end)

        _pcall(function()
            local _v3 = Vector3.new(1, 2, 3)
            if _v3.X ~= 1 or _v3.Y ~= 2 or _v3.Z ~= 3 then _valid = false end
        end)

        _pcall(function()
            local _cf = CFrame.new(0, 0, 0)
            if _type(_cf) ~= "userdata" then _valid = false end
        end)

        _pcall(function()
            local _col = Color3.new(1, 0, 0)
            if _col.R ~= 1 or _col.G ~= 0 or _col.B ~= 0 then _valid = false end
        end)

        _pcall(function()
            local _ud2 = UDim2.new(0, 100, 0, 100)
            if _ud2.X.Offset ~= 100 then _valid = false end
        end)

        _pcall(function()
            local _tick = tick()
            if _type(_tick) ~= "number" then _valid = false end
            if _tick <= 0 then _valid = false end
        end)

        _pcall(function()
            local _tbl2 = {}
            local _mt2 = {__newindex = function(t, k, v) _rawset(t, k, v * 2) end}
            _setmt(_tbl2, _mt2)
            _tbl2.x = 5
            if _rawget(_tbl2, "x") ~= 10 then _valid = false end
        end)

        _pcall(function()
            local _mt3 = {}
            local _mt3t = {__len = function() return ]] .. fakeNum2 .. [[ end}
            _setmt(_mt3, _mt3t)
            if #_mt3 ~= ]] .. fakeNum2 .. [[ then _valid = false end
        end)

        _pcall(function()
            local _mt4 = _setmt({}, {__eq = function(a, b) return true end})
            local _mt5 = _setmt({}, _getmt(_mt4))
            if not (_mt4 == _mt5) then _valid = false end
        end)

        _pcall(function()
            local _co = _coroutinecreate(function() return ]] .. fakeNum2 .. [[ end)
            if _type(_co) ~= "thread" then _valid = false end
            local ok, val = _coroutineresume(_co)
            if not ok or val ~= ]] .. fakeNum2 .. [[ then _valid = false end
        end)

        _pcall(function()
            local _tableFuncs = {"insert","remove","concat","sort","move"}
            for _, k in _ipairs(_tableFuncs) do
                if _type(table[k]) ~= "function" then _valid = false end
            end
        end)

        _pcall(function()
            local _abs = _mathabs(-]] .. fakeAbs .. [[)
            if _abs ~= ]] .. fakeAbs .. [[ then _valid = false end
            local _floor = _mathfloor(]] .. string.format("%.1f", fakeFloorIn) .. [[)
            if _floor ~= ]] .. fakeFloorOut .. [[ then _valid = false end
            local _ceil = _mathceil(]] .. string.format("%.1f", fakeCeilIn) .. [[)
            if _ceil ~= ]] .. fakeCeilOut .. [[ then _valid = false end
        end)

        _pcall(function()
            local _find = _strfind("]] .. fakeSentence .. [[", "]] .. fakeWord .. [[")
            if _find ~= ]] .. fakeFindPos .. [[ then _valid = false end
            local _sub = _strsub("]] .. fakeStr1 .. [[", 1, ]] .. fakeSubEnd .. [[)
            if _sub ~= "]] .. fakeSubResult .. [[" then _valid = false end
            local _upper = _strupper("]] .. fakeStr1Lower .. [[")
            if _upper ~= "]] .. fakeStr1Upper .. [[" then _valid = false end
        end)

        _pcall(function()
            local _ti = {}
            _tableinsert(_ti, "]] .. fakeInsertA .. [[")
            _tableinsert(_ti, "]] .. fakeInsertB .. [[")
            if #_ti ~= 2 then _valid = false end
            _tableremove(_ti, 1)
            if #_ti ~= 1 then _valid = false end
            if _ti[1] ~= "]] .. fakeInsertB .. [[" then _valid = false end
        end)

        _pcall(function()
            local _concat = _tableconcat({"]] .. fakeInsertA .. [[","]] .. fakeInsertB .. [["}, ",")
            if _concat ~= "]] .. fakeConcatResult .. [[" then _valid = false end
        end)

        _pcall(function()
            local _np = _newproxy(true)
            local _npm = _getmt(_np)
            local _npval = ]] .. math.random(100,999) .. [[
            _npm.__index = function() return _npval end
            _npm.__len = function() return _npval end
            if _getmt(_np) ~= _npm then _valid = false end
        end)

        _pcall(function()
            local _gc1 = _mathrandom(]] .. fakeRandA .. [[, ]] .. fakeRandB .. [[)
            local _gc2 = _mathrandom(]] .. fakeRandC .. [[, ]] .. fakeRandD .. [[)
            if _type(_gc1) ~= "number" then _valid = false end
            if _type(_gc2) ~= "number" then _valid = false end
            if _gc1 < 1 or _gc2 < 1 then _valid = false end
        end)

        _pcall(function()
            local _rl = _rawlen({1,2,3,4,5})
            if _rl ~= 5 then _valid = false end
            local _rl2 = _rawlen("]] .. fakeStr1 .. [[")
            if _rl2 ~= ]] .. #fakeStr1 .. [[ then _valid = false end
        end)

        _pcall(function()
            local _ws = game:GetService("Workspace")
            if _ws ~= workspace then _valid = false end
        end)

        _pcall(function()
            local _np2 = _newproxy(false)
            if _type(_np2) ~= "userdata" then _valid = false end
            if _getmt(_np2) ~= nil then _valid = false end
        end)

        _pcall(function()
            local _sv = _strbyte("]] .. fakeStr3First .. [[")
            if _sv ~= ]] .. fakeStr3Byte .. [[ then _valid = false end
        end)

        _pcall(function()
            local _sc2 = _strchar(]] .. fakeCharCode .. [[)
            if _type(_sc2) ~= "string" then _valid = false end
            if #_sc2 ~= 1 then _valid = false end
        end)

        _pcall(function()
            local _gm = {}
            for w in _strgmatch("]] .. fakeInsertA .. [[ ]] .. fakeInsertB .. [[", "%S+") do
                _tableinsert(_gm, w)
            end
            if #_gm ~= 2 then _valid = false end
        end)

        _pcall(function()
            local _gs = _strgsub("]] .. fakeStr3 .. [[", ".", function(c) return c end)
            if _gs ~= "]] .. fakeStr3 .. [[" then _valid = false end
        end)

        _pcall(function()
            local _sm = _strmatch("]] .. fakeStr1 .. [[", "^%a+$")
            if _sm ~= "]] .. fakeStr1 .. [[" then _valid = false end
        end)

        _pcall(function()
            local _coo = _coroutinecreate(function() end)
            local _st = _coroutinestatus(_coo)
            if _st ~= "suspended" then _valid = false end
        end)

        _pcall(function()
            local _tabSort = {]] .. fakeSortA .. [[, ]] .. fakeSortB .. [[, ]] .. fakeSortC .. [[}
            _tablesort(_tabSort)
            if _tabSort[1] > _tabSort[2] then _valid = false end
            if _tabSort[2] > _tabSort[3] then _valid = false end
        end)

        _pcall(function()
            local _sfmt = _strformat("%d", ]] .. fakeNum2 .. [[)
            if _sfmt ~= "]] .. tostring(fakeNum2) .. [[" then _valid = false end
        end)

        _pcall(function()
            local _svc = game:GetService("UserInputService")
            if _typeof(_svc) ~= "Instance" then _valid = false end
        end)

        if not _valid then _crash() end
    end

    _check()

    _pcall(function()
        local _rs = game:GetService("RunService")
        _rs.Heartbeat:Connect(function()
            _check()
        end)
    end)

    local _obj = _setmt({}, {__tostring = _crash})
    _obj[_mathrandom(1, 100)] = _obj
    ;(function() end)(_obj)
end
    ]]

    local parsed = Parser:new({LuaVersion = Enums.LuaVersion.Lua51}):parse(code);
    local doStat = parsed.body.statements[1];
    doStat.body.scope:setParent(ast.body.scope);
    table.insert(ast.body.statements, 1, doStat);

    return ast;
end

return AntiTamper;
