
unpack = unpack or table.unpack;

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local visitast = require("prometheus.visitast");
local util     = require("prometheus.util")

local AstKind = Ast.AstKind;

local NumbersToExpressions = Step:extend();
NumbersToExpressions.Description = "This Step Converts number Literals to Expressions";
NumbersToExpressions.Name = "Numbers To Expressions";

NumbersToExpressions.SettingsDescriptor = {
    Treshold = {
        type = "number",
        default = 1,
        min = 0,
        max = 1,
    },
    InternalTreshold = {
        type = "number",
        default = 0.2,
        min = 0,
        max = 0.8,
    }
}
-- ai comments lol 
local FAKE_STRINGS = {
    "you thought you could deobf this? cute",
    "i wrote this in my sleep and you still cant read it",
    "every minute you spend deobfing this, i spend improving it",
    "lightSec v2.2 - good luck with that",
    "your deobfer called, it said it gives up",
    "404: your skills not found",
    "imagine spending hours on this lmaooo",
    "this obfuscation has more layers than your personality",
    "still trying? respect the dedication at least",
    "lightcate encryption: because your curiosity is adorable",
    "you are not him bro",
    "the more you look, the less you understand",
    "protected by lightcate v2.2",
    "bro really said let me deobf this real quick",
}

function NumbersToExpressions:init(settings)
end

function NumbersToExpressions:CreateNumberExpression(val, depth)
    if depth > 0 and math.random() >= self.InternalTreshold or depth > 15 then
        return Ast.NumberExpression(val)
    end

    local generators = util.shuffle({unpack(self.ExpressionGenerators)});
    for i, generator in ipairs(generators) do
        local node = generator(val, depth + 1);
        if node then
            return node;
        end
    end

    return Ast.NumberExpression(val)
end

function NumbersToExpressions:apply(ast)
    self.ExpressionGenerators = {
        function(val, depth)
            if type(val) ~= "number" then return false end
            local val2 = math.random(1, 100)
            local diff = val - val2
            if tonumber(tostring(diff)) + tonumber(tostring(val2)) ~= val then return false end
            return Ast.AddExpression(Ast.NumberExpression(diff), Ast.NumberExpression(val2), false)
        end,
        function(val, depth)
            if type(val) ~= "number" then return false end
            local val2 = math.random(1, 100)
            local diff = val + val2
            if tonumber(tostring(diff)) - tonumber(tostring(val2)) ~= val then return false end
            return Ast.SubExpression(Ast.NumberExpression(diff), Ast.NumberExpression(val2), false)
        end,
    }

    local topStr = "This file is protected by LightSec v2.2 https://discord.gg/nHdWn6xR8J";
    local topNode = Ast.StringExpression(topStr);
    local topScope = require("prometheus.scope"):new(ast.body.scope);
    local topId = topScope:addVariable();
    local topDecl = Ast.LocalVariableDeclaration(topScope, {topId}, {topNode});
    local topBlock = Ast.DoStatement(Ast.Block({topDecl}, topScope));
    table.insert(ast.body.statements, 1, topBlock);

    for _ = 1, math.random(4, 8) do
        local fakeStr = FAKE_STRINGS[math.random(1, #FAKE_STRINGS)];
        local fakeNode = Ast.StringExpression(fakeStr);
        local fakeScope = require("prometheus.scope"):new(ast.body.scope);
        local fakeId = fakeScope:addVariable();
        local fakeDecl = Ast.LocalVariableDeclaration(fakeScope, {fakeId}, {fakeNode});
        local fakeBlock = Ast.DoStatement(Ast.Block({fakeDecl}, fakeScope));
        local pos = math.random(math.floor(#ast.body.statements / 2), math.max(math.floor(#ast.body.statements / 2), #ast.body.statements));
        table.insert(ast.body.statements, pos, fakeBlock);
    end

    visitast(ast, nil, function(node, data)
        if node.kind == AstKind.NumberExpression then
            if math.random() <= self.Treshold then
                return self:CreateNumberExpression(node.value, 0);
            end
        end
    end)
end

return NumbersToExpressions;
