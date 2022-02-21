
local utils = {}
-- https://gist.github.com/tylerneylon/81333721109155b2d244
function utils.deepcopy(obj)
    if type(obj) ~= 'table' then return obj end
    local res = setmetatable({}, getmetatable(obj))
    for k, v in pairs(obj) do res[utils.deepcopy(k)] = utils.deepcopy(v) end
    return res
end

function utils.save_to_file(content, tw)
    local now = os.time(os.date("!*t"))
    local filename = string.format("wireshark-misp-%s.json", now)
    local full_path
    if EXPORT_FILEPATH ~= '' then
        full_path = string.format('%s/%s', EXPORT_FILEPATH, filename)
    else
        full_path = string.format('%s', EXPORT_FILEPATH, filename)
    end
    local file = assert(io.open(full_path, "w"))
    file:write(content)
    file:close()
    utils.make_splash(string.format("Saved %s at\n%s", filename, EXPORT_FILEPATH))
    if tw then
        tw:close()
    end
end

function utils.make_splash(text)
    local splash = TextWindow.new("MISP Export error");
    splash:set(text)
    return splash
end

-- verify tshark/wireshark version is new enough - needs to be 3.3.1+ as community was introduced in this version
function utils.check_wireshark_version()
    local version_ok = true
    local major, minor, micro = 0, 0, 0
    major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
    if (
        tonumber(major) < 3) or
        ((tonumber(major) <= 3) and (tonumber(minor) < 3)) or
        ((tonumber(major) <= 3) and (tonumber(minor) <= 3) and (tonumber(micro) < 1)
    ) then
        version_ok = false
    end
    return version_ok
end


return utils