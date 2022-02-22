
local utils = {}
-- https://gist.github.com/tylerneylon/81333721109155b2d244
function utils.deepcopy(obj)
    if type(obj) ~= 'table' then return obj end
    local res = setmetatable({}, getmetatable(obj))
    for k, v in pairs(obj) do res[utils.deepcopy(k)] = utils.deepcopy(v) end
    return res
end

function utils.save_to_file(content, export_filepath, tw)
    local now = os.time(os.date("!*t"))
    local filename = string.format("wireshark-misp-%s.json", now)
    local full_path
    if export_filepath ~= '' then
        full_path = string.format('%s/%s', export_filepath, filename)
    else
        full_path = string.format('%s', export_filepath, filename)
    end
    local file = assert(io.open(full_path, "w"))
    file:write(content)
    file:close()
    utils.make_splash(string.format("Saved %s at %s", filename, export_filepath))
    if tw then
        tw:close()
    end
end

function utils.make_splash(text)
    if gui_enabled() then
        local splash = TextWindow.new("MISP Export error");
        splash:set(text)
        return splash
    else
        print(text)
    end
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

function utils.humanizeFilesize(size)
    if (size == 0) then
        return "0.00 B"
    end

    local sizes = {'B', 'kB', 'MB', 'GB', 'TB', 'PB'}
    local e = math.floor(math.log(size, 1024))
    local significant = math.floor(size/math.pow(1024, e), 2)
    local remaining = math.floor(size/math.pow(1024, e-1), 2) % 1024
    local text = string.format("%s.%s%s", significant, remaining, sizes[e])
    return text
end

function utils.parse_args(args)
    local t = {}
    for i, arg in ipairs(args) do
        local matches = string.gmatch(arg, "([^=]+)=(.+)")
        local k, v = matches()
        if k ~= '' and v ~= '' then
            t[k] = v
        end
    end
    return t
end

return utils