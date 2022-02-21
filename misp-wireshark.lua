local my_info = {
    version = "1.0",
    author  = "Sami Mokaddem, CIRCL - Computer Incident Response Center Luxembourg",
    email   = "sami.mokaddem@circl.lu",
    license = "AGPLv2",
    details = [[
        This is a plugin for Wireshark, to output data in the MISP Format.
        Currently support the following:
            - `network-connection` from tcp
            - `http-request` from tcp.http, including HTTP payloads
            - `dns-record` from udp.dns
    ]],
    repository = "https://github.com/MISP/misp-wireshark"
}
set_plugin_info(my_info)

local LuaMISP = require 'lib.LuaMISP.LuaMISP'
local mispHelper = require 'mispHelper'
local wiresharkUtils = require 'mispWiresharkUtils'

 -- this only works in wireshark UI
 if not gui_enabled() then return end


local get_http                      = Field.new("http")
local get_http_useragent            = Field.new("http.user_agent")
local get_http_host                 = Field.new("http.host")
local get_http_file_data            = Field.new("http.file_data")
local get_http_request_method       = Field.new("http.request.method")
local get_http_request_uri          = Field.new("http.request.uri")
local get_http_response_in_frame    = Field.new("http.response_in")
local get_http_cookie               = Field.new("http.cookie")
local get_http_referer              = Field.new("http.referer")
local get_http_content_type         = Field.new("http.content_type")
local get_http_content_length       = Field.new("http.content_length")
local get_http_server               = Field.new("http.server")
local get_http_text                 = Field.new("text")

local get_frame_number              = Field.new("frame.number")
local get_tcp                       = Field.new("tcp")
local get_stream_index              = Field.new("tcp.stream")
local get_community_id              = Field.new("communityid")

local get_dns                       = Field.new("dns")
local get_dns_query_name            = Field.new("dns.qry.name")
local get_dns_query_type            = Field.new("dns.qry.type")
local get_dns_resp_class            = Field.new("dns.resp.class")
local get_dns_mx                    = Field.new("dns.mx.mail_exchange")
local get_dns_ptr                   = Field.new("dns.ptr.domain_name")
local get_dns_a                     = Field.new("dns.a")
local get_dns_aaaa                  = Field.new("dns.aaaa")
local get_dns_ns                    = Field.new("dns.ns")


local SUPPORT_COMMUNITY_ID = false
local INCLUDE_HTTP_PAYLOAD = true
local EXPORT_FILEPATH = ''
local FILTERS = ''
local TAGS = {}
local summary = {}
local final_output


local function menuable_tap(main_filter)
    -- Declare the window we will use
    local tw = TextWindow.new("MISP format export result")
    
    local tcp_streams = {}
    local http_payloads = {}
    local http_packets = {}
    local dns_queries = {}

    -- local filters = get_filter() or '' -- get_filter() function is not working anymore. We rely on user provided filter instead
    FILTERS = main_filter
    local tap = Listener.new(nill, FILTERS);

    local function remove()
        -- this way we remove the listener that otherwise will remain running indefinitely
        tap:remove();
    end
    
    -- we tell the window to call the remove() function when closed
    tw:set_atclose(remove)
    -- add buttons to the window
    tw:add_button("Save to file", function () wiresharkUtils.save_to_file(final_output, EXPORT_FILEPATH, tw) end)


    -- this function will be called once for each packet
    function tap.packet(pinfo,tvb)
        local frame_number = tonumber(tostring(get_frame_number()))
        local community_id = nil
        if SUPPORT_COMMUNITY_ID then
            community_id = tostring(get_community_id())
        end

        local tcp = get_tcp()
        if tcp then
            local stream_index = tonumber(tostring(get_stream_index()))
            local index = stream_index + 1
            local contextualData = {
                pinfo = pinfo,
                community_id = community_id,
                frame_number = frame_number,
                stream_index = stream_index,
                index = index,
            }
            handleTCP(tcp_streams, contextualData)

            local http = get_http()
            if http then
                handleHTTP(http_payloads, http_packets, contextualData)
            end
        end

        local dns = get_dns()
        if dns then
            local contextualData = {
                pinfo = pinfo,
            }
            handleDNS(dns_queries, contextualData)
        end
    end
 
    -- this function will be called once every few seconds to update our window
    function tap.draw()
        tw:clear()
        local collected_data = {
            tcp_streams = tcp_streams,
            http_payloads = http_payloads,
            http_packets = http_packets,
            dns_queries = dns_queries,
        }
        local misp_format = generate_misp_format(collected_data)
        final_output = misp_format
        local output_too_large = #misp_format / 1024 > 500 -- Output larger than ~500k
        if not output_too_large then
            tw:set(misp_format)
        else
            local summary = generate_summary()
            local text = ''
            if (FILTERS == '') then
                text = text .. '[warning] No filters have been set. The whole capture has been processed.\n'
            end
            text = text .. '[info] Output is too large to be displayed.\n\nOutput content:\n'
            text = text .. summary
            tw:set(text)
        end
    end


    -- this function will be called whenever a reset is needed
    -- e.g. when reloading the capture file
    function tap.reset()
        tw:clear()
        tcp_streams = {}
        http_payloads = {}
    end

    -- Ensure that all existing packets are processed.
    retap_packets()
end


local function dialog_options()
    if wiresharkUtils.check_wireshark_version() then
        SUPPORT_COMMUNITY_ID = true
    else
        SUPPORT_COMMUNITY_ID = false
    end
    local working_dir = get_working_directory()
    local function dialog_export_func(main_filter, include_http_payload, export_filepath, tags_text)
        INCLUDE_HTTP_PAYLOAD = getBoolFromString(include_http_payload, true)
        if export_filepath ~= '' then
            EXPORT_FILEPATH = export_filepath
        else
            EXPORT_FILEPATH = working_dir
        end
        TAGS = getTableFromString(tags_text)
        menuable_tap(main_filter)
    end
    new_dialog(
        "MISP format export options",
        dialog_export_func,
        "Main filter",
        "Include HTTP payload? (Y/n)",
        string.format("Export path (%s)", working_dir),
        "Tags (comma-separated)"
        -- {name="Main filter", value=get_filter()}, -- feature is not working according to the doc. Keep it in case it gets fixed.
        -- {name="Include HTTP payload? (Y/n)", value="Y"},
        -- {name="Export file path", value=working_dir},
        -- {name="Tags (comma-separated)", value="tlp:white,extraction-origin:wireshark"}
    )
    if not SUPPORT_COMMUNITY_ID then
        wiresharkUtils.make_splash("Wireshark version is too old to export the community-id!\nThis script needs Wireshark version 3.3.1 or higher to include the community-id.\n")
    end
end

register_menu("MISP: Export to MISP format", dialog_options, MENU_TOOLS_UNSORTED)

function getBoolFromString(include_http_payload, default)
    if include_http_payload == '' then
        return default
    else
        if include_http_payload == 'y' or include_http_payload == 'Y' or include_http_payload == '1' then
            return true
        else
            return false
        end
    end
end

function  getTableFromString(string)
    local tag_table = {}
    for tag in string.gmatch(string, "[^,]+") do
        table.insert(tag_table, tag)
    end
    return tag_table
end

function get_working_directory()
    return os.getenv("PWD") or io.popen("echo $PWD"):read("*all")
end


function generate_misp_format(collected_data)
    local tcp_streams = collected_data.tcp_streams
    local http_payloads = collected_data.http_payloads
    local http_packets = collected_data.http_packets
    local dns_queries = collected_data.dns_queries
    summary = {
        network_connection = 0,
        http_request = 0,
        http_payload = 0,
        http_payload_total_size = 0,
        dns_record = 0,
    }

    local event = Event:new({title='Wireshark test event'})

    local all_network_objects = {}
    for stream_id, tcp_stream in pairs(tcp_streams) do
        local network_object = mispHelper.generate_misp_network_connection_object_for_stream(tcp_stream)
        all_network_objects[stream_id] = network_object
        event:addObject(network_object)
        summary['network_connection'] = summary['network_connection'] + 1
    end

    for frame_number, http_packet in pairs(http_packets) do
        local stream_id = http_packet['stream_id']
        local http_request_object = mispHelper.generate_misp_http_request_object(http_packet)
        event:addObject(http_request_object)
        summary['http_request'] = summary['http_request'] + 1
        all_network_objects[stream_id]:addReference(http_request_object, 'contains')
        if INCLUDE_HTTP_PAYLOAD then
            if http_payloads[stream_id] then
                if http_payloads[stream_id][frame_number] then
                    local payload_object = mispHelper.generate_misp_file_object_for_payload(stream_id, frame_number, http_payloads[stream_id][frame_number])
                    all_network_objects[stream_id]:addReference(payload_object, 'contains')
                    http_request_object:addReference(payload_object, 'contains')
                    event:addObject(payload_object)
                    summary['http_payload'] = summary['http_payload'] + 1
                    a_attachment = payload_object:getAttributeByName('size-in-bytes')
                    if a_attachment ~= nil then
                        summary['http_payload_total_size'] = summary['http_payload_total_size'] + a_attachment.value
                    end
                end
            end
        end
    end

    for query_name, dns_query in pairs(dns_queries) do
        local o_dns = mispHelper.generate_misp_dns_record_object(query_name, dns_query)
        event:addObject(o_dns)
        summary['dns_record'] = summary['dns_record'] + 1
    end
    local output = event:toJson()
    return output
end

function generate_summary()
    local text = ''
    for key, amount in pairs(summary) do
        if key == 'http_payload_total_size' then
            text = text .. string.format('- %s: %s\n', key, wiresharkUtils.humanizeFilesize(tonumber(amount)))
        else
            text = text .. string.format('- %s: %s\n', key, amount)
        end
    end
    return text
end

-- Tap handler
---------------

function handleTCP(tcp_streams, contextualData)
    local pinfo = contextualData.pinfo
    local stream_index = contextualData.stream_index
    local index = contextualData.index
    local start_time = tonumber(pinfo.abs_ts)
    local tcp_srcport = tonumber(pinfo.src_port)
    local tcp_dstport = tonumber(pinfo.dst_port)
    local tcp_srcip = tostring(pinfo.src)
    local tcp_dstip = tostring(pinfo.dst)

    if tcp_streams[index] == nil then
        tcp_streams[index] = {
            tcp_stream = tcp_stream,
            start_time = start_time,
            stop_time = start_time,
            tcp_src_port = tcp_srcport,
            tcp_dst_port = tcp_dstport,
            tcp_src_ip = tcp_srcip,
            tcp_dst_ip = tcp_dstip,
            community_id = contextualData.community_id,
            flow_duration = 0,
            packet_count = 1,
        }
    else
        local stream = tcp_streams[index]
        stream.stop_time = start_time
        stream.flow_duration = stream.stop_time - stream.start_time
        stream.packet_count = stream.packet_count + 1
    end
end

function handleHTTP(http_payloads, http_packets, contextualData)
    local index = contextualData.index
    local frame_number = contextualData.frame_number
    local tcp_srcip = tostring(contextualData.pinfo.src)
    local tcp_dstip = tostring(contextualData.pinfo.dst)

    local http_file_data = get_http_file_data()
    local http_response_in_frame = get_http_response_in_frame()
    if http_response_in_frame then
        http_response_in_frame = tonumber(http_response_in_frame)
    end
    local method = get_http_request_method()
    if method then
        method = tostring(method)
    end
    local host = get_http_host()
    if host then
        host = tostring(host)
    end
    local uri = get_http_request_uri()
    if uri then
        uri = tostring(uri)
    end
    local user_agent = get_http_useragent()
    if user_agent then
        user_agent = tostring(user_agent)
    end
    local refere = get_http_referer()
    if refere then
        refere = tostring(refere)
    end
    local content_type = get_http_content_type()
    if content_type then
        content_type = tostring(content_type)
    end
    local content_length = get_http_content_length()
    if content_length then
        content_length = tostring(content_length)
    end
    local cookie = get_http_cookie()
    if cookie then
        cookie = tostring(cookie)
    end
    local server = get_http_server()
    if server then
        server = tostring(server)
    end
    local text = get_http_text()
    if text then
        text = tostring(text)
    end

    if http_file_data then
        if http_payloads[index] == nil then
            http_payloads[index] = {}
        end
        local raw_data = {
            len = http_file_data.range:bytes():len(),
            rawData = http_file_data.range:bytes():raw(),
            name = http_file_data.name,
        }
        http_payloads[index][frame_number] = raw_data
    end

    if http_packets[frame_number] == nil then
        http_packets[frame_number] = {
            stream_id               = index,
            http_response_in_frame  = http_response_in_frame,
            http_file_data          = http_file_data,
            host                    = host,
            method                  = method,
            uri                     = uri,
            user_agent              = user_agent,
            refere                  = refere,
            content_type            = content_type,
            content_length          = content_length,
            cookie                  = cookie,
            server                  = server,
            http_text               = text,
            tcp_src_ip              = tcp_srcip,
            tcp_dst_ip              = tcp_dstip,
        }
    end
end

-- Collect DNS query and response. If multiple same queries are in the capture, the last takes precedence
-- /!\ In case multiple replies are returned (e.g. multiple mx records) in the same query, only the first one is returned
-- This is a limitation from Wireshark's `Field.new("dns.mx.mail_exchange")`
-- If we want to have all of them, a new dissector should probably be implemented
function handleDNS(dns_queries, contextualData)
    local query_name = get_dns_query_name()
    if query_name then
        query_name = tostring(query_name)
    else
        return
    end

    if dns_queries[query_name] == nil then
        dns_queries[query_name] = {}
    end

    local first_seen = tonumber(contextualData.pinfo.abs_ts)
    dns_queries[query_name]['first_seen'] = first_seen

    local dns_query_type = get_dns_query_type()
    if dns_query_type then
        dns_queries[query_name]['dns_query_type'] = tostring(dns_query_type)
    end
    local dns_resp_class = get_dns_resp_class()
    if dns_resp_class then
        dns_queries[query_name]['dns_resp_class'] = tostring(dns_resp_class)
    end
    local dns_mx = get_dns_mx()
    if dns_mx then
        dns_queries[query_name]['dns_mx'] = tostring(dns_mx)
    end
    local dns_ptr = get_dns_ptr()
    if dns_ptr then
        dns_queries[query_name]['dns_ptr'] = tostring(dns_ptr)
    end
    local dns_a = get_dns_a()
    if dns_a then
        dns_queries[query_name]['dns_a'] = tostring(dns_a)
    end
    local dns_aaaa = get_dns_aaaa()
    if dns_aaaa then
        dns_queries[query_name]['dns_aaaa'] = tostring(dns_aaaa)
    end
    local dns_ns = get_dns_ns()
    if dns_ns then
        dns_queries[query_name]['dns_ns'] = tostring(dns_ns)
    end
end
