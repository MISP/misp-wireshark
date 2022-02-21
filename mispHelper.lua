
local utils = require 'mispWiresharkUtils'

local mispHelper = {}

-- Registed used MISP object templates
--------------------------------------

local NETWORK_CONNECTION_TEMPLATE = {
    name                = "network-connection",
    description         = "A local or remote network connection.",
    template_uuid       = "af16764b-f8e5-4603-9de1-de34d272f80b",
    template_version    = "3"
}
NETWORK_CONNECTION_TEMPLATE['meta-category'] = "network"
function get_network_connection_template()
    return utils.deepcopy(NETWORK_CONNECTION_TEMPLATE)
end

local FILE_TEMPLATE = {
    name                = "file",
    description         = "File object describing a file with meta-information",
    template_uuid       = "688c46fb-5edb-40a3-8273-1af7923e2215",
    template_version    = "24"
}
FILE_TEMPLATE['meta-category'] = "file"
function get_file_template()
    return utils.deepcopy(FILE_TEMPLATE)
end

local HTTP_REQUEST_TEMPLATE = {
    name                = "http-request",
    description         = "A single HTTP request header",
    template_uuid       = "b4a8d163-8110-4239-bfcf-e08f3a9fdf7b",
    template_version    = "4"
}
HTTP_REQUEST_TEMPLATE['meta-category'] = "network"
function get_http_request_template()
    return utils.deepcopy(HTTP_REQUEST_TEMPLATE)
end

local DNS_RECORD_TEMPLATE = {
    name                = "dns-record",
    description         = "A set of DNS records observed for a specific domain.",
    template_uuid       = "f023c8f0-81ab-41f3-9f5d-fa597a34a9b9",
    template_version    = "2"
}
DNS_RECORD_TEMPLATE['meta-category'] = "network"
function get_dns_record_template()
    return utils.deepcopy(DNS_RECORD_TEMPLATE)
end

local PASSIVE_DNS_TEMPLATE = {
    name                = "passive-dns",
    description         = "Passive DNS records as expressed in draft-dulaunoy-dnsop-passive-dns-cof-07. See https://tools.ietf.org/id/draft-dulaunoy-dnsop-passive-dns-cof-07.html",
    template_uuid       = "b77b7b1c-66ab-4a41-8da4-83810f6d2d6c",
    template_version    = "5"
}
PASSIVE_DNS_TEMPLATE['meta-category'] = "network"
function get_passive_dns_template()
    return utils.deepcopy(PASSIVE_DNS_TEMPLATE)
end

-- Actual functions converting data collected from the tap into LuaMISP entities
---------------------------------------------------------------------------------

function mispHelper.generate_misp_network_connection_object_for_stream(tcp_stream)
    local a_src_port     = Attribute:new({object_relation='src-port', type='port', value=tcp_stream['tcp_src_port']})
    local a_dst_port     = Attribute:new({object_relation='dst-port', type='port', value=tcp_stream['tcp_dst_port']})
    local a_ip_src       = Attribute:new({object_relation='ip-src', type='ip-src', value=tcp_stream['tcp_src_ip']})
    local a_ip_dst       = Attribute:new({object_relation='ip-dst', type='ip-dst', value=tcp_stream['tcp_dst_ip']})
    local a_layer3       = Attribute:new({object_relation='layer3-protocol', type='text', value='IP'})
    local a_layer4       = Attribute:new({object_relation='layer4-protocol', type='text', value='TCP'})
    local a_layer7       = Attribute:new({object_relation='layer7-protocol', type='text', value='HTTP'})
    local a_community_id = Attribute:new({object_relation='community-id', type='community-id', value=tcp_stream['community_id']})
    local first_seen     = os.date("%Y-%m-%d %X", tcp_stream['start_time'])
    local last_seen      = os.date("%Y-%m-%d %X", tcp_stream['stop_time'])

    if TAGS then
        a_src_port:addTags(TAGS)
        a_dst_port:addTags(TAGS)
        a_ip_src:addTags(TAGS)
        a_ip_dst:addTags(TAGS)
    end

    local o_network_connection = Object:new(get_network_connection_template())
    o_network_connection.first_seen = first_seen
    o_network_connection.last_seen = last_seen
    o_network_connection:addAttributes({
        a_src_port,
        a_dst_port,
        a_ip_src,
        a_ip_dst,
        a_layer3,
        a_layer4,
        a_layer7,
        a_community_id
    })
    return o_network_connection
end

function mispHelper.generate_misp_file_object_for_payload(stream_id, frame_number, http_payload)
    local payload_name = string.format("payload-%s-%s", stream_id, frame_number)
    local a_attachment = Attribute:new({type='attachment', object_relation='attachment', value=payload_name, data=http_payload.rawData})
    local a_filename = Attribute:new({type='filename', object_relation='filename', value=payload_name, disable_correlation=1})
    local a_fsize = Attribute:new({type='size-in-bytes', object_relation='size-in-bytes', value=http_payload.len})
    local o_payload = Object:new(get_file_template())
    o_payload.comment = http_payload.name
    if TAGS then
        a_attachment:addTags(TAGS)
        a_filename:addTags(TAGS)
    end
    o_payload:addAttributes({
        a_attachment,
        a_filename,
        a_fsize,
    })
    return o_payload
end

function mispHelper.generate_misp_http_request_object(http_request)
    local a_content_type    = Attribute:new({object_relation='content-type', type='other', value=http_request['content_type']})
    local a_cookie          = Attribute:new({object_relation='cookie', type='port', value=http_request['cookie']})
    local a_ip_dst          = Attribute:new({object_relation='ip-dst', type='ip-dst', value=http_request['tcp_dst_ip']})
    local a_ip_src          = Attribute:new({object_relation='ip-src', type='ip-src', value=http_request['tcp_src_ip']})
    local a_method          = Attribute:new({object_relation='method', type='http-method', value=http_request['method']})
    local a_refere          = Attribute:new({object_relation='referer', type='other', value=http_request['refere']})
    local a_uri             = Attribute:new({object_relation='uri', type='uri', value=http_request['uri']})
    local a_user_agent      = Attribute:new({object_relation='user-agent', type='user-agent', value=http_request['user_agent']})
    local a_content_length  = Attribute:new({object_relation='content-length', type='other', value=http_request['content_length']}) -- unused
    local a_server          = Attribute:new({object_relation='server', type='text', value=http_request['server']}) -- unused
    local a_text            = Attribute:new({object_relation='text', type='text', value=http_request['text']}) -- unused
    local first_seen        = os.date("%Y-%m-%d %X", http_request['start_time'])
    local last_seen         = os.date("%Y-%m-%d %X", http_request['stop_time'])

    if TAGS and a_uri ~= nil then
        a_uri:addTags(TAGS)
    end
    if TAGS and a_text ~= nil then
        a_text:addTags(TAGS)
    end
    if TAGS and a_ip_dst ~= nil then
        a_ip_dst:addTags(TAGS)
    end

    local o_http_request = Object:new(get_http_request_template())
    o_http_request.first_seen = first_seen
    o_http_request.last_seen = last_seen
    o_http_request:addAttribute(a_content_type)
    o_http_request:addAttribute(a_cookie)
    o_http_request:addAttribute(a_ip_dst)
    o_http_request:addAttribute(a_ip_src)
    o_http_request:addAttribute(a_method)
    o_http_request:addAttribute(a_refere)
    o_http_request:addAttribute(a_uri)
    o_http_request:addAttribute(a_user_agent)
    return o_http_request
end

function mispHelper.generate_misp_dns_record_object(query_name, dns_query)
    local o_dns_record = Object:new(get_dns_record_template())
    o_dns_record.first_seen = os.date("%Y-%m-%d %X", dns_query['first_seen'])

    local function addAttributeFor(object, dnsEntry, object_relation, type)
        if dnsEntry ~= nil then
            for i, recordValue in pairs(dnsEntry) do
                local attribute = Attribute:new({object_relation=object_relation, type=type, value=recordValue, comment=string.format('%s-#%d', object_relation, i)})
                object:addAttribute(attribute)
            end
        end
    end

    o_dns_record:addAttribute(Attribute:new({object_relation='queried-domain', type='domain', value=query_name}))
    addAttributeFor(o_dns_record, dns_query['dns_a'], 'a-record', 'ip-dst')
    addAttributeFor(o_dns_record, dns_query['dns_aaaa'], 'aaaa-record', 'ip-dst')
    addAttributeFor(o_dns_record, dns_query['dns_mx'], 'mx-record', 'domain')
    addAttributeFor(o_dns_record, dns_query['dns_ns'], 'ns-record', 'domain')
    addAttributeFor(o_dns_record, dns_query['dns_ptr'], 'ptr-record', 'domain')
    addAttributeFor(o_dns_record, dns_query['dns_cname'], 'cname-record', 'domain')
    addAttributeFor(o_dns_record, dns_query['dns_srv'], 'srv-record', 'domain')
    addAttributeFor(o_dns_record, dns_query['dns_soa'], 'soa-record', 'domain')
    addAttributeFor(o_dns_record, dns_query['dns_spf'], 'spf-record', 'ip-dst')

    return o_dns_record
end

function mispHelper.generate_misp_passive_dns_object()
end

return mispHelper