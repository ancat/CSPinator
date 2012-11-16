import sys, fnmatch
sys.path.append('burpee')
import gds.pub.burp as burp

def post_process(rules):
    for i in rules.keys():
        if i == 'default-src':
            continue
        for host in rules[i]:
            if host in rules['default-src']:
                rules[i].remove(host)
    return rules

def make_header(rules, report_uri='', mode=None):
    if mode == 'ff' or mode is None:
        string = 'X-Content-Security-Policy'
    elif mode == 'webkit':
        string = 'X-WebKit-CSP'
    else:
        raise ValueError('what')

    if report_uri:
        string += '-Report-Only'
    string += ': '
    if rules['default-src']:
        string += 'default-src ' + ' '.join(rules['default-src']) + '; '
    for rule in rules.keys():
        if rules[rule] and rule != 'default-src':
            string += rule + ' ' + ' '.join(rules[rule]) + '; '
    if report_uri:
        string += 'report-uri ' + report_uri
    return string

def determine_rule_type(request):
    path = request.url.path
    if ".jpg" in path or ".jpeg" in path or ".gif" in path or ".png" in path:
        return "img-src"
    elif ".js" in path:
        return "script-src"
    elif ".css" in path:
        return "style-src"
    elif request.is_xhr:
        return "xhr-src"
    return "default-src"

def wildcardify(domains):
    temp = {}
    replace = []
    final = []

    for i in domains:
        domain = '.'.join(i.split('.')[-2:])
        update = 1
        if temp.has_key(domain):
            update = temp[domain] + 1
        temp.update({domain : update})
    for i in temp.keys():
        if temp[i] > 1:
            replace.append('*.' + i)
    for i in range(len(domains)):
        for j in replace:
            if fnmatch.fnmatch(domains[i], j):
                domains[i] = j
    return list(set(domains))

HOST = sys.argv[2]
HOSTS = []
RULES = {
    'default-src':[],
    'img-src':[],
    'frame-src':[],
    'xhr-src':[],
    'script-src':[],
    'media-src':[],
    'connect-src':[],
    'font-src':[],
    'style-src':[]
}
requests = burp.parse(sys.argv[1])
for req in requests:
    headers = req.get_request_headers()
    rule_type = determine_rule_type(req)
    if headers['host'] not in RULES[rule_type]:
        if HOST == headers['host']:
            RULES[rule_type].append('self')
        else:
            RULES[rule_type].append(headers['host'])

for i in RULES.keys():
    RULES[i] = wildcardify(RULES[i])

RULES = post_process(RULES)

print make_header(RULES, None, 'webkit')
print make_header(RULES, None, 'ff')