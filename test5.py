#!/usr/bin/env python3
"""Privacy-preserving website JS and offline HAR triage.
Usage: py test5.py https://example.com/
Or: python test5.py --har traffic.har --source ./js --out report.json
URL mode fetches only homepage and same-origin linked scripts; never probes APIs.
Use on websites you own or have authorization to assess.
"""py
import argparse, json, re, pathlib, collections, urllib.parse, hashlib

PII_KEYS = {
    'email':'email', 'emailaddress':'email', '이메일':'email',
    'phone':'phone', 'phonenumber':'phone', 'mobile':'phone', 'tel':'phone', '전화번호':'phone', '휴대폰':'phone',
    'birth':'birth', 'birthday':'birth', 'birthdate':'birth', 'dob':'birth', '생년월일':'birth',
    'fullname':'name', 'username':'name', 'customername':'name', 'realname':'name', '이름':'name', '성명':'name',
    'address':'address', '주소':'address', 'rrn':'national_id', '주민등록번호':'national_id',
    'residentregistrationnumber':'national_id', 'password':'credential', 'passwordhash':'credential',
    'accesstoken':'credential', 'refreshtoken':'credential', 'cardnumber':'financial'
}
# A lone 'name' or 'id' is not reliable evidence of personal data.
STRONG = {'email','phone','birth','address','national_id','credential','financial'}
SECRET_PATTERNS = {
    'AWS access key ID': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'Stripe secret key': re.compile(r'\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b'),
    'Private key header': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'Supabase service_role reference': re.compile(r'(?i)\bservice_role\b'),
}
PUBLIC_CONFIG = re.compile(r'(?i)\b(?:firebaseConfig|publishableKey|anonKey|supabaseUrl|databaseURL)\b')
# Match URL paths only in source text; never request them.
API_PATH = re.compile(r'''["'`]((?:/api/|/rest/v1/|/graphql\b|/auth/v1/)[A-Za-z0-9_./?=&${}\-]*)["'`]''')
FETCH_CALL = re.compile(r'''\b(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*["'`]([^"'`]{1,300})["'`]''')


def normalize_key(key):
    return re.sub(r'[^a-z0-9가-힣]', '', str(key).lower())

def classify_key(key):
    k = normalize_key(key)
    if k == 'name': return 'possible_name'
    return PII_KEYS.get(k)

def record_fields(item):
    if not isinstance(item, dict): return set()
    return {c for key in item.keys() if (c := classify_key(key))}

def analyze_json(data):
    """Shape-only analysis. Never include values in the report."""
    result = []
    def walk(node, path='$', depth=0):
        if depth > 14 or len(result) >= 100: return
        if isinstance(node, list):
            dicts = [x for x in node if isinstance(x, dict)]
            if dicts:
                field_counts = collections.Counter()
                matching_records = 0
                for item in dicts[:1000]:
                    fields = record_fields(item)
                    field_counts.update(fields)
                    if len(fields & STRONG) >= 2 or ('possible_name' in fields and len(fields & STRONG) >= 1):
                        matching_records += 1
                if field_counts:
                    result.append({'path':path, 'array_length':len(node),
                        'sampled_objects':len(dicts[:1000]),
                        'field_categories':dict(sorted(field_counts.items())),
                        'records_with_combined_pii_fields':matching_records,
                        'note':'Schema indicators only; exposure and authorization not established'})
            for i, value in enumerate(node[:10]): walk(value, path+'[*]', depth+1)
        elif isinstance(node, dict):
            fields = sorted(record_fields(node))
            if fields and depth <= 2:
                result.append({'path':path, 'object_field_categories':fields,
                    'note':'Field names alone are not evidence of PII disclosure'})
            for key, value in list(node.items())[:100]:
                if isinstance(value,(dict,list)): walk(value, path+'.'+str(key), depth+1)
    walk(data)
    # Remove duplicates from sampled nested records
    seen=set(); dedup=[]
    for r in result:
        sig=json.dumps(r,ensure_ascii=False,sort_keys=True)
        if sig not in seen: seen.add(sig); dedup.append(r)
    return dedup[:100]

def source_map_link(text, label):
    """Resolve a sourceMappingURL reference without fetching its contents."""
    matches = re.findall(r'(?m)//[#@]\s*sourceMappingURL\s*=\s*(\S+)|/\*[#@]\s*sourceMappingURL\s*=\s*(\S+?)\s*\*/', text)
    if not matches:
        return None
    ref = (matches[-1][0] or matches[-1][1]).strip()
    if ref.startswith('data:'):
        return '[inline source map: data URL]'
    if not label.startswith(('https://', 'http://')):
        return None
    link = urllib.parse.urljoin(label, ref)
    source = urllib.parse.urlsplit(label)
    dest = urllib.parse.urlsplit(link)
    if (source.scheme, source.netloc) != (dest.scheme, dest.netloc):
        return '[external source map reference omitted]'
    return urllib.parse.urlunsplit((dest.scheme, dest.netloc, dest.path, '', ''))

def analyze_source(text, label):
    endpoints=sorted(set(API_PATH.findall(text)) | set(FETCH_CALL.findall(text)))[:300]
    patterns=[name for name, pat in SECRET_PATTERNS.items() if pat.search(text)]
    return {'source':label, 'api_path_candidates':endpoints,
        'secret_pattern_indicators':patterns,
        'public_client_config_present':bool(PUBLIC_CONFIG.search(text)),
        'source_map_reference': bool(re.search(r'[#@]\s*sourceMappingURL\s*=',text)),
        'source_map_url': source_map_link(text, label)}

def analyze_har(path):
    with open(path,'r',encoding='utf-8-sig') as f: data=json.load(f)
    entries=data.get('log',{}).get('entries',[])
    report=[]; stats=collections.Counter()
    for entry in entries[:20000]:
        req=entry.get('request',{}); resp=entry.get('response',{})
        url=req.get('url',''); parsed=urllib.parse.urlsplit(url)
        safe_url=urllib.parse.urlunsplit((parsed.scheme,parsed.netloc,parsed.path,'',''))
        method=req.get('method','?'); status=resp.get('status')
        stats['total_requests']+=1
        if '/api/' in parsed.path or '/rest/v1/' in parsed.path or '/graphql' in parsed.path:
            stats['api_requests']+=1
        content=resp.get('content') or {}; mime=content.get('mimeType','')
        item={'url_without_query':safe_url, 'method':method, 'status':status,
              'response_mime_type':mime, 'response_bytes_reported':content.get('size')}
        body=content.get('text')
        if isinstance(body,str) and content.get('encoding') != 'base64' and len(body)<=3_000_000:
            try:
                payload=json.loads(body)
                item['json_shape_indicators']=analyze_json(payload)
                if item['json_shape_indicators']: stats['json_with_sensitive_field_names']+=1
            except (ValueError,TypeError): pass
        elif not isinstance(body,str):
            item['response_body_available']=False
        report.append(item)
    return {'har_entry_count':len(entries), 'analyzed_entries':len(report),
            'statistics':dict(stats), 'requests':report}

def analyze_public_site(url):
    """Read the landing page and its same-origin linked JS; do not probe APIs."""
    import urllib.request
    from html.parser import HTMLParser
    class Assets(HTMLParser):
        def __init__(self):
            super().__init__(); self.scripts=[]
        def handle_starttag(self, tag, attrs):
            if tag.lower() == 'script':
                v=dict(attrs).get('src')
                if v: self.scripts.append(v)
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme not in ('http','https') or not parsed.hostname:
        raise ValueError('HTTP(S) URL required')
    origin=(parsed.scheme,parsed.netloc)
    def retrieve(target):
        req=urllib.request.Request(target,headers={'User-Agent':'SiteSecurityResearchScanner/3.1'})
        with urllib.request.urlopen(req,timeout=10) as r:
            final=urllib.parse.urlsplit(r.geturl())
            if (final.scheme,final.netloc) != origin:
                return None, 'redirected outside origin'
            mime=r.headers.get_content_type()
            size=r.headers.get('Content-Length')
            if size and int(size)>2_000_000: return None,'asset too large'
            data=r.read(2_000_001)
            if len(data)>2_000_000: return None,'asset too large'
            return (data.decode('utf-8',errors='replace'),mime),None
    result={'url':url,'mode':'public_landing_page_and_same_origin_scripts_only',
            'sources':[],'errors':[],'limitations':['No API endpoints called','No authentication tests','Dynamic chunks may be missed']}
    try:
        page,error=retrieve(url)
        if error: result['errors'].append(error); return result
        html,mime=page
        result['sources'].append(analyze_source(html,url))
        parser=Assets(); parser.feed(html)
        seen=set()
        for path in parser.scripts[:40]:
            target=urllib.parse.urljoin(url,path)
            u=urllib.parse.urlsplit(target)
            if (u.scheme,u.netloc)!=origin or target in seen: continue
            seen.add(target)
            try:
                asset,error=retrieve(target)
                if error: result['errors'].append(target+': '+error); continue
                text,mime=asset
                if 'javascript' in mime or u.path.lower().endswith(('.js','.mjs')):
                    result['sources'].append(analyze_source(text,target))
            except Exception as exc:
                result['errors'].append(target+': '+type(exc).__name__)
    except Exception as exc:
        result['errors'].append(type(exc).__name__+': '+str(exc))
    return result

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('url',nargs='?',help='Public website URL to inspect (landing page + linked JS only)')
    ap.add_argument('--har',type=pathlib.Path,help='HAR exported from authorized browser session')
    ap.add_argument('--source',type=pathlib.Path,help='JS/HTML source file or folder')
    ap.add_argument('--out',type=pathlib.Path,default=pathlib.Path('report.json'))
    args=ap.parse_args()
    if not args.har and not args.source and not args.url: ap.error('provide URL, --har and/or --source')
    report={'version':'3.0','mode':'offline_passive',
        'limitations':['No authorization bypass tests','No live API requests',
          'Public client configuration is not itself a vulnerability',
          'A HAR may omit response bodies; missing results do not imply safety',
          'Field names alone do not establish personal-data exposure'],
        'sources':[], 'traffic':None, 'site':None}
    if args.url:
        report['site']=analyze_public_site(args.url)
        report['sources'].extend(report['site']['sources'])
    if args.source:
        paths=[args.source] if args.source.is_file() else sorted(p for p in args.source.rglob('*') if p.is_file() and p.suffix.lower() in {'.js','.mjs','.html','.json','.map'})[:500]
        for p in paths:
            if p.stat().st_size>5_000_000: continue
            text=p.read_text(encoding='utf-8',errors='replace')
            report['sources'].append(analyze_source(text,str(p)))
    if args.har: report['traffic']=analyze_har(args.har)
    args.out.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(f'완료: {args.out} | JS/HTML {len(report["sources"])}개 | HAR 요청 {report["traffic"]["analyzed_entries"] if report["traffic"] else 0}개')
    map_urls=sorted({x['source_map_url'] for x in report['sources'] if isinstance(x.get('source_map_url'),str) and x['source_map_url'].startswith('https://')})
    if map_urls:
        print(f'Source Map 참조 URL {len(map_urls)}개 (주소만 추출, 접근 가능 여부 미확인):')
        for link in map_urls[:30]: print('  '+link)
        if len(map_urls)>30: print(f'  ...외 {len(map_urls)-30}개 (report.json 확인)')
    print('주의: 보고서에는 응답 본문/쿠키/토큰/개인정보 원문을 저장하지 않습니다.')
if __name__=='__main__': main()
