import requests,pathlib,json,hashlib,datetime
r=pathlib.Path(__file__).parent
url='https://buy-download.norton.com/downloads/2024/22.24.8/N360/US/N360-ESD-22.24.8.36-EN.exe'
m={'vendor':'Norton','source_url':'https://community.norton.com/t/norton-360-v24-offline-installer/262674','binary_link':url,'scope':'Historical Norton 360 22.24.8.36 Windows; current official support redirect returned 404. Vendor-hosted older package, not current engine.','retrieved_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
try:
 with requests.get(url,stream=True,timeout=60) as q:
  q.raise_for_status();m['final_url']=q.url;p=r/'raw/Norton.exe';h=hashlib.sha256();n=0
  with p.open('wb') as f:
   for block in q.iter_content(1024*1024):
    n+=len(block)
    if n>800*1024*1024:raise ValueError('Size exceeds 800 MiB cap')
    f.write(block);h.update(block)
  with p.open('rb') as f:
   if f.read(2)!=b'MZ':raise ValueError('not PE')
  m.update(status='downloaded',size_bytes=n,sha256=h.hexdigest(),local_file=p.name)
except Exception as e:m.update(status='failed',error=str(e))
(r/'reports/Norton-provenance.json').write_text(json.dumps(m,indent=2));print(json.dumps(m))
