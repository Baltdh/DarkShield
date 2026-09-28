import requests, pathlib, json,hashlib,datetime,concurrent.futures
from bs4 import BeautifulSoup
root=pathlib.Path(__file__).parent
pages={'Avast':'https://www.avast.com/en-us/download-thank-you.php?locale=en-us&product=AVAST-ONE-MOD-WIN-AV','AVG':'https://www.avg.com/en-us/download-thank-you.php?product=FREEGSR','Norton':'https://www.norton.com/latestn360','Malwarebytes':'https://www.malwarebytes.com/mwb-download/thankyou'}
def fetch(item):
 name,url=item; record={'vendor':name,'source_url':url,'retrieved_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 try:
  r=requests.get(url,timeout=45); r.raise_for_status()
  if not r.content.startswith(b'MZ'):
   links=[a.get('href','') for a in BeautifulSoup(r.text,'html.parser').find_all('a')]
   selected=[x for x in links if ('bits.avcdn.net' in x or 'downloads.malwarebytes.com' in x)]
   if not selected: raise ValueError('No official binary link found; final page '+r.url)
   record['binary_link']=selected[0];r=requests.get(selected[0],timeout=90);r.raise_for_status()
  if not r.content.startswith(b'MZ'): raise ValueError('Response is not a PE executable: '+r.url)
  p=root/'raw'/(name+'.exe');p.write_bytes(r.content)
  record.update(final_url=r.url,size_bytes=len(r.content),sha256=hashlib.sha256(r.content).hexdigest(),local_file=p.name,status='downloaded')
 except Exception as e: record.update(status='failed',error=str(e))
 (root/'reports'/(name+'-provenance.json')).write_text(json.dumps(record,indent=2));print(json.dumps(record),flush=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(fetch,pages.items()))
