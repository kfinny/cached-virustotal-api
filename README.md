# cached-virustotal-api

A cached extension of the official [Python client](https://github.com/VirusTotal/vt-py) for VirusTotal.

## Usage

Create the CachedClient like so:
```python
from kfinny.cachedvt import CachedClient

client = CachedClient(<apikey>, cache_dir=<some folder>)
```

The folder does not need to exist, but if it does, it should be empty or a prior cache from this library. The cache is 
sqlite database created by [DiskCache](https://github.com/grantjenks/python-diskcache).

The client may be used just as it is documented by the [vt-py](https://virustotal.github.io/vt-py/index.html) project. 
The codebase "adds" a single function to the client API, `yield_file_report` and can take a list of hashes.
```python
# yield_file_report
hashes = [<list of md5,sha1,sha256 hashes>]

for obj in client.yield_file_report(hashes):
    assert(obj.type == 'file')
    print(f'{obj.md5} : {obj.sha1} : {obj.sha256}')
```

Files not found on VirusTotal are not returned, but they are cached, since the whole point of this library is to conserve
quota.
```python
>>> hits, misses = client.cache.stats()
>>> reports = list(client.yield_file_report('abcd'*16))
>>> reports
[]
>>> _hits, _misses = client.cache.stats()
>>> assert(_misses - misses == 1)
>>>
```
## Prior Versions

A [previous version](https://github.com/kfinny/cached-virustotal-api/releases/tag/v1.2.0) of this code worked with the
 [virustotal-api](https://github.com/blacktop/virustotal-api) last tested using this commit
  [551b87a](https://github.com/blacktop/virustotal-api/tree/551b87a88c920a876be50c19d503e4b650477d9e).
