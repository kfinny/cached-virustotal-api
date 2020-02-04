import logging
from virus_total_apis import IntelApi, PrivateApi, PublicApi
from diskcache import Cache
from .disk import VtCache


class CachedPublicApi(PublicApi):

    def __init__(self, api_key, cache_dir, proxies=None):
        PublicApi.__init__(self, api_key=api_key, proxies=proxies)
        self.cache = Cache(cache_dir, disk=VtCache, disk_compress_level=6, tag_index=True)
        self.cache_dir = cache_dir
        self.reportBatchLimit = 4

    def _get_report(self, resource):
        data, tag = self.cache.get(resource, tag=True)
        if data and tag != 'data':
            data, tag = self.cache.get(data, tag=True)
        return data

    def _put_report(self, report):
        if report['response_code'] == 1:
            sha256 = report['sha256']
            sha1 = report['sha1']
            md5 = report['md5']
            self.cache.set(sha256, report, tag='data')
            self.cache.set(sha1, sha256, tag='sha1')
            self.cache.set(md5, sha256, tag='md5')
        else:
            try:
                self.cache.set(report['resource'], report, tag='data')
            except ValueError as e:
                logging.warning(str(e))

    def yield_file_report(self, resource, timeout=None):
        queryset = set()
        if isinstance(resource, str):
            resource = resource.split(',')
        if isinstance(resource, (tuple, list, set, frozenset)):
            for r in resource:
                data = self._get_report(r)
                if data is not None:
                    yield data
                else:
                    queryset.add(r)
        resource = sorted(queryset)
        for i in range(0, len(resource), self.reportBatchLimit):
            res = ','.join([str(s) for s in resource[i:i + self.reportBatchLimit]])
            response = self.get_file_report(res, timeout=timeout)
            if response['response_code'] == 200:
                results = response['results']
                if not isinstance(results, list):
                    results = [results]
                for data in results:
                    self._put_report(data)
                    yield data
            else:
                raise Exception("Response Error: VirusTotal returned {} for res := {}".format(
                    response["response_code"], res))
        logging.info("hits = {}, misses = {}".format(*self.cache.stats()))


class CachedPrivateApi(PrivateApi, CachedPublicApi):

    def __init__(self, api_key=None, proxies=None, cache_dir=None):
        PrivateApi.__init__(self, api_key=api_key, proxies=proxies)
        CachedPublicApi.__init__(self, api_key=api_key, proxies=proxies, cache_dir=cache_dir)
        self.reportBatchLimit = 32

    def yield_file_search_hashes(self, query, limit=1000):
        count = 0
        r = self.file_search(query)
        while r['response_code'] == 200 and count < limit:
            if r['results']['response_code'] == 0:
                break
            for h in r['results']['hashes']:
                count += 1
                if count > limit:
                    break
                yield h
            if 'offset' not in r['results']:
                break
            if count < limit:
                r = self.file_search(query, offset=r['results']['offset'])


class CachedIntelApi(IntelApi, CachedPrivateApi):

    def __init__(self, api_key=None, proxies=None, cache_dir=None):
        IntelApi.__init__(self, api_key=api_key, proxies=proxies)
        CachedPrivateApi.__init__(self, api_key=api_key, proxies=proxies, cache_dir=cache_dir)
