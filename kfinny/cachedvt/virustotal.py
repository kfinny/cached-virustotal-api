import logging
from vt import Client, Object
from vt.error import APIError
from diskcache import Cache
from .disk import VtCache


class CachedClient(Client):

    def __init__(self, apikey, agent="unknown", host=None, cache_dir=None):
        super().__init__(apikey, agent=agent, host=host)
        self.cache = Cache(cache_dir, disk=VtCache, disk_compress_level=6, tag_index=True)
        self.cache_dir = cache_dir
        self.logger = logging.getLogger('kfinny.cachedvt.CachedClient')

    def _get(self, resource):
        data, tag = self.cache.get(resource, tag=True)
        if data and tag in ['sha1', 'md5']:
            data, tag = self.cache.get(data, tag=True)
        if data and tag == 'object':
            data = Object.from_dict(data)
        return data

    def _put_object(self, obj):
        self.cache.set(obj.sha256, obj.to_dict(), tag='object')
        self.cache.set(obj.sha1, obj.sha256, tag='sha1')
        self.cache.set(obj.md5, obj.sha256, tag='md5')

    def _put_error(self, resource, error):
        self.cache.set(resource, {'resource': resource, 'code': error.code, 'message': error.message}, tag='error')

    def yield_file_report(self, resource):
        queryset = set()
        if isinstance(resource, str):
            resource = resource.split(',')
        if isinstance(resource, (tuple, list, set, frozenset)):
            for r in resource:
                data = self._get(r)
                if data is not None:
                    yield data
                else:
                    queryset.add(r)
        resource = sorted(queryset)
        for i in resource:
            try:
                obj = self.get_object(f'/files/{i}')
                self._put_object(obj)
                yield obj
            except APIError as e:
                self._put_error(i, e)
        self.logger.debug("hits = {}, misses = {}".format(*self.cache.stats()))
