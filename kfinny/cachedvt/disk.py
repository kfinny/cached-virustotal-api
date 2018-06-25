import json
import re
import zlib

import diskcache


class VtCache(diskcache.Disk):
    HASH_PATTERN = re.compile("^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")

    def __init__(self, directory, compress_level=1, **kwargs):
        self.compress_level = compress_level
        super(VtCache, self).__init__(directory, **kwargs)

    def put(self, key):
        k = str(key).lower()
        if VtCache.HASH_PATTERN.match(k):
            return super(VtCache, self).put(k)
        raise ValueError("Invalid key format")

    def store(self, value, read, key):
        k = str(key).lower()
        if not read:
            json_bytes = json.dumps(value).encode('utf-8')
            value = zlib.compress(json_bytes, self.compress_level)
        return super(VtCache, self).store(value, False, key=k)

    def fetch(self, mode, filename, value, read):
        data = super(VtCache, self).fetch(mode, filename, value, read)
        if not read:
            data = json.loads(zlib.decompress(data).decode('utf-8'))
        return data
