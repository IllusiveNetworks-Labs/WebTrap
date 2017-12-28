import collections
import urlparse

class ClonedResourceDetails(collections.namedtuple(
        'ClonedResourceDetails',
        ('resource',
         'mime_type',
         'resource_data',
         'resource_url',
         'charset',
         'query'))):

    def get_relative_file_path(self):
        resource_url = urlparse.urlparse(self.resource_url)
        resource_path = urlparse.unquote(resource_url.path)
        if resource_path.endswith('/'):
            resource_path += 'index.html'
        return resource_path.lstrip('/')

    def get_directory(self):
        return '/'.join(self.get_relative_file_path().split('/')[:-1])

    def get_filename(self):
        return self.get_relative_file_path().split('/')[-1]
