#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  king_phisher/client/web_cloner.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the  nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import argparse
import codecs
import collections
import logging
import re
import string
import sys
import urllib
import requests

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

from ClonedResourceDetails import ClonedResourceDetails
from PostProcessor import PostProcessor

if sys.version_info[0] < 3:
    import urlparse
    urllib.parse = urlparse
else:
    import urllib.parse

try:
    gi.require_version('WebKit2', '3.0')
    from gi.repository import WebKit2
    HAS_WEBKIT2 = True
except ImportError:
    HAS_WEBKIT2 = False


class WebPageCloner(object):
    """
    This object is used to clone web pages. It will use the WebKit2GTK+ engine
    and hook signals to detect what remote resources that are loaded from the
    target URL. These resources are then written to disk. Resources that have
    a MIME type of text/html have the King Phisher server javascript file
    patched in..
    """

    def __init__(self, target_url):
        """
        :param str target_url: The URL of the target web page to clone.
        """
        if not HAS_WEBKIT2:
            raise RuntimeError('cloning requires WebKit2GTK+')

        self.logger = logging.getLogger(__name__)
        self.target_url = urllib.parse.urlparse(target_url)
        self.cloned_resources = collections.OrderedDict()
        self.first_cloned_url = None
        self.load_started = False
        self.load_failed_event = None
        self.__web_resources = []
        self._init_webview()

    def _init_webview(self):
        self.webview = WebKit2.WebView()
        web_context = self.webview.get_context()
        web_context.set_cache_model(WebKit2.CacheModel.DOCUMENT_VIEWER)
        web_context.set_tls_errors_policy(WebKit2.TLSErrorsPolicy.IGNORE)
        self.webview.connect('decide-policy',
                             self.signal_decide_policy)
        self.webview.connect('load-changed',
                             self.signal_load_changed)
        self.webview.connect('load-failed',
                             self.signal_load_failed)
        self.webview.connect('resource-load-started',
                             self.signal_resource_load_started)
        self.webview.load_uri(self.target_url_str)

    def get_first_cloned_url(self):
        return self.first_cloned_url

    def _webkit_empty_resource_bug_workaround(self, url_to_rerequest, expected_len):
        """
        This works around an issue in WebKit2GTK+ that will hopefully be
        resolved eventually. Sometimes the resource data that is returned is
        an empty string so attempt to re-request it with Python.
        """
        try:
            response = requests.get(url_to_rerequest, timeout=10)
        except requests.exceptions.RequestException:
            self.logger.warning(
                'failed to request the empty resource with python')
            return ''
        if response.status_code < 200 or response.status_code > 299:
            self.logger.warning(
                "requested the empty resource with python, but received status: %d (%s)",
                response.status_code, response.reason)
            return ''
        data = response.content
        if len(data) != expected_len:
            self.logger.warning(
                "requested the empty resource with python, but the length appears invalid")
        return data

    @property
    def load_failed(self):
        return self.load_failed_event is not None

    @property
    def target_url_str(self):
        return urllib.parse.urlunparse(self.target_url)

    def copy_resource_data(self, resource, data):
        """
        Copy the data from a loaded resource to a local file.

        :param resource: The resource whose data is being copied.
        :type resource: :py:class:`WebKit2.WebResource`
        :param data: The raw data of the represented resource.
        :type data: bytes, str
        """

        mime_type = None
        charset = 'utf-8'
        response = resource.get_response()

        if response and hasattr(response, 'get_http_headers'):
            mime_type = response.get_http_headers().get('content-type')
            if mime_type and ';' in mime_type:
                mime_type, charset = mime_type.split(';', 1)
                charset = charset.strip()
                if charset.startswith('charset='):
                    charset = charset[8:].strip()
        else:
            mime_type = response.get_mime_type()

        resource_url_str = resource.get_property('uri')
        if resource_url_str.endswith('/'):
            resource_url_str += "index.html"
        resource_url = urllib.parse.urlparse(resource_url_str)
        fullpath_url = resource_url.geturl().replace(
            self.target_url.scheme + "://" + self.target_url.netloc, "")

        crd = ClonedResourceDetails(resource=fullpath_url,
                                    mime_type=mime_type,
                                    resource_data=data,
                                    resource_url=resource_url_str,
                                    charset=charset,
                                    query=resource_url.query)

        if not self.cloned_resources:
            self.first_cloned_url = resource_url_str

        self.cloned_resources[resource_url_str] = crd

    def patch_html(self, data, substring, replacement, encoding='utf-8'):
        try:
            codec = codecs.lookup(encoding)
        except LookupError as error:
            self.logger.warning('failed to decode data from web response, %s', error.args[0])
            return data

        try:
            data = codec.decode(data)[0]
        except ValueError as error:
            self.logger.error("failed to decode data from web response (%s) using encoding %s",
                              error.__class__.__name__, encoding)
            return data

        return codec.encode(data.replace(substring, replacement))[0]

    def org_patch_html(self, data, encoding='utf-8'):
        """
        Patch the HTML data to include the King Phisher javascript resource.
        The script tag is inserted just before the closing head tag. If no head
        tag is present, the data is left unmodified.

        :param str data: The HTML data to patch.
        :return: The patched HTML data.
        :return type: str
        """

        try:
            codec = codecs.lookup(encoding)
        except LookupError as error:
            self.logger.warning('failed to decode data from web response, ' +
                                error.args[0])
            return data

        try:
            data = codec.decode(data)[0]
        except ValueError as error:
            self.logger.error("failed to decode data from web response (%s) using encoding %d",
                              error.__class__.__name__, encoding)
            return data

        match = re.search(r'</head>', data, flags=re.IGNORECASE)
        if not match:
            return codec.encode(data)[0]
        end_head = match.start(0)
        patched = ''
        patched += data[:end_head]
        patched += '<script src="/kp.js" type="text/javascript"></script>'
        ws_cursor = end_head - 1
        while ws_cursor > 0 and data[ws_cursor] in string.whitespace:
            ws_cursor -= 1
        patched += data[ws_cursor + 1:end_head]
        patched += data[end_head:]
        return codec.encode(patched)[0]

    def is_resource_on_target(self, resource):
        """
        Test whether the resource is on the target system. This tries to match
        the hostname, scheme and port number of the resource's URI against the
        target URI.

        :return: Whether the resource is on the target or not.
        :rtype: bool
        """
        resource_url = urllib.parse.urlparse(resource.get_property('uri'))
        if resource_url.netloc.lower() != self.target_url.netloc.lower():
            return False
        return True

    def stop_cloning(self):
        """Stop the current cloning operation if it is running."""
        if self.webview.get_property('is-loading'):
            self.webview.stop_loading()

    def wait(self):
        """
        Wait for the cloning operation to complete and return whether the
        operation was successful or not.

        :return: True if the operation was successful.
        :rtype: bool
        """
        while not self.load_started:
            gtk_sync()
        while self.webview.get_property('is-loading') or self.__web_resources:
            gtk_sync()
        self.webview.destroy()
        return not self.load_failed

    def cb_get_data_finish(self, resource, task):
        data = resource.get_data_finish(task)

        for _ in range(1):
            response = resource.get_response()
            if not response:
                break
            resource_url_str = resource.get_property('uri')
            if not self.is_resource_on_target(resource):
                self.logger.debug('loaded external resource: ' + resource_url_str)
                break
            if not data:
                self.logger.warning('loaded empty on target resource: ' + resource_url_str)
                data = self._webkit_empty_resource_bug_workaround(
                    resource_url_str, response.get_content_length())
            else:
                self.logger.info('loaded on target resource: ' + resource_url_str)
            if data:
                self.copy_resource_data(resource, data)
        self.__web_resources.remove(resource)

    def signal_decide_policy(self, webview, decision, decision_type):
        self.logger.debug("received policy decision request of type: %s", decision_type.value_name)
        if decision_type != WebKit2.PolicyDecisionType.NAVIGATION_ACTION:
            return
        new_target_url_str = decision.get_request().get_uri()
        new_target_url = urllib.parse.urlparse(new_target_url_str)
        if new_target_url_str == self.target_url_str:
            return
        # don't allow offsite redirects
        if new_target_url.netloc.lower() != self.target_url.netloc.lower():
            return
        self.target_url = new_target_url
        self.logger.info("updated the target url to: %s", new_target_url_str)

    def signal_load_changed(self, webview, load_event):
        self.logger.debug("load status changed to: %s", load_event.value_name)
        if load_event == WebKit2.LoadEvent.STARTED:
            self.load_started = True

    def signal_load_failed(self, webview, event, uri, error):
        self.logger.critical("load failed on event: %s for uri: %s", event.value_name, uri)
        self.load_failed_event = event

    def signal_resource_load_started(self, webveiw, resource, request):
        self.__web_resources.append(resource)
        resource.connect('failed', self.signal_resource_load_failed)
        resource.connect('finished', self.signal_resource_load_finished)

    def signal_resource_load_finished(self, resource):
        resource.get_data(callback=self.cb_get_data_finish)

    def signal_resource_load_failed(self, resource, error):
        self.logger.warning('failed to load resource: ' + resource.get_uri())

def gtk_sync():
    """Wait while all pending GTK events are processed."""
    while Gtk.events_pending():
        Gtk.main_iteration()

def main(url_to_clone, ouptut_directory):
    logging.basicConfig(level=logging.ERROR)
    print "Start cloning"
    page_cloner = WebPageCloner(url_to_clone)
    page_cloner.wait()
    if page_cloner.load_failed_event != None:
        print "Error cloning page"
        return
    print "Start post processing"
    post_processor = PostProcessor(
        page_cloner.get_first_cloned_url(), page_cloner.cloned_resources, ouptut_directory)
    post_processor.run()
    print "Done!"

if __name__ == "__main__":

    arguments_parser = argparse.ArgumentParser(prog=__file__)
    arguments_parser.add_argument("-o", "--output-directory", default="./webRoot", type=str,
                                  help="Setting the output directory for the cloned webpage")
    arguments_parser.add_argument("website_url", default=None,
                                  type=str, help="The URL path to the web page you desire to clone")

    parsed_arguments = arguments_parser.parse_args()

    main(parsed_arguments.website_url, parsed_arguments.output_directory)
