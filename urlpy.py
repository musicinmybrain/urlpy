#!/usr/bin/env python
#
# Copyright (c) nexB, Inc.
# Copyright (c) 2012-2015 SEOmoz, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''This is a module for dealing with urls. In particular, sanitizing them.
This version is a friendly fork of the upstream from Moz to keep a pure Python
version around to run on Python on all OSes.
It also uses an alternate publicsuffix list provider package.
'''

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import codecs
import re
import sys

try:
    import urlparse
except ImportError:  # pragma: no cover
    # Python 3 support
    import urllib.parse as urlparse

try:
    from urllib.parse import quote as urllib_quote
    from urllib.parse import unquote as urllib_unquote
except ImportError:
    from urllib import quote as urllib_quote
    from urllib import quote as urllib_unquote

# Python versions
_sys_v0 = sys.version_info[0]
py2 = _sys_v0 == 2
py3 = _sys_v0 == 3


# Come codes that we'll need
IDNA = codecs.lookup('idna')
UTF8 = codecs.lookup('utf-8')
ASCII = codecs.lookup('ascii')
W1252 = codecs.lookup('windows-1252')

# The default ports associated with each scheme
PORTS = {
    'http': 80,
    'https': 443
}


def parse(url):
    '''Parse the provided url string and return an URL object'''
    return URL.parse(url)


class URL(object):
    '''
    For more information on how and what we parse / sanitize:
        http://tools.ietf.org/html/rfc1808.html
    The more up-to-date RFC is this one:
        http://www.ietf.org/rfc/rfc3986.txt
    '''

    # Via http://www.ietf.org/rfc/rfc3986.txt
    GEN_DELIMS = ":/?#[]@"
    SUB_DELIMS = "!$&'()*+,;="
    ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    DIGIT = "0123456789"
    UNRESERVED = ALPHA + DIGIT + "-._~"
    RESERVED = GEN_DELIMS + SUB_DELIMS
    PCHAR = UNRESERVED + SUB_DELIMS + ":@"
    PATH = PCHAR + "/"
    QUERY = PCHAR + "/?"
    FRAGMENT = PCHAR + "/?"
    USERINFO = UNRESERVED + SUB_DELIMS + ":"

    PERCENT_ESCAPING_RE = re.compile('(%([a-fA-F0-9]{2})|.)', re.S)

    @classmethod
    def parse(cls, url):
        '''Parse the provided url, and return a URL instance'''
        if isinstance(url, URL):
            return url
        parsed = urlparse.urlparse(url)

        try:
            port = parsed.port
        except ValueError:
            port = None

        userinfo = parsed.username
        if userinfo and parsed.password:
            userinfo += ':%s' % parsed.password

        return cls(parsed.scheme, parsed.hostname, port,
            parsed.path, parsed.params, parsed.query, parsed.fragment, userinfo)

    def __init__(self, scheme, host, port, path, params, query, fragment, userinfo=None):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path or '/'
        self.params = re.sub(r'^;+', '', str(params))
        self.params = re.sub(r'^;|;$', '', re.sub(r';{2,}', ';', self.params))
        # Strip off extra leading ?'s
        self.query = re.sub(r'^\?+', '', str(query))
        self.query = re.sub(r'^&|&$', '', re.sub(r'&{2,}', '&', self.query))
        self.fragment = fragment
        self.userinfo = userinfo

    def copy(self):
        '''Return a new instance of an identical URL.'''
        return URL(
            self.scheme,
            self.host,
            self.port,
            self.path,
            self.params,
            self.query,
            self.fragment,
            self.userinfo)

    def equiv(self, other):
        '''Return true if this url is equivalent to another'''
        _other = self.parse(other)
        _other = _other.canonical().defrag().abspath().escape()

        _self = self.parse(self)
        _self = _self.canonical().defrag().abspath().escape()

        result = (
            _self.scheme == _other.scheme    and
            _self.host == _other.host      and
            _self.path == _other.path      and
            _self.params == _other.params    and
            _self.query == _other.query)

        if result:
            if _self.port and not _other.port:
                # Make sure _self.port is the default for the scheme
                return _self.port == PORTS.get(_self.scheme, None)
            elif _other.port and not _self.port:
                # Make sure _other.port is the default for the scheme
                return _other.port == PORTS.get(_other.scheme, None)
            else:
                return _self.port == _other.port
        else:
            return False

    def __eq__(self, other):
        '''Return true if this url is /exactly/ equal to another'''
        other = self.parse(other)
        return (
            self.scheme == other.scheme    and
            self.host == other.host      and
            self.path == other.path      and
            self.port == other.port      and
            self.params == other.params    and
            self.query == other.query     and
            self.fragment == other.fragment  and
            self.userinfo == other.userinfo)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return '<urlpy.URL object "{}" >'.format(self)

    def canonical(self):
        '''Canonicalize this url. This includes reordering parameters and args
        to have a consistent ordering'''
        self.query = '&'.join(sorted([q for q in self.query.split('&')]))
        self.params = ';'.join(sorted([q for q in self.params.split(';')]))
        return self

    def defrag(self):
        '''Remove the fragment from this url'''
        self.fragment = None
        return self

    def deparam(self, params):
        '''Strip any of the provided parameters out of the url'''
        lowered = set([p.lower() for p in params])
        def function(name, _):
            return name.lower() in lowered
        return self.filter_params(function)

    def filter_params(self, function):
        '''Remove parameters if function(name, value)'''
        def keep(query):
            name, _, value = query.partition('=')
            return not function(name, value)
        self.query = '&'.join(q for q in self.query.split('&') if q and keep(q))
        self.params = ';'.join(q for q in self.params.split(';') if q and keep(q))
        return self

    def deuserinfo(self):
        '''Remove any userinfo'''
        self.userinfo = None
        return self

    def abspath(self):
        '''Clear out any '..' and excessive slashes from the path'''
        # Remove double forward-slashes from the path
        path = re.sub(r'\/{2,}', '/', self.path)
        # With that done, go through and remove all the relative references
        unsplit = []
        directory = False
        for part in path.split('/'):
            # If we encounter the parent directory, and there's
            # a segment to pop off, then we should pop it off.
            if part == '..' and (not unsplit or unsplit.pop() != None):
                directory = True
            elif part != '.':
                unsplit.append(part)
                directory = False
            else:
                directory = True

        # With all these pieces, assemble!
        if directory:
            # If the path ends with a period, then it refers to a directory,
            # not a file path
            self.path = '/'.join(unsplit) + '/'
        else:
            self.path = '/'.join(unsplit)
        return self

    def sanitize(self):
        '''A shortcut to abspath and escape'''
        return self.abspath().escape()

    def remove_default_port(self):
        '''If a port is provided an is the default, remove it.'''
        if self.port and self.scheme and (self.port == PORTS[self.scheme]):
            self.port = None
        return self

    def escape(self, *args, **kwargs):
        '''Make sure that the path is correctly escaped'''
        self.path = urllib_quote(
            urllib_unquote(self.path), safe=URL.PATH)
        # Safe characters taken from:
        #    http://tools.ietf.org/html/rfc3986#page-50
        self.query = urllib_quote(urllib_unquote(self.query),
            safe=URL.QUERY)
        # The safe characters for URL parameters seemed a little more vague.
        # They are interpreted here as *pchar despite this page, since the
        # updated RFC seems to offer no replacement
        #    http://tools.ietf.org/html/rfc3986#page-54
        self.params = urllib_quote(urllib_unquote(self.params),
            safe=URL.QUERY)
        if self.userinfo:
            self.userinfo = urllib_quote(urllib_unquote(self.userinfo),
                safe=URL.USERINFO)
        return self

    def unescape(self):
        '''Unescape the path'''
        self.path = urllib_unquote(self.path)
        return self

    def __str__(self):
        '''Return the url in an arbitrary encoding'''
        netloc = self.host or ''
        if self.port:
            netloc += (':' + str(self.port))

        if self.userinfo is not None:
            netloc = '%s@%s' % (self.userinfo, netloc)

        result = urlparse.urlunparse((
            str(self.scheme),
            str(netloc),
            str(self.path),
            str(self.params),
            str(self.query),
            self.fragment))
        if isinstance(result, bytes):
            result = result.decode('utf-8')
        return result

    ###########################################################################
    # Information about the domain
    ###########################################################################
    @property
    def hostname(self):
        '''Return the hostname of the url.'''
        return self.host or ''

    ###########################################################################
    # Information about the type of url it is
    ###########################################################################
    @property
    def absolute(self):
        '''Return True if this is a fully-qualified URL with a hostname and
        everything'''
        return bool(self.host)

    @property
    def unicode(self):
        return str(self)
