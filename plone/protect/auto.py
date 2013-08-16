from AccessControl import getSecurityManager
from Acquisition import aq_parent

from plone.protect.authenticator import check
from plone.protect.authenticator import createToken

from plone.protect.interfaces import IDisableProtection

import logging
LOGGER = logging.getLogger('plone.protect')

from plone.transformchain.interfaces import ITransform
from zope.interface import implements, Interface
from zope.component import adapts
from repoze.xmliter.utils import getHTMLSerializer
from lxml import etree


class ProtectTransform(object):
    implements(ITransform)
    adapts(Interface, Interface)  # any context, any request

    # should be the last thing that runs here...
    order = 999999

    def __init__(self, published, request):
        self.published = published
        self.request = request

    def parseTree(self, result):
        # hhmmm, this is kind of taken right out of plone.app.theming
        # maybe this logic(parsing dom) should be someone central?
        contentType = self.request.response.getHeader('Content-Type')
        if contentType is None or not contentType.startswith('text/html'):
            return None

        contentEncoding = self.request.response.getHeader('Content-Encoding')
        if contentEncoding and contentEncoding in ('zip', 'deflate',
                                                   'compress',):
            return None

        try:
            return getHTMLSerializer(result, pretty_print=False)
        except (TypeError, etree.ParseError):
            # XXX handle something special?
            LOGGER.warn('error parsing dom, failure to add csrf '
                        'token to response?')
            return None

    def transformString(self, result, encoding):
        return self.transformIterable([result], encoding)

    def transformUnicode(self, result, encoding):
        return self.transformIterable([result], encoding)

    def transformIterable(self, result, encoding):
        """Apply the transform if required
        """
        if getSecurityManager().getUser() is None:
            return

        result = self.parseTree(result)
        if result is None:
            return None

        return self.transform(result)

    def getHost(self):
        base1 = self.request.get('BASE1')
        host = base1.lower()
        serverPort = self.request.get('SERVER_PORT')
        return host, serverPort

    def getContext(self):
        published = self.request.get('PUBLISHED')
        return aq_parent(published)

    def transform(self, result):

        if getSecurityManager().getUser() is None:
            return

        app = self.request.PARENTS[-1]
        if len(app._p_jar._registered_objects) > 0 and not \
                IDisableProtection.providedBy(self.request):
            # XXX Okay, we're writing here, we need to protect!
            check(self.request)
            #context = self.getContext()
            # XXX need to handle redirect case here
            #data = self.request.form.copy()
            #data['action'] = action
            #data['original_url'] = self.request.URL + '?' + \
            #    self.request.QUERY_STRING
            #if action in _redirected_actions:
            #    data['referer'] = self.request.environ.get('HTTP_REFERER')
            #self.request.response.redirect('%s/@@confirm-action?%s' % (
            #    context.absolute_url(),
            #    urlencode(data)
            #))

        root = result.tree.getroot()
        host, port = self.getHost()
        for form in root.cssselect('form'):
            method = form.attrib.get('method', 'GET').lower()
            if method != 'post':
                continue
            action = form.attrib.get('action', '').strip()
            if action:
                # prevent leaking of token
                if (action.startswith('http://') or
                    action.startswith('https://')) and not (
                        action.startswith(host) or
                        action.startswith(host + ':' + port)):
                    continue
            hidden = etree.Element("input")
            hidden.attrib['name'] = '_authenticator'
            hidden.attrib['value'] = createToken()
            form.append(hidden)

        return result

    def __call__(self, result, encoding):
        if isinstance(result, unicode):
            newResult = self.transformUnicode(result, encoding)
        elif isinstance(result, str):
            newResult = self.transformBytes(result, encoding)
        else:
            newResult = self.transformIterable(result, encoding)

        if newResult is not None:
            result = newResult

        return result
