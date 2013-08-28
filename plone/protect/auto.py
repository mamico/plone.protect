import os
import time

from AccessControl import getSecurityManager
from Acquisition import aq_parent

from plone.protect.authenticator import check
from plone.protect.authenticator import createToken

from plone.protect.interfaces import IDisableCSRFProtection

import logging
LOGGER = logging.getLogger('plone.protect')

from plone.transformchain.interfaces import ITransform
from zope.interface import implements, Interface
from zope.component import adapts
from repoze.xmliter.utils import getHTMLSerializer
from lxml import etree
import transaction
from zExceptions import Forbidden
from zope.component.hooks import getSite
from urllib import urlencode
from OFS.interfaces import IApplication
from plone.protect.interfaces import IConfirmView
from plone.portlets.interfaces import IPortletAssignment
from plone.keyring.interfaces import IKeyManager
from zope.component import getUtility
from plone.protect.authenticator import isAnonymousUser


X_FRAME_OPTIONS = os.environ.get('PLONE_X_FRAME_OPTIONS', 'SAMEORIGIN')


_ring_rotation_schedules = (
    ('_system', 60 * 60 * 24 * 7),  # weekly
    ('_forms', 60 * 60 * 24),  # daily
    ('_anon', 60 * 60 * 24),  # daily
)


class ProtectTransform(object):
    """
    XXX Need to be extremely careful with everything we do in here
    since an error here would mean the transform is skipped
    and no CSRF protection...
    """

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
                        'token to response for url %s' % self.request.URL)
            return None

    def transformString(self, result, encoding):
        return self.transformIterable([result], encoding)

    def transformUnicode(self, result, encoding):
        return self.transformIterable([result], encoding)

    def transformIterable(self, result, encoding):
        """Apply the transform if required
        """
        # before anything, do the clickjacking protection
        self.request.response.setHeader('X-Frame-Options', X_FRAME_OPTIONS)

        # only auto CSRF protect authenticated users
        if isAnonymousUser(getSecurityManager().getUser()):
            return

        # if on confirm view, do not check, just abort and
        # immediately transform without csrf checking again
        if IConfirmView.providedBy(self.request.get('PUBLISHED')):
            # abort it, show the confirmation...
            transaction.abort()
            return self.transform(result)

        # next, check if we're zope root.
        # XXX right now, we're not protecting zope root :(
        context = self.getContext()
        if IApplication.providedBy(context):
            return

        if self.check():
            # safe check, let's see if it's time to rotate the keys
            # yes, I know, this will cause a write on read...
            # we know it's safe and the user is logged in
            # disadvantage: only rotates if user is logged in.
            #   sites that people don't log into often will not get keys
            #   rotated
            # possible edge case:
            #   request was aborted, but redirected and we try to write?
            #   XXX do we need to check if the transaction was aborted first?
            # XXX should we check if the client is not read-only first?
            manager = getUtility(IKeyManager)
            current_time = time.time()
            for ring_name, check_period in _ring_rotation_schedules:
                try:
                    ring = manager[ring_name]
                    if (ring.last_rotation + check_period) < current_time:
                        LOGGER.info('auto rotating keyring %s' % ring_name)
                        ring.rotate()
                except:
                    continue
        else:
            # we don't need to transform the doc, we're getting redirected
            return

        # finally, let's run the transform
        return self.transform(result)

    def getHost(self):
        base1 = self.request.get('BASE1')
        host = base1.lower()
        serverPort = self.request.get('SERVER_PORT')
        return host, serverPort

    def getContext(self):
        published = self.request.get('PUBLISHED')
        return aq_parent(published)

    def check(self):
        app = self.request.PARENTS[-1]
        if len(app._p_jar._registered_objects) > 0 and not \
                IDisableCSRFProtection.providedBy(self.request):
            # XXX Okay, we're writing here, we need to protect!
            try:
                check(self.request)
                return True
            except Forbidden:
                if self.request.REQUEST_METHOD != 'GET':
                    # only try to "fix" GET requests
                    raise
                # abort the transaction and just be silent
                # XXX
                # okay, so right now, we're going to check if the current
                # registered objects to write, are just portlet assignments.
                # I don't know why, but when a site is created, these
                # cause some writes on read. ALL, registered objects
                # need to be portlet assignments. XXX needs to be fixed
                # somehow...
                all_portlet_assignments = True
                for obj in app._p_jar._registered_objects:
                    if not IPortletAssignment.providedBy(obj):
                        all_portlet_assignments = False
                        break
                if not all_portlet_assignments:
                    LOGGER.info('aborting transaction due to no CSRF '
                                'protection on url %s' % self.request.URL)
                    transaction.abort()
                    data = self.request.form.copy()
                    data['original_url'] = self.request.URL
                    self.request.response.redirect('%s/@@confirm-action?%s' % (
                        getSite().absolute_url(),
                        urlencode(data)
                    ))
                    return False
        return True

    def transform(self, result):
        result = self.parseTree(result)
        if result is None:
            return None
        root = result.tree.getroot()
        host, port = self.getHost()
        token = createToken()
        for form in root.cssselect('form'):
            # XXX should we only do POST? If we're logged in and
            # it's an internal form, I'm inclined to say no...
            #method = form.attrib.get('method', 'GET').lower()
            #if method != 'post':
            #    continue
            action = form.attrib.get('action', '').strip()
            if action:
                # prevent leaking of token
                if (action.startswith('http://') or
                    action.startswith('https://')) and not (
                        action.startswith(host) or
                        action.startswith(host + ':' + port)):
                    continue
            # check if the token is already on the form..
            hidden = form.cssselect('[name="_authenticator"]')
            if len(hidden) == 0:
                hidden = etree.Element("input")
                hidden.attrib['name'] = '_authenticator'
                hidden.attrib['type'] = 'hidden'
                hidden.attrib['value'] = token
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
