import unittest2 as unittest

from plone.testing.z2 import Browser

from plone.protect.testing import PROTECT_FUNCTIONAL_TESTING


class AutoCSRFProtectTests(unittest.TestCase):
    layer = PROTECT_FUNCTIONAL_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        self.browser = Browser(self.layer['app'])

    def open(self, path):
        self.browser.open(self.portal.absolute_url() + '/' + path)

    def test_adds_csrf_protection_input(self):
        self.open('test-unprotected')
        self.assertTrue('name="_authenticator"' in self.browser.contents)

    def test_authentication_works_automatically(self):
        self.open('test-unprotected')
        self.browser.getControl('submit1').click()

    def test_authentication_works_for_other_form(self):
        self.open('test-unprotected')
        self.browser.getControl('submit2').click()

    def test_works_for_get_form_yet(self):
        self.open('test-unprotected')
        self.browser.getControl('submit3').click()

    def test_forbidden_raised_if_auth_failure(self):
        self.open('test-unprotected')
        self.browser.getForm('one').\
            getControl(name="_authenticator").value = 'foobar'
        try:
            self.browser.getControl('submit1').click()
        except Exception, ex:
            self.assertEquals(ex.getcode(), 403)

"""
    def testAbortsTransactionIfNotProtected(self):
        raise NotImplemented()

    def testRedirectsToConfirmationIfNotProtected(self):
        raise NotImplemented()

    def testWorksCaseInsensativeFormAttributes(self):
        raise NotImplemented()

    def testProtectBlankAction(self):
        raise NotImplemented()

    def testProtectRelative(self):
        raise NotImplemented()

    def testProtectFullPathInternal(self):
        raise NotImplemented()

    def testDoNotProtectExternalPosts(self):
        raise NotImplemented()

    def testDoNotProtectGET(self):
        raise NotImplemented()
"""
