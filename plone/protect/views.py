from Products.Five import BrowserView
from zope.interface import implements
from plone.protect.interfaces import IConfirmView


class ConfirmView(BrowserView):
    implements(IConfirmView)
