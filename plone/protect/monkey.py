from urlparse import urlparse, urljoin


def RedirectTo__call__(self, controller_state):
    url = self.getArg(controller_state)
    context = controller_state.getContext()
    # see if this is a relative url or an absolute
    if len(urlparse(url)[1]) == 0:
        # No host specified, so url is relative.  Get an absolute url.
        url = urljoin(context.absolute_url()+'/', url)
    url = self.updateQuery(url, controller_state.kwargs)
    request = context.REQUEST
    if '_authenticator' in request.form:
        if '?' in url:
            url += '&'
        else:
            url += '?'
        url += '_authenticator=' + request.form['_authenticator']
    return request.RESPONSE.redirect(url)
