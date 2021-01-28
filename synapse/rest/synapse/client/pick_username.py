# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from typing import TYPE_CHECKING, Callable, Iterable, Union

import jinja2
import pkg_resources

from twisted.web.http import Request
from twisted.web.resource import Resource
from twisted.web.static import File

from synapse.api.errors import SynapseError
from synapse.config._base import _create_mxc_to_http_filter, _format_ts_filter
from synapse.config.homeserver import HomeServerConfig
from synapse.handlers.sso import USERNAME_MAPPING_SESSION_COOKIE_NAME
from synapse.http.server import (
    DirectServeHtmlResource,
    DirectServeJsonResource,
    respond_with_html,
)
from synapse.http.servlet import parse_string
from synapse.http.site import SynapseRequest

if TYPE_CHECKING:
    from synapse.server import HomeServer


def pick_username_resource(hs: "HomeServer") -> Resource:
    """Factory method to generate the username picker resource.

    This resource gets mounted under /_synapse/client/pick_username. The top-level
    resource is just a File resource which serves up the static files in the resources
    "res" directory, but it has a couple of children:

    * "submit", which does the mechanics of registering the new user, and redirects the
      browser back to the client URL

    * "check": checks if a userid is free.

    XXX: update the above
    """

    # XXX should we make this path customisable so that admins can restyle it?
    base_path = pkg_resources.resource_filename("synapse", "res/username_picker")
    res = File(base_path)

    res.putChild(b"account_details", UsernamePickerTemplateResource(hs))
    res.putChild(b"submit", SubmitResource(hs))
    res.putChild(b"check", AvailabilityCheckResource(hs))

    return res


class UsernamePickerTemplateResource(DirectServeHtmlResource):
    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._sso_handler = hs.get_sso_handler()

        def template_search_dirs():
            if hs.config.sso.sso_template_dir:
                yield hs.config.sso.sso_template_dir
            yield hs.config.sso.default_template_dir

        self._jinja_env = build_jinja_env(template_search_dirs(), hs.config)

    async def _async_render_GET(self, request: Request) -> None:
        try:
            session_id = request.getCookie(USERNAME_MAPPING_SESSION_COOKIE_NAME)
            if not session_id:
                raise SynapseError(code=400, msg="missing session_id")
            session = self._sso_handler.get_mapping_session(session_id)
        except SynapseError as e:
            self._sso_handler.render_error(request, "bad_session", e.msg, code=e.code)
            return

        idp_id = session.auth_provider_id
        template_params = {
            "idp": self._sso_handler.get_identity_providers()[idp_id],
            "user_attributes": {
                "display_name": session.display_name,
                "emails": session.emails,
            },
        }

        # loaded dynamically to allow easier update cycles. (jinja will only reload it
        # if the mtime changes)
        template = self._jinja_env.get_template("sso_auth_account_details.html")
        html = template.render(template_params)
        respond_with_html(request, 200, html)


class AvailabilityCheckResource(DirectServeJsonResource):
    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._sso_handler = hs.get_sso_handler()

    async def _async_render_GET(self, request: Request):
        localpart = parse_string(request, "username", required=True)

        session_id = request.getCookie(USERNAME_MAPPING_SESSION_COOKIE_NAME)
        if not session_id:
            raise SynapseError(code=400, msg="missing session_id")

        is_available = await self._sso_handler.check_username_availability(
            localpart, session_id.decode("ascii", errors="replace")
        )
        return 200, {"available": is_available}


class SubmitResource(DirectServeHtmlResource):
    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._sso_handler = hs.get_sso_handler()

    async def _async_render_POST(self, request: SynapseRequest):
        localpart = parse_string(request, "username", required=True)

        session_id = request.getCookie(USERNAME_MAPPING_SESSION_COOKIE_NAME)
        if not session_id:
            raise SynapseError(code=400, msg="missing session_id")

        await self._sso_handler.handle_submit_username_request(
            request, localpart, session_id.decode("ascii", errors="replace")
        )


# TODO: move this not-here and call it from more places
def build_jinja_env(
    template_search_directories: Iterable[str],
    config: HomeServerConfig,
    autoescape: Union[bool, Callable[[str], bool], None] = None,
) -> jinja2.Environment:
    """Set up a Jinja2 environment to load templates from the given search path

    The returned environment defines the following filters:
        - format_ts: formats timestamps as strings in the server's local timezone
             (XXX: why is that useful??)
        - mxc_to_http: converts mxc: uris to http URIs. Args are:
             (uri, width, height, resize_method="crop")

    and the following global variables:
        - server_name: matrix server name

    Args:
        template_search_directories: directories to search for templates
        config: homeserver config, for things like `server_name` and `public_baseurl`
        autoescape: whether template variables should be autoescaped. bool, or
           a function mapping from template name to bool. Defaults to escaping templates
           whose names end in .html, .xml or .htm.

    Returns:
        jinja environment
    """

    if autoescape is None:
        autoescape = jinja2.select_autoescape()

    loader = jinja2.FileSystemLoader(template_search_directories)
    env = jinja2.Environment(loader=loader, autoescape=autoescape)

    # Update the environment with our custom filters
    env.filters.update(
        {
            "format_ts": _format_ts_filter,
            "mxc_to_http": _create_mxc_to_http_filter(config.public_baseurl),
        }
    )

    # common variables for all templates
    env.globals.update({"server_name": config.server_name})

    return env
