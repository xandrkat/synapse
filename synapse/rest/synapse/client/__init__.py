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

from typing import TYPE_CHECKING, Mapping

from twisted.web.resource import Resource

from synapse.rest.synapse.client.new_user_consent import NewUserConsentResource
from synapse.rest.synapse.client.pick_idp import PickIdpResource
from synapse.rest.synapse.client.pick_username import pick_username_resource
from synapse.rest.synapse.client.sso_register import SsoRegisterResource

if TYPE_CHECKING:
    from synapse.server import HomeServer


def build_sso_login_resource_tree(hs: "HomeServer") -> Mapping[str, Resource]:
    """Builds a resource tree to include the resources used for SSO login.

    These are always loaded as part of the 'client' resource, whether or not SSO
    login is actually enabled (they just won't work very well if it's not)

    Returns:
         map from path to Resource.
    """
    resources = {
        "/_synapse/client/pick_idp": PickIdpResource(hs),
        "/_synapse/client/pick_username": pick_username_resource(hs),
        "/_synapse/client/new_user_consent": NewUserConsentResource(hs),
        "/_synapse/client/sso_register": SsoRegisterResource(hs),
    }

    if hs.config.oidc_enabled:
        from synapse.rest.oidc import OIDCResource

        resources["/_synapse/oidc"] = OIDCResource(hs)

    if hs.config.saml2_enabled:
        from synapse.rest.saml2 import SAML2Resource

        resources["/_matrix/saml2"] = SAML2Resource(hs)

    return resources


__all__ = ["build_sso_login_resource_tree"]
