# -*- coding: utf-8 -*-
# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from synapse.http.server import DirectServeHtmlResource


class NewUserConsentResource(DirectServeHtmlResource):
    """A resource which collects consent to the server's terms from a new user

    This resource gets mounted at /_synapse/client/new_user_consent, and is shown
    when we are automatically creating a new user due to an SSO login.

    It shows a template which prompts the user to go and read the Ts and Cs, and click
    a clickybox if they have done so.
    """
