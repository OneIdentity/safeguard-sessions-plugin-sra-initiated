#!/usr/bin/env pluginwrapper3
#
# Copyright (c) 2024 One Identity
# All Rights Reserved.
#

import os
import json
from ipaddress import ip_address, ip_network

from .vault import Vault, VaultError, AccessRequestDenied

from safeguard.sessions.plugin.plugin_base import cookie_property
from safeguard.sessions.plugin import AAPlugin, AAResponse

PLUGIN_SECTION = 'plugin'

# Authentication-Authorization plugins for SCB are installed to /opt/scb/var/plugins/aa/.
# It is a lot easier just to SSH into SCB to test your plugin rather than uploading through
# the UI to test changes.  Just upload it the first time, the work on it from there.

# The lock files for SCB are stored in /opt/scb/var/lock/.  You will want to delete the
# xml and config lock files in that directory.

# The logging goes to /var/log/messages-<DAY>, where <DAY> is the three character represent-
# action of the day of the week, e.g. /var/log/messages-Fri.


class Plugin(AAPlugin):
    def _extract_mfa_password(self):
        return 'can pass'

    def _extract_username(self):
        username = super()._extract_username()
        self.original_username = username
        new_domain = self.plugin_configuration.get(PLUGIN_SECTION, 'replace_domain')
        if new_domain:
            (username, domain) = split_username(username)
            return username + '@' + new_domain
        return username

    @cookie_property
    def original_username(self):
        pass

    @cookie_property
    def spp_username(self):
        (username, domain) = split_username(self.username)
        if self.spp_auth_provider.lower() == 'starling':
            return self.username

        return username

    @cookie_property
    def spp_auth_provider(self):
        provider = self.plugin_configuration.get(PLUGIN_SECTION, 'spp_auth_provider')
        if provider:
            return provider

        (username, domain) = split_username(self.username)
        return domain if domain else 'Local'

    def set_https_proxy(self):
        if self.plugin_configuration.getboolean('plugin', 'use_https_proxy', False):
            super().set_https_proxy()
        else:
            self.logger.info("HTTPS proxy server configuration ignored, communicating directly")

    def do_authenticate(self):
        self.session_cookie.setdefault("SessionId", self.connection.session_id)

        if self.username:
            if self.is_client_excluded():
                return AAResponse.deny('Client network not allowed')

            return AAResponse.accept('Accepting authentication by default')

        key_value_pairs = self.connection.key_value_pairs
        if "token" not in key_value_pairs:
            print("Without token authentication is denied")
            return {"verdict": "DENY"}

        if "vaultaddress" not in key_value_pairs:
            print("Without vault address authentication is denied")
            return {"verdict": "DENY"}

        vault = Vault.connect_vault(key_value_pairs["vaultaddress"])

        try:
            response = vault.authenticate_token(
                token=key_value_pairs["token"], session_id=self.session_cookie["SessionId"]
            )

        except VaultError as error:
            print(error)

            return {"verdict": "DENY"}

        self.session_cookie["SessionKey"] = response["SessionKey"]
        self.session_cookie["VaultAddress"] = vault.address
        return AAResponse.accept().with_gateway_user(response["User"], response["Groups"])

    # SPS initiated code path should be extracted. pylint: disable=too-many-return-statements
    def do_authorize(self):
        self.session_cookie.setdefault("SessionId", self.connection.session_id)
        self.session_cookie["WorkflowStatus"] = "token-granted"
        key_value_pairs = self.connection.key_value_pairs
        if "token" not in key_value_pairs:
            print("Start SPS initiated workflow")
            try:
                self.session_cookie["AuthUser"] = self.spp_username
                self.session_cookie["AuthProvider"] = self.spp_auth_provider

                vault = Vault.connect_joined_vault()
                self.session_cookie["VaultAddress"] = vault.address

                assets = vault.get_assets_by_hostname_or_address(
                    server_hostname=self.connection.server_hostname,
                    server_ip=self.connection.server_ip,
                    auth_provider=self.spp_auth_provider,
                    auth_user=self.spp_username,
                )

                if len(assets) != 1:
                    print(
                        f"No unique asset found; address='{self.connection.server_ip}', hostname='{self.connection.server_hostname}'"
                    )
                    return AAResponse.deny()

                asset_id = assets[0]["Id"]
                asset_network_address = assets[0]["NetworkAddress"]

                accounts = vault.get_accounts_in_scope_for_asset_by_name(
                    asset_id=asset_id,
                    account_name=self.connection.server_username,
                    account_domain=self.connection.server_domain,
                    auth_provider=self.spp_auth_provider,
                    auth_user=self.spp_username,
                )
                if len(accounts) != 1:
                    print(
                        f"No unique account found; asset_id='{asset_id}', username='{self.connection.server_username}', domain='{self.connection.server_domain}'"
                    )
                    return AAResponse.deny()

                account_id = accounts[0]["Id"]

                access_request = vault.create_access_request(
                    asset_id=asset_id,
                    account_id=account_id,
                    auth_provider=self.spp_auth_provider,
                    auth_user=self.spp_username,
                    protocol=self.connection.protocol,
                    reason_comment=self.session_comment()
                )
                self.session_cookie["WorkflowStatus"] = "access-requested"
                self.session_cookie["AccessRequestId"] = access_request["Id"]

                state_file = OpenAccessRequestStateFile(self.session_cookie["SessionId"])
                state_file.save(
                    {
                        "AccessRequestId": access_request["Id"],
                        "AuthProvider": self.spp_auth_provider,
                        "AuthUser": self.spp_username,
                        "VaultAddress": vault.address,
                    }
                )

                vault.poll_access_request(
                    access_request, auth_provider=self.spp_auth_provider, auth_user=self.spp_username
                )
                state_file.delete()

                token = vault.get_session_token(
                    access_request, auth_provider=self.spp_auth_provider, auth_user=self.spp_username
                )
                self.session_cookie["WorkflowStatus"] = "session-initialized"

                response = vault.authenticate_token(
                    token=token, session_id=self.session_cookie["SessionId"]
                )
                self.session_cookie["SessionKey"] = response["SessionKey"]
                self.session_cookie["token"] = token

            except VaultError as error:
                print(error)

                return AAResponse.deny()

            except AccessRequestDenied as error:
                state_file.delete()

                print(error)
                self.session_cookie["WorkflowStatus"] = "access-denied"

                return AAResponse.deny()

        elif "vaultaddress" not in key_value_pairs:
            print("Without vault address authorization is denied")
            return {"verdict": "DENY"}

        else:
            vault = Vault.connect_vault(key_value_pairs["vaultaddress"])
            token = key_value_pairs["token"]
            self.session_cookie["token"] = token

            asset_network_address = self.connection.server_hostname or self.connection.server_ip

        try:
            vault.authorize_session(
                token=token,
                session_id=self.session_cookie["SessionId"],
                session_key=self.session_cookie["SessionKey"],
                client_ip=self.connection.client_ip,
                client_port=self.connection.client_port,
                server_hostname=asset_network_address,
                server_port=self.connection.server_port,
                server_username=self.connection.server_username,
                protocol=self.connection.protocol,
            )

        except VaultError as error:
            print(error)

            return {"verdict": "DENY"}

        return AAResponse.accept(self.session_comment())

    def is_client_excluded(self):
        client_address = ip_address(self.connection.client_ip)
        exclude_networks: list = self.plugin_configuration.getlist(PLUGIN_SECTION, 'exclude_networks', '')
        for item in filter(lambda x: x, exclude_networks):
            network = ip_network(item)
            if client_address in network:
                return True
        return False

    def session_comment(self):
        return 'SRA,gateway_user_external_upn={}'.format(self.original_username)

    def do_session_ended(self):
        try:
            session_id = self.session_cookie["SessionId"]
        except KeyError:
            return

        workflow_status = self.session_cookie.get("WorkflowStatus", "zorp-timeout")
        credential_status = self.session_cookie.get("CredentialStatus")

        # In case of RDP multiple proxy session belongs to the user's RDP session.
        # The access request can be closed only if the credentails are fetched.
        # In case of zorp-timeout the access request can be closed because zorp won't
        # call the credentalstore plugin.
        if workflow_status != "zorp-timeout" and credential_status != "fetched":
            return

        # In case of timeout zorp kills the plugin and the cookie and session_cookie
        # will be empty, so we have to read the state file for the session info.
        if workflow_status == "zorp-timeout":
            try:
                state_file = OpenAccessRequestStateFile(session_id)
                self.session_cookie = state_file.get()

            except FileNotFoundError as error:
                print(error)
                return

            finally:
                state_file.delete()

            vault_address = self.session_cookie["VaultAddress"]

        else:
            vault_address = self.session_cookie["VaultAddress"]

        vault = Vault.connect_vault(vault_address)

        try:
            if workflow_status in {"access-requested", "zorp-timeout"}:
                vault.cancel_access_request(
                    access_request_id=self.session_cookie["AccessRequestId"],
                    auth_provider=self.session_cookie["AuthProvider"],
                    auth_user=self.session_cookie["AuthUser"],
                )

            elif workflow_status == "session-initialized":
                vault.check_in_access_request(
                    access_request_id=self.session_cookie["AccessRequestId"],
                    auth_provider=self.session_cookie["AuthProvider"],
                    auth_user=self.session_cookie["AuthUser"],
                )

            if "SessionKey" in self.session_cookie:
                vault.close_authentication(
                    session_id=session_id,
                    session_key=self.session_cookie["SessionKey"],
                    token=self.session_cookie.get("token", "token"),
                )

            else:
                print(
                    "Session key is missing to close authentication; "
                    f"state={workflow_status}"
                )

        except VaultError as error:
            print(error)

        return


class OpenAccessRequestStateFile:
    def __init__(self, session_id):
        state_dir = os.environ.get("SCB_PLUGIN_STATE_DIRECTORY")
        file_name = session_id.replace("/", "_").replace(":", "_")
        self.path = os.path.join(state_dir, file_name)

    def save(self, content):
        with open(self.path, "w") as state_file:
            json.dump(content, state_file)

    def get(self):
        with open(self.path, "r") as state_file:
            return json.load(state_file)

    def delete(self):
        try:
            os.remove(os.path.join(self.path))
        except FileNotFoundError:
            pass


def split_username(username):
    if '@' not in username:
        return username, None
    username_r = username[::-1]
    atidx = len(username_r) - username_r.find('@')
    return username[:atidx - 1], username[atidx:]
