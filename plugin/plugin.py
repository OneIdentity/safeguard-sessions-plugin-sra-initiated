#!/usr/bin/env pluginwrapper3
#
# Copyright (c) 2013-2021 Balabit
# All Rights Reserved.
#

import re
import os
import json

from vault import Vault, VaultError, AccessRequestDenied

# box_configuration has to be imported before box_config to avoid circular import
# pylint: disable=unused-import
from safeguard.sessions.plugin.box_configuration import BoxConfiguration
from safeguard.sessions.plugin_impl.box_config import BoxConfig

# Authentication-Authorization plugins for SCB are installed to /opt/scb/var/plugins/aa/.
# It is a lot easier just to SSH into SCB to test your plugin rather than uploading through
# the UI to test changes.  Just upload it the first time, the work on it from there.

# The lock files for SCB are stored in /opt/scb/var/lock/.  You will want to delete the
# xml and config lock files in that directory.

# The logging goes to /var/log/messages-<DAY>, where <DAY> is the three character represent-
# ation of the day of the week, e.g. /var/log/messages-Fri.


class Plugin(object):
    def authenticate(
        self,
        session_id,
        session_cookie,
        cookie,
        protocol,
        connection_name,
        client_ip,
        client_port,
        key_value_pairs,
        gateway_user,
    ):
        session_cookie.setdefault("SessionId", session_id)
        if gateway_user:
            return {
                "verdict": "ACCEPT",
                "cookie": cookie,
                "session_cookie": session_cookie,
            }

        if "token" not in key_value_pairs:
            print("Without token authentication is denied")
            return {"verdict": "DENY"}

        if "vaultaddress" not in key_value_pairs:
            print("Without vault address authentication is denied")
            return {"verdict": "DENY"}

        vault = Vault.connect_vault(key_value_pairs["vaultaddress"])

        try:
            response = vault.authenticate_token(
                token=key_value_pairs["token"], session_id=session_cookie["SessionId"]
            )

        except VaultError as error:
            print(error)

            return {"verdict": "DENY"}

        session_cookie["SessionKey"] = response["SessionKey"]
        session_cookie["VaultAddress"] = vault.address
        return {
            "verdict": "ACCEPT",
            "gateway_user": response["User"],
            "gateway_groups": response["Groups"],
            "cookie": cookie,
            "session_cookie": session_cookie,
        }

    # SPS initiated code path should be extracted. pylint: disable=too-many-return-statements
    def authorize(
        self,
        session_id,
        session_cookie,
        cookie,
        protocol,
        connection_name,
        client_ip,
        client_port,
        gateway_user,
        gateway_domain,
        server_ip,
        server_port,
        server_hostname,
        server_username,
        server_domain,
        key_value_pairs,
    ):
        session_cookie["WorkflowStatus"] = "token-granted"

        if "token" not in key_value_pairs:
            print("Start SPS initiated workflow")
            try:
                auth_provider = get_auth_provider(
                    protocol, connection_name, gateway_domain
                )
                session_cookie["AuthUser"] = gateway_user
                session_cookie["AuthProvider"] = auth_provider

                vault = Vault.connect_joined_vault()
                session_cookie["VaultAddress"] = vault.address

                assets = vault.get_assets_by_hostname_or_address(
                    server_hostname=server_hostname,
                    server_ip=server_ip,
                    auth_provider=auth_provider,
                    auth_user=gateway_user,
                )

                if len(assets) != 1:
                    print(
                        f"No unique asset found; address='{server_ip}', hostname='{server_hostname}'"
                    )
                    return self._deny(cookie, session_cookie)

                asset_id = assets[0]["Id"]
                asset_network_address = assets[0]["NetworkAddress"]

                accounts = vault.get_accounts_in_scope_for_asset_by_name(
                    asset_id=asset_id,
                    account_name=server_username,
                    account_domain=server_domain,
                    auth_provider=auth_provider,
                    auth_user=gateway_user,
                )
                if len(accounts) != 1:
                    print(
                        f"No unique account found; asset_id='{asset_id}', username='{server_username}', domain='{server_domain}'"
                    )
                    return self._deny(cookie, session_cookie)

                account_id = accounts[0]["Id"]

                access_request = vault.create_access_request(
                    asset_id=asset_id,
                    account_id=account_id,
                    auth_provider=auth_provider,
                    auth_user=gateway_user,
                    protocol=protocol,
                )
                session_cookie["WorkflowStatus"] = "access-requested"
                session_cookie["AccessRequestId"] = access_request["Id"]

                state_file = OpenAccessRequestStateFile(session_cookie["SessionId"])
                state_file.save(
                    {
                        "AccessRequestId": access_request["Id"],
                        "AuthProvider": auth_provider,
                        "AuthUser": gateway_user,
                        "VaultAddress": vault.address,
                    }
                )

                vault.poll_access_request(
                    access_request, auth_provider=auth_provider, auth_user=gateway_user
                )
                state_file.delete()

                token = vault.get_session_token(
                    access_request, auth_provider=auth_provider, auth_user=gateway_user
                )
                session_cookie["WorkflowStatus"] = "session-initialized"

                response = vault.authenticate_token(
                    token=token, session_id=session_cookie["SessionId"]
                )
                session_cookie["SessionKey"] = response["SessionKey"]
                session_cookie["token"] = token

            except (VaultError, BoxConfigurationError) as error:
                print(error)

                return self._deny(cookie, session_cookie)

            except AccessRequestDenied as error:
                state_file.delete()

                print(error)
                session_cookie["WorkflowStatus"] = "access-denied"

                return self._deny(cookie, session_cookie)

        elif "vaultaddress" not in key_value_pairs:
            print("Without vault address authorization is denied")
            return {"verdict": "DENY"}

        else:
            vault = Vault.connect_vault(key_value_pairs["vaultaddress"])
            token = key_value_pairs["token"]
            session_cookie["token"] = token

            asset_network_address = server_hostname or server_ip

        try:
            vault.authorize_session(
                token=token,
                session_id=session_cookie["SessionId"],
                session_key=session_cookie["SessionKey"],
                client_ip=client_ip,
                client_port=client_port,
                server_hostname=asset_network_address,
                server_port=server_port,
                server_username=server_username,
                protocol=protocol,
            )

        except VaultError as error:
            print(error)

            return {"verdict": "DENY"}

        return {"verdict": "ACCEPT", "session_cookie": session_cookie, "cookie": cookie}

    def _deny(self, cookie, session_cookie):
        return {"verdict": "DENY", "session_cookie": session_cookie, "cookie": cookie}

    def session_ended(self, session_id, session_cookie, cookie):
        try:
            session_id = session_cookie["SessionId"]
        except KeyError:
            return

        workflow_status = session_cookie.get("WorkflowStatus", "zorp-timeout")
        credential_status = session_cookie.get("CredentialStatus")

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
                session_cookie = state_file.get()

            except FileNotFoundError as error:
                print(error)
                return

            finally:
                state_file.delete()

            vault_address = session_cookie["VaultAddress"]

        else:
            vault_address = session_cookie["VaultAddress"]

        vault = Vault.connect_vault(vault_address)

        try:
            if workflow_status in {"access-requested", "zorp-timeout"}:
                vault.cancel_access_request(
                    access_request_id=session_cookie["AccessRequestId"],
                    auth_provider=session_cookie["AuthProvider"],
                    auth_user=session_cookie["AuthUser"],
                )

            elif workflow_status == "session-initialized":
                vault.check_in_access_request(
                    access_request_id=session_cookie["AccessRequestId"],
                    auth_provider=session_cookie["AuthProvider"],
                    auth_user=session_cookie["AuthUser"],
                )

            if "SessionKey" in session_cookie:
                vault.close_authentication(
                    session_id=session_id,
                    session_key=session_cookie["SessionKey"],
                    token=session_cookie.get("token", "token"),
                )

            else:
                print(
                    "Session key is missing to close authentication; "
                    f"state={workflow_status}"
                )

        except VaultError as error:
            print(error)

        return


def get_auth_provider(protocol, connection_name, gateway_domain):
    box_config = BoxConfig()

    connections_url = f"/api/configuration/{protocol}/connections"
    print(f"GET request to localrest; url={connections_url}")
    connection_policies = box_config.query(connections_url)["items"]

    for connection_policy in connection_policies:
        if connection_policy["body"]["name"] == connection_name:
            break
    else:
        raise BoxConfigurationError(
            f"Connection policy not found; protocol={protocol}, name={connection_name}"
        )

    if protocol == "rdp":
        rdg = connection_policy["body"]["remote_desktop_gateway"]
        if not rdg["enabled"]:
            raise BoxConfigurationError(
                f"No Remote Desktop Gateway is configured for connection;"
                f"connection_name={connection_name}"
            )
        if rdg["local_authentication"]["selection"] == "local_user_database":
            return "local"
        else:
            return gateway_domain

    else:
        policies = connection_policy["body"]["policies"]
        auth_policy_ref = policies["authentication_policy"]["meta"]["href"]

        print(f"GET request to localrest; url={auth_policy_ref}")
        auth_policy = box_config.query(auth_policy_ref)
        auth_backend = auth_policy["body"]["backend"]["selection"]

        if auth_backend == "local":
            return "local"

        elif auth_backend == "ldap":
            ldap_server_ref = policies["ldap_server"]["meta"]["href"]
            print(f"GET request to localrest; url={ldap_server_ref}")
            ldap_server = box_config.query(ldap_server_ref)

            return conv_bind_dn_to_auth_domain(ldap_server["body"]["user_base_dn"])


def conv_bind_dn_to_auth_domain(bind_dn):
    auth_domain = ".".join(re.findall("dc=([^,]+)", bind_dn, re.IGNORECASE))
    print(
        f"Bind dn converted to auth domain; bind_dn={bind_dn}, auth_domain={auth_domain}"
    )
    return auth_domain


class BoxConfigurationError(Exception):
    pass


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
