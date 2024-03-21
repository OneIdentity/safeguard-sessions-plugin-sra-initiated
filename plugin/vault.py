#
# Copyright (c) 2024 One Identity
# All Rights Reserved.
#

import json
import requests
import time

from requests_toolbelt.adapters.source import SourceAddressAdapter

class Vault:
    def __init__(self, spp_ip, sps_ip):
        self._session = requests.Session()
        self._session.verify = "/etc/spp/server.crt"
        self._session.cert = ("/etc/spp/client.crt", "/etc/spp/client.key")
        self._session.headers.update({"content-type": "application/json"})
        self._session.mount("https://", SourceAddressAdapter(sps_ip))
        self.address = spp_ip

        sps_interactive_url = f"https://{spp_ip}:8649/service/SPSInteractive/v3/"
        self.plugin_url = sps_interactive_url + "Plugin/"
        self.broker_url = sps_interactive_url + "AccessRequestBroker/"

    @classmethod
    def connect_vault(cls, spp_ip):
        return cls(spp_ip, cls._get_sps_ip())

    @classmethod
    def connect_joined_vault(cls):
        sps_ip = cls._get_sps_ip()
        spp_ips = cls._get_spp_ips()

        for spp_ip in spp_ips:
            self = cls(spp_ip, sps_ip)
            if self._check_connection():  # pylint: disable=protected-access
                return self

        raise VaultError("Could not connect to joined vault", {"addresses": spp_ips})

    @staticmethod
    def _get_sps_ip():
        with open("/etc/spp/join.json", "r") as config_file:
            config = json.load(config_file)

        return config["sps_cluster_interface_ip"]

    @staticmethod
    def _get_spp_ips():
        with open("/etc/spp/cluster_members.json") as fp:
            cluster_members = json.load(fp)

        addresses = [member["Ipv4Address"] for member in cluster_members]
        return addresses

    def _check_connection(self):
        url = self._get_plugin_resource("Authentication")
        print(f"Validate vault connection; url={url}")

        try:
            self._session.get(url)
        except requests.exceptions.ConnectionError:
            return False

        return True

    def _get_plugin_resource(self, resource):
        return self.plugin_url + resource

    def _get_broker_resource(self, resource):
        return self.broker_url + resource

    def authenticate_token(self, *, token, session_id):
        print("Authenticate token")

        url = self._get_plugin_resource("Authentication")
        parameters = {"token": token, "sessionId": session_id}

        return self._get(url, parameters=parameters, auth="PsmPlugin")

    def close_authentication(self, *, session_id, session_key, token):
        print("Close authentication")

        url = self._get_plugin_resource("Authentication")
        parameters = {
            "sessionId": session_id,
            "sessionKey": session_key,
            "token": token,
        }

        return self._delete(url, parameters=parameters, auth="PsmPlugin")

    def authorize_session(
        self,
        *,
        token,
        session_id,
        session_key,
        client_ip,
        client_port,
        server_hostname,
        server_port,
        server_username,
        protocol,
    ):
        print("Authorize session")

        url = self._get_plugin_resource("Authorization")
        session_params = {
            "token": token,
            "sessionId": session_id,
            "sessionKey": session_key,
            "clientIp": client_ip,
            "clientPort": client_port,
            "targetServer": server_hostname,
            "targetPort": server_port,
            "targetUserName": server_username,
            "protocol": protocol,
        }

        return self._get(url, parameters=session_params, auth="PsmPlugin")

    def get_credentials(self, *, session_id, session_key, credential_type=None):
        url = self._get_plugin_resource("Credentials")
        parameters = {"sessionId": session_id, "sessionKey": session_key}

        if credential_type is not None:
            print(f"Get credentials; type={credential_type}")
            parameters["credentialType"] = credential_type
        else:
            print("Get credentials")

        return self._get(url, parameters=parameters, auth="PsmPlugin")

    def close_credentials(self, *, session_id, session_key):
        print("Close credentials")

        url = self._get_plugin_resource("Credentials")
        parameters = {"sessionId": session_id, "sessionKey": session_key}

        return self._post(url, parameters=parameters, auth="PsmPlugin")

    def delete_credentials(self, *, session_id, session_key):
        print("Notify SPP about session ended")

        url = self._get_plugin_resource("Credentials")
        parameters = {"sessionId": session_id, "sessionKey": session_key}

        return self._delete(url, parameters=parameters, auth="PsmPlugin")

    def _delete(self, url, parameters=None, auth="PsmPlugin"):
        print(
            f"DELETE request; url={url}, parameters={_remove_sensitive_data(parameters)}, auth={auth}"
        )

        headers = {"Authorization": f"{auth} certuser"}
        response = self._session.delete(url, params=parameters, headers=headers)
        decoded_response = self._decode_response(response)

        print(f"Response to DELETE; data={_remove_sensitive_data(decoded_response)}")

        return decoded_response

    def get_assets_by_hostname_or_address(
        self, *, server_hostname, server_ip, auth_provider, auth_user
    ):
        print("Get assets matching hostname or address")

        if server_hostname:
            asset_filter = f"NetworkAddress eq '{server_ip}' OR NetworkAddress ieq '{server_hostname}'"
        else:
            asset_filter = f"NetworkAddress eq '{server_ip}'"

        url = self._get_broker_resource("RequestableAssets")
        request = {
            "Filter": asset_filter,
            "ForUser": auth_user,
            "ForProvider": auth_provider,
        }
        return self._get(url, parameters=request, auth="SPSInteractive")

    # pylint: disable=invalid-name
    def get_accounts_in_scope_for_asset_by_name(
        self, *, asset_id, account_name, account_domain, auth_provider, auth_user
    ):
        print(
            f"Requesting accounts in scope for asset {asset_id} by name {account_name} and domain {account_domain}"
        )

        url = self._get_broker_resource(f"RequestableAssets/{asset_id}/Accounts")

        if account_domain:
            account_filter = f"Name ieq '{account_name}' AND ((DomainName eq null) OR (DomainName ieq '{account_domain}'))"
        else:
            account_filter = f"Name ieq '{account_name}'"

        request = {
            "Filter": account_filter,
            "ForUser": auth_user,
            "ForProvider": auth_provider,
        }
        return self._get(url, parameters=request, auth="SPSInteractive")

    def create_access_request(
        self, *, asset_id, account_id, auth_provider, auth_user, protocol, reason_comment
    ):
        print("Create access request")

        url = self._get_broker_resource("AccessRequests")

        protocol = "remotedesktop" if protocol == "rdp" else protocol
        access_request = {
            "AccountId": account_id,
            "SystemId": asset_id,
            "ForUser": auth_user,
            "ForProvider": auth_provider,
            "AccessRequestType": protocol,
            "ReasonCode": "SPS",
            "ReasonComment": reason_comment
        }

        return self._post(url, post_data=access_request, auth="SPSInteractive")

    def poll_access_request(self, access_request, *, auth_provider, auth_user):
        url = self._get_broker_resource(f"AccessRequests/{access_request['Id']}")

        while True:
            state = access_request.get("State", "Unknown")
            print(f"Access Request state is {state}")

            if state == "RequestAvailable":
                return

            # PendingAcknowledgment state means that the access request has either
            # been denied or expired. We have to acknowledge this.
            elif (
                state == "PendingAcknowledgment"
                or access_request["NeedsAcknowledgement"]
            ):
                self._post(
                    url + "/Acknowledge",
                    parameters={
                        "forUser": auth_user,
                        "forProvider": auth_provider,
                        "comment": "Access Request has been denied.",
                    },
                    auth="SPSInteractive",
                )

                raise AccessRequestDenied("Access request has been denied")

            time.sleep(1)

            access_request = self._get(
                url,
                parameters={"forUser": auth_user, "forProvider": auth_provider},
                auth="SPSInteractive",
            )

    def get_session_token(self, access_request, *, auth_provider, auth_user):
        return self._post(
            self._get_broker_resource(
                f"AccessRequests/{access_request['Id']}/GetSessionToken"
            ),
            parameters={"forUser": auth_user, "forProvider": auth_provider},
            auth="SPSInteractive",
        )

    def check_in_access_request(self, *, access_request_id, auth_provider, auth_user):
        print("Check in access request")

        url = self._get_broker_resource(f"AccessRequests/{access_request_id}/CheckIn")
        return self._post(
            url,
            parameters={"forUser": auth_user, "forProvider": auth_provider},
            auth="SPSInteractive",
        )

    def cancel_access_request(self, *, access_request_id, auth_provider, auth_user):
        print("Cancel access request")

        url = self._get_broker_resource(f"AccessRequests/{access_request_id}/Cancel")
        return self._post(
            url,
            parameters={"forUser": auth_user, "forProvider": auth_provider},
            auth="SPSInteractive",
        )

    def _post(self, url, parameters=None, post_data=None, auth="PsmPlugin"):
        print(
            f"POST request; url={url}, parameters={_remove_sensitive_data(post_data)}, auth={auth}"
        )

        headers = {"Authorization": f"{auth} certuser"}
        response = self._session.post(
            url, params=parameters, json=post_data, headers=headers
        )
        decoded_response = self._decode_response(response)

        print(f"Response to POST; data={_remove_sensitive_data(decoded_response)}")

        return decoded_response

    def _get(self, url, parameters=None, auth="PsmPlugin"):
        print(
            f"GET request; url={url}, parameters={_remove_sensitive_data(parameters)}, auth={auth}"
        )

        headers = {"Authorization": f"{auth} certuser"}
        response = self._session.get(url, params=parameters, headers=headers)
        decoded_response = self._decode_response(response)

        print(f"Response to GET; data={_remove_sensitive_data(decoded_response)}")

        return decoded_response

    def _decode_response(self, response):
        try:
            decoded_response = response.json()
        except json.decoder.JSONDecodeError:
            decoded_response = response.text

        if response.status_code < 200 or response.status_code >= 400:
            if isinstance(decoded_response, dict):
                status_code = decoded_response.get("Code", response.status_code)
                message = decoded_response.get("Message", "Denied by password vault")
            else:
                status_code = response.status_code
                message = "Denied by password vault"

            raise VaultError(message, status_code, response.text)

        return decoded_response


def _remove_sensitive_data(data):
    if not isinstance(data, dict):
        return data

    sensitive_keys = {"passwords", "keys", "sessionkey"}
    return {
        key: value for key, value in data.items() if key.lower() not in sensitive_keys
    }


class VaultError(Exception):
    def __init__(self, message, status_code=None, data=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.data = data

    def __str__(self):
        message = f"[ERROR] {self.message}"

        if self.status_code is not None:
            message = f"{message}; code={self.status_code}"

        if self.data is not None:
            message = f"{message}, data={self.data}"

        return message


class AccessRequestDenied(Exception):
    pass
