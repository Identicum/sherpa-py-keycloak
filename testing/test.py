#!/usr/bin/env python3

import os
import sys
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.utils.clients import OIDCClient
import sherpa.utils.http as http


sys.path.insert(0, './sherpa/keycloak/')
from keycloak_lib import SherpaKeycloakAdmin


def main(arguments):
	logger = Logger(os.path.basename(__file__), "TRACE", "./testing/test.log")
	local_properties = Properties("./testing/local.properties", "./testing/local.properties")
	run(logger, local_properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, local_properties):
	keycloak_base_url = "http://idp:8080/"
	custom_realm = "testrealm"
	keycloak_user = "admin"
	keycloak_password = "admin"
	temp_file = "./testing/temp.json"
	idp_url = keycloak_base_url + "realms/" + custom_realm

	logger.debug("Creating user sessions.")
	oidc_client = OIDCClient(idp_url=idp_url, logger=logger)
	for client_credentials in [http.to_base64_creds('ropc1_client_id', 'ropc1_client_secret'),
							   http.to_base64_creds('ropc2_client_id', 'ropc2_client_secret')]:
		for user in ['user1', 'user2', 'user3']:
			oidc_client.do_ropc(client_credentials, username=user, password=user)

	logger.debug("Connecting to custom realm: {}", custom_realm)
	custom_admin = SherpaKeycloakAdmin(logger=logger, local_properties=local_properties, server_url=keycloak_base_url, username=keycloak_user, password=keycloak_password, user_realm_name="master", realm_name=custom_realm)

	custom_admin.sherpa_logout_user_sessions(username='user1', client_id=None)
	custom_admin.sherpa_logout_user_sessions(username='user2', client_id='ropc2_client_id')



if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
