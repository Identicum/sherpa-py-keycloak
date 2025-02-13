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
	logger = Logger(os.path.basename(__file__), "INFO", "./testing/test.log")
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

	ropc_clients = [
		["ropc1_client_id", "ropc1_client_secret"],
		["ropc2_client_id", "ropc2_client_secret"],
		["ropc3_client_id", "ropc3_client_secret"],
		["ropc4_client_id", "ropc4_client_secret"]
	]
	users = ['user1', 'user2', 'user3', 'user4']
	sessions_per_user = 3

	# logger.debug("Creating user sessions.")
	# oidc_client = OIDCClient(idp_url=idp_url, logger=logger)
	# for ropc_client in ropc_clients:
	# 	client_credentials=http.to_base64_creds(ropc_client[0], ropc_client[1])
	# 	for user in users:
	# 		for i in range(sessions_per_user):
	# 			oidc_client.do_ropc(client_credentials, username=user, password=user)

	logger.info("Connecting to custom realm: {}", custom_realm)
	custom_admin = SherpaKeycloakAdmin(logger=logger, local_properties=local_properties, server_url=keycloak_base_url, username=keycloak_user, password=keycloak_password, user_realm_name="master", realm_name=custom_realm)

	logger.info("Killing sessions.")
	# custom_admin.sherpa_logout_user_sessions(username='user1', client_id=None)
	# custom_admin.sherpa_logout_user_sessions(username='user2', client_id=None)
	# custom_admin.sherpa_logout_user_sessions(username='user3', client_id=None)
	# custom_admin.sherpa_logout_user_sessions(username='user4', client_id=None)
	# custom_admin.sherpa_logout_user_sessions(username='user2', client_id='ropc2_client_id')

	logger.info("get_client_sessions_stats().")
	client_session_stats = custom_admin.get_client_sessions_stats()
	for client_session_stat in client_session_stats:
		logger.info("Client: {} ({}), active sesions: {}, offline sessions: {}", client_session_stat['clientId'], client_session_stat['id'], client_session_stat['active'], client_session_stat['offline'])

	# logger.info("sherpa_get_client_sessions().")
	# for ropc_client in ropc_clients:
	# 	client_id = ropc_client[0]
	# 	client_sessions = custom_admin.sherpa_get_client_sessions(client_id=client_id)
	# 	logger.info("Client sessions for {}: {}", client_id, len(client_sessions))

	logger.info("sherpa_get_user_client_offlinesessions().")
	client_id = 'ropc3_client_id'
	username = 'user2'
	user_client_offlinesessions = custom_admin.sherpa_get_user_client_offlinesessions(username=username, client_id=client_id)
	logger.info("Offline sessions for client_id: {}, username: {} are: {}", client_id, username, len(user_client_offlinesessions))




if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
