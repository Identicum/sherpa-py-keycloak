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

	ropc_clients = [
		["ropc1_client_id", "ropc1_client_secret"],
		["ropc2_client_id", "ropc2_client_secret"],
		["ropc3_client_id", "ropc3_client_secret"],
		["ropc4_client_id", "ropc4_client_secret"]
	]
	users = ['user1', 'user2', 'user3', 'user4']
	sessions_per_user = 2

	logger.debug("Creating user sessions.")
	oidc_client = OIDCClient(idp_url=idp_url, logger=logger)
	for ropc_client in ropc_clients:
		client_credentials=http.to_base64_creds(ropc_client[0], ropc_client[1])
		for user in users:
			for i in range(sessions_per_user):
				oidc_client.do_ropc(client_credentials, username=user, password=user)

	logger.info("Connecting to custom realm: {}", custom_realm)
	custom_admin = SherpaKeycloakAdmin(logger=logger, local_properties=local_properties, server_url=keycloak_base_url, username=keycloak_user, password=keycloak_password, user_realm_name="master", realm_name=custom_realm)

	client_session_stats = custom_admin.get_client_sessions_stats()
	for client_session_stat in client_session_stats:
		logger.info("get_client_sessions_stats() ({}), active: {}, offline: {}", client_session_stat['clientId'], client_session_stat['active'], client_session_stat['offline'])

	for ropc_client in ropc_clients:
		client_id = ropc_client[0]
		client_keycloak_id = custom_admin.get_client_id(client_id)
		client_session_count = custom_admin.get_client_sessioncount(client_id=client_keycloak_id)
		logger.info("get_client_sessioncount({}): {}", client_id, client_session_count)

	for ropc_client in ropc_clients:
		client_id = ropc_client[0]
		client_keycloak_id = custom_admin.get_client_id(client_id)
		client_sessions = custom_admin.get_client_all_sessions(client_id=client_keycloak_id)
		logger.info("get_client_all_sessions({}): {}", client_id, len(client_sessions))

	for ropc_client in ropc_clients:
		client_id = ropc_client[0]
		client_keycloak_id = custom_admin.get_client_id(client_id)
		client_session_count = custom_admin.get_client_offlinesessioncount(client_id=client_keycloak_id)
		logger.info("get_client_offlinesessioncount({}): {}", client_id, client_session_count)

	for ropc_client in ropc_clients:
		client_id = ropc_client[0]
		client_keycloak_id = custom_admin.get_client_id(client_id)
		client_offline_sessions = custom_admin.get_client_offlinesessions(client_id=client_keycloak_id)
		logger.info("get_client_offlinesessions({}): {}", client_id, len(client_offline_sessions))
		if len(client_offline_sessions) > 0:
			logger.info("First offline session: {}", client_offline_sessions[0])

	for username in [users[0], users[1]]:
		user_id = custom_admin.get_user_id(username)
		for ropc_client in ropc_clients:
			client_id = ropc_client[0]
			client_keycloak_id = custom_admin.get_client_id(client_id)
			user_client_offlinesessions = custom_admin.get_user_client_offlinesessions(user_id=user_id, client_id=client_keycloak_id)
			logger.info("get_user_client_offlinesessions({}, {}): {}", username, client_id, len(user_client_offlinesessions))

	client_id = ropc_clients[3][0]
	client_keycloak_id = custom_admin.get_client_id(client_id)
	client_offline_sessions = custom_admin.get_client_offlinesessions(client_id=client_keycloak_id)
	for client_offline_session in client_offline_sessions:
		logger.info("Delete session feedback: {}", custom_admin.delete_session(client_offline_session['id'], isOffline=True))

	logger.info("logout_all_users(): {}", custom_admin.logout_all_users())


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
