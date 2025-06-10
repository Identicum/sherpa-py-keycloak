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
	logger = Logger(os.path.basename(__file__), "DEBUG", "./testing/test_sessions.log")
	properties = Properties("./testing/local.properties", "./testing/local.properties")
	run(logger, properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, properties):
	keycloak_base_url = "http://idp:8080/"
	custom_realm = "testrealm"
	keycloak_user = "admin"
	keycloak_password = "admin"
	temp_file = "./testing/temp.json"
	idp_url = keycloak_base_url + "realms/" + custom_realm

	ropc_clients = [
		["ropc01_client_id", "ropc01_client_secret"],
		["ropc02_client_id", "ropc02_client_secret"],
		["ropc03_client_id", "ropc03_client_secret"],
		["ropc04_client_id", "ropc04_client_secret"],
		["ropc05_client_id", "ropc05_client_secret"],
		["ropc06_client_id", "ropc06_client_secret"],
		["ropc07_client_id", "ropc07_client_secret"],
		["ropc08_client_id", "ropc08_client_secret"],
		["ropc09_client_id", "ropc09_client_secret"],
		["ropc10_client_id", "ropc10_client_secret"]
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
	custom_admin = SherpaKeycloakAdmin(logger=logger, properties=properties, server_url=keycloak_base_url, username=keycloak_user, password=keycloak_password, user_realm_name="master", realm_name=custom_realm)

	client_session_stats = custom_admin.get_client_sessions_stats()
	logger.debug("get_client_sessions_stats(): {}", client_session_stats)
	sorted_client_session_stats = sorted(client_session_stats, key=lambda x: x['clientId'])
	for client_session_stat in sorted_client_session_stats:
		logger.info("get_client_sessions_stats() ({}), active: {}, offline: {}", client_session_stat['clientId'], client_session_stat['active'], client_session_stat['offline'])

	for ropc_client in ropc_clients:
		client_id = ropc_client[0]
		client_keycloak_id = custom_admin.get_client_id(client_id)
		client_session_count = custom_admin.get_client_sessioncount(client_id=client_keycloak_id)
		logger.info("get_client_sessioncount({}): {}", client_id, client_session_count)

	for ropc_client in [ropc_clients[1], ropc_clients[3]]:
		client_id = ropc_client[0]
		client_keycloak_id = custom_admin.get_client_id(client_id)
		query = { "first": 0, "max": 1000 }
		client_sessions = custom_admin.get_client_all_sessions(client_id=client_keycloak_id, query=query)
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
