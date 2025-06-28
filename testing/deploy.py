#!/usr/bin/env python3

import os
import sys
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger

sys.path.insert(0, './sherpa/keycloak/')
from keycloak_lib import SherpaKeycloakAdmin


def main(arguments):
	properties = Properties("./testing/local.properties", "./testing/local.properties")
	logger = Logger(os.path.basename(__file__), properties.get("log_level"), properties.get("log_file"))
	run(logger, properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, properties):
	keycloak_base_url = "http://idp:8080/"
	keycloak_user = "admin"
	keycloak_password = "admin"
	temp_file = "./testing/temp.json"

	logger.debug("Connecting to master realm")
	master_admin = SherpaKeycloakAdmin(logger=logger, properties=properties, server_url=keycloak_base_url, username=keycloak_user, password=keycloak_password)

	logger.debug("Importing Clients in master realm")
	master_admin.sherpa_import_clients("./testing/objects/master/clients", temp_file)
	master_admin.sherpa_assign_realm_role_to_client("test_client_creds", "admin")

	for custom_realm in ["testrealm"]:
		logger.debug("Importing custom realm: {}", custom_realm)
		master_admin.sherpa_create_realm("./testing/objects/{}/realm.json".format(custom_realm), temp_file)

		logger.debug("Connecting to custom realm: {}", custom_realm)
		custom_admin = SherpaKeycloakAdmin(logger=logger, properties=properties, server_url=keycloak_base_url, username=keycloak_user, password=keycloak_password, user_realm_name="master", realm_name=custom_realm)

		logger.debug("Importing Clients in realm: {}", custom_realm)
		custom_admin.sherpa_import_clients("./testing/objects/{}/clients".format(custom_realm), temp_file)

		logger.debug("Importing Users in realm: {}", custom_realm)
		custom_admin.sherpa_import_users("./testing/objects/{}/users".format(custom_realm), temp_file)

		logger.debug("Importing Organizations in realm: {}", custom_realm)
		custom_admin.sherpa_import_organizations("./testing/objects/{}/organizations".format(custom_realm), temp_file)

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
