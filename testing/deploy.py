#!/usr/bin/env python3

import os
import sys
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger

sys.path.insert(0, './sherpa/keycloak/')
from keycloak_lib import SherpaKeycloakAdmin


def main(arguments):
	logger = Logger(os.path.basename(__file__), "TRACE", "./testing/setup.log")
	local_properties = Properties("./testing/local.properties", "./testing/local.properties")
	run(logger, local_properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, local_properties):
	keycloak_base_url = "http://idp:8080/"
	custom_realm = "testrealm"
	keycloak_user = "admin"
	keycloak_password = "admin"
	temp_file = "./testing/temp.json"

	logger.debug("Connecting to master realm")
	master_admin = SherpaKeycloakAdmin(logger=logger, local_properties=local_properties, server_url=keycloak_base_url, username=keycloak_user, password=keycloak_password)

	logger.debug("Importing Clients in master realm")
	master_admin.sherpa_import_clients("./testing/master_objects/clients", temp_file)
	master_admin.sherpa_assign_realm_role_to_client("test_client_creds", "admin")

	logger.debug("Importing custom realm")
	master_admin.sherpa_create_realm("./testing/objects/realm.json", temp_file)

	logger.debug("Connecting to custom realm: {}", custom_realm)
	custom_admin = SherpaKeycloakAdmin(logger=logger, local_properties=local_properties, server_url=keycloak_base_url, username=keycloak_user, password=keycloak_password, user_realm_name="master", realm_name=custom_realm)

	logger.debug("Importing Clients in custom realm")
	custom_admin.sherpa_import_clients("./testing/objects/clients", temp_file)

	logger.debug("Importing Users in custom realm")
	custom_admin.sherpa_import_users("./testing/objects/users", temp_file)


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
