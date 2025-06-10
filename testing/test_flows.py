#!/usr/bin/env python3

import os
import sys
from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties


sys.path.insert(0, './sherpa/keycloak/')
from keycloak_lib import SherpaKeycloakAdmin


def main(arguments):
	logger = Logger(os.path.basename(__file__), "DEBUG", "./testing/test_flows.log")
	properties = Properties("./testing/local.properties", "./testing/local.properties")
	run(logger, properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, properties):
	keycloak_base_url = "http://idp:8080/"
	custom_realm = "testrealm"
	keycloak_user = "admin"
	keycloak_password = "admin"

	logger.info("Connecting to custom realm: {}", custom_realm)
	custom_admin = SherpaKeycloakAdmin(logger=logger, properties=properties, server_url=keycloak_base_url, username=keycloak_user, password=keycloak_password, user_realm_name="master", realm_name=custom_realm, verify=False)

	# realm_json = custom_admin.get_realm(custom_realm)
	# logger.debug("get_realm(): {}", realm_json)

	flow_json = custom_admin.sherpa_get_authentication_flow("browser")
	logger.debug("sherpa_get_authentication_flow(): {}, type: {}", flow_json, type(flow_json))


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
