#!/usr/bin/env python3

import os
import sys
from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties


sys.path.insert(0, './sherpa/keycloak/')
from keycloak_lib import SherpaKeycloakAdmin


def main(arguments):
	properties = Properties("./testing/local.properties", "./testing/local.properties")
	logger = Logger(os.path.basename(__file__), properties.get("log_level"), "./testing/test_organizations.log")
	run(logger, properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, properties):
	custom_realm = properties.get("custom_realm")
	logger.info("Connecting to custom realm: {}", custom_realm)
	custom_admin = SherpaKeycloakAdmin(logger=logger, properties=properties, server_url=properties.get("keycloak_base_url"), username=properties.get("keycloak_user"), password=properties.get("keycloak_password"), user_realm_name="master", realm_name=custom_realm)

	custom_admin.sherpa_add_user_to_organization(username="user1", organization_alias="sherpa")
	custom_admin.sherpa_add_user_to_organization(username="user2", organization_alias="sherpa")
	custom_admin.sherpa_add_user_to_organization(username="user3", organization_alias="identicum")
	custom_admin.sherpa_add_user_to_organization(username="user4", organization_alias="identicum")


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
