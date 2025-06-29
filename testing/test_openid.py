#!/usr/bin/env python3

import os
import sys
from sherpa.utils.basics import Logger
from sherpa.utils.basics import Properties


sys.path.insert(0, './sherpa/keycloak/')
from keycloak_lib import SherpaKeycloakOpenID


def main(arguments):
	properties = Properties("./testing/local.properties", "./testing/local.properties")
	logger = Logger(os.path.basename(__file__), properties.get("log_level"), "./testing/test_openid.log")
	run(logger, properties)
	logger.info("{} finished.".format(os.path.basename(__file__)))


def run(logger, properties):
	realm_name = properties.get("custom_realm")
	logger.debug("Connecting to realm: {}", realm_name)
	oidc = SherpaKeycloakOpenID(logger=logger, properties=properties, server_url=properties.get("keycloak_base_url"), realm_name=realm_name, client_id="admin-cli", client_secret_key=None)

	well_known = oidc.well_known()
	logger.info("well_known: {}", well_known)


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
