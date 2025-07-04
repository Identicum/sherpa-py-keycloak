# sherpa-py-keycloak is available under the MIT License. https://github.com/Identicum/sherpa-py-keycloak/
# Copyright (c) 2024, Identicum - https://identicum.com/
#
# Authors:
#   Gustavo J Gallardo - ggallard@identicum.com
#

import json
import os
import shutil
from importlib.metadata import version
from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.urls_patterns import URL_ADMIN_REALM, URL_ADMIN_USER, URL_ADMIN_CLIENT
from keycloak.exceptions import (
     KeycloakDeleteError,
     KeycloakGetError,
     KeycloakPostError,
     KeycloakPutError,
     raise_error_from_response
)
from sherpa.utils import validators
from sherpa.utils.clients import OIDCClient


URL_ADMIN_REALM_USERPROFILE = URL_ADMIN_REALM + "/users/profile"
URL_ADMIN_REALM_LOGOUT_ALL = URL_ADMIN_REALM + "/logout-all"
URL_ADMIN_SESSION = "admin/realms/{realm-name}/sessions/{id}"
URL_ADMIN_USER_CLIENT_OFFLINESESSIONS = URL_ADMIN_USER + "/offline-sessions/{client-id}"
URL_ADMIN_CLIENT_SESSION_COUNT = URL_ADMIN_CLIENT + "/session-count"
URL_ADMIN_CLIENT_OFFLINESESSION_COUNT = URL_ADMIN_CLIENT + "/offline-session-count"
URL_ADMIN_CLIENT_OFFLINESESSIONS = URL_ADMIN_CLIENT + "/offline-sessions"



class SherpaKeycloakOpenID(KeycloakOpenID):
	def __init__(self, logger, properties, server_url, realm_name, client_id, client_secret_key=None, verify=True, custom_headers=None, proxies=None, cert=None):
		self.logger = logger
		self.properties = properties
		logger.debug("KeycloakOpenID version: " + version("sherpa-py-keycloak"))
		self.logger.debug("Initializing with server_url: {}, realm_name: {}, client_id: {}, verify={}, custom_headers={}, proxies={}, cert={}", server_url, realm_name, client_id, verify, custom_headers, proxies, cert)
		KeycloakOpenID.__init__(self, server_url=server_url, realm_name=realm_name, client_id=client_id, client_secret_key=client_secret_key, verify=verify, custom_headers=custom_headers, proxies=proxies, cert=cert)


class SherpaKeycloakAdmin(KeycloakAdmin):
	def __init__(self, logger, properties, server_url, username=None, password=None, realm_name='master', client_id='admin-cli', verify=True, client_secret_key=None, custom_headers=None, user_realm_name=None):
		self.logger = logger
		self.properties = properties
		logger.debug("SherpaKeycloakAdmin version: " + version("sherpa-py-keycloak"))
		if username is not None:
			logger.trace("Authenticating using username: {}", username)
			if password is None or password == "":
				validators.raise_and_log(logger, Exception, "Missing password for username: {}", username)
		else:
			logger.trace("Authenticating using client_credentials")
			if client_id is None or client_id == "" or client_secret_key is None or client_secret_key == "":
				validators.raise_and_log(logger, Exception, "Missing client_id or client_secret: {}", user_realm_name)
		self.logger.debug("Initializing with server_url: {}, username: {}, realm_name: {}, client_id: {}, user_realm_name: {}", server_url, username, realm_name, client_id, user_realm_name)
		KeycloakAdmin.__init__(self, server_url=server_url, username=username, password=password, realm_name=realm_name, client_id=client_id, verify=verify, client_secret_key=client_secret_key, custom_headers=custom_headers, user_realm_name=user_realm_name)

	# ######################################################
	# Added methods

	def get_realm_userprofile(self):
		"""Get the realm's UserProfile config.

		UPConfig:
		https://www.keycloak.org/docs-api/25.0.2/rest-api/index.html#UPConfig

		:return: UPConfig
		:rtype: dict
		"""
		params_path = {"realm-name": self.connection.realm_name}
		data_raw = self.connection.raw_get(URL_ADMIN_REALM_USERPROFILE.format(**params_path))
		return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])


	def update_realm_userprofile(self, payload):
		"""Update the realm's UserProfile config.

		:param payload: UPConfig
		:type payload: dict

		:return: Http response
		:rtype: bytes
		"""
		params_path = {"realm-name": self.connection.realm_name, "payload": payload}
		data_raw = self.connection.raw_put(
			URL_ADMIN_REALM_USERPROFILE.format(**params_path), data=json.dumps(payload)
		)
		return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[200])


	def update_realm_unmanagedAttributes(self, unmanaged_attributes_policy):
		"""Set the unmanaged attributes policy for a realm.

		:param unmanaged_attributes_policy: Unmanaged attributes policy
		:type unmanaged_attributes_policy: str
		"""
		userprofile = self.get_realm_userprofile()
		if unmanaged_attributes_policy == "DISABLED":
			# delete node
			userprofile.pop("unmanagedAttributePolicy", None)
		else:
			userprofile["unmanagedAttributePolicy"] = unmanaged_attributes_policy
		self.update_realm_userprofile(userprofile)


	def delete_session(self, session_id, isOffline=False):
		""" Delete specific session

		:param session_id: Session id
		:type session_id: str

		:returns: Keycloak server response
		:rtype: bytes
		"""
		self.logger.trace("Deleting session: {}", session_id)
		params_path = {"realm-name": self.connection.realm_name, "id": session_id}
		data_raw = self.connection.raw_delete(URL_ADMIN_SESSION.format(**params_path)+"?isOffline="+str(isOffline).lower())
		return raise_error_from_response(data_raw, KeycloakDeleteError, expected_codes=[204])


	def logout_all_users(self):
		""" Logout all users in realm
		POST /admin/realms/{realm-name}/logout-all


		:return: Http response
		:rtype: bytes
		"""
		params_path = {"realm-name": self.connection.realm_name}
		data_raw = self.connection.raw_post(URL_ADMIN_REALM_LOGOUT_ALL.format(**params_path), data="")
		return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[200])


	def get_client_sessioncount(self, client_id=None):
		"""Get the (online) sessions for a particular Client.
		GET /admin/realms/{realm-name}/clients/{client-id}/session-count

		:param client_id: Client's keycloak id
		:type client_id: str

		:returns: Keycloak server response
		:rtype: bytes
		"""
		params_path = {"realm-name": self.connection.realm_name, "id": client_id}
		data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_SESSION_COUNT.format(**params_path))
		return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])


	def get_user_client_offlinesessions(self, user_id=None, client_id=None):
		"""Get the users's offline sessions for a particular Client.
		GET /admin/realms/{realm-name}/users/{id}/offline-sessions/{client-id}

		:param user_id: User's keycloak id
		:type user_id: str
		:param client_id: Client's keycloak id
		:type client_id: str

		:returns: Keycloak server response
		:rtype: bytes
		"""
		params_path = {"realm-name": self.connection.realm_name, "id": user_id, "client-id": client_id}
		data_raw = self.connection.raw_get(URL_ADMIN_USER_CLIENT_OFFLINESESSIONS.format(**params_path))
		return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])


	def get_client_offlinesessioncount(self, client_id=None):
		"""Get the offline sessions for a particular Client.
		GET /admin/realms/{realm-name}/clients/{id}/offline-session-count

		:param client_id: Client's keycloak id
		:type client_id: str

		:returns: Keycloak server response
		:rtype: bytes
		"""
		params_path = {"realm-name": self.connection.realm_name, "id": client_id}
		data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_OFFLINESESSION_COUNT.format(**params_path))
		return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])


	def get_client_offlinesessions(self, client_id=None):
		"""Get the offline sessions for a particular Client.
		Returns PAGINATED
		GET /admin/realms/{realm-name}/clients/{id}/offline-sessions

		:param client_id: Client's keycloak id
		:type client_id: str

		:returns: Keycloak server response
		:rtype: bytes
		"""
		params_path = {"realm-name": self.connection.realm_name, "id": client_id}
		data_raw = self.connection.raw_get(URL_ADMIN_CLIENT_OFFLINESESSIONS.format(**params_path))
		return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])


	def logout_user_client_sessions(self, user_id, client_id):
		""" Logout user sessions for a specific Client.

		:param user_id: User id
		:type user_id: str
		:param client_keycloak_id: Client's keycloak id
		:type client_keycloak_id: str

		:returns: Keycloak server response
		:rtype: bytes
		"""
		client_sessions = self.get_client_all_sessions(client_id)
		self.logger.debug("client_sessions: {}", client_sessions)
		for client_session in client_sessions:
			if client_session["userId"] == user_id:
				self.logger.debug("Logging out user session: {}", client_session["id"])
				self.delete_session(client_session["id"])


	def logout_user_client_offlinesessions(self, user_id, client_id):
		""" Logout user offline sessions for a specific Client.

		:param user_id: User id
		:type user_id: str
		:param client_keycloak_id: Client's keycloak id
		:type client_keycloak_id: str

		:returns: Keycloak server response
		:rtype: bytes
		"""
		client_offline_sessions = self.get_client_offlinesessions(client_id)
		self.logger.debug("client_offline_sessions: {}", client_offline_sessions)
		for client_offline_session in client_offline_sessions:
			if client_offline_session["userId"] == user_id:
				self.logger.debug("Logging out user offline session: {}", client_offline_session["id"])
				self.delete_session(client_offline_session["id"], isOffline=True)


	# ######################################################
	# Sherpa methods

	def sherpa_client_exists(self, client_id):
		clients = self.get_clients()
		for client in clients:
			# self.logger.trace("client: {}", client)
			# self.logger.trace("client_id: {}", client["clientId"])
			if client["clientId"] == client_id:
				return True
		return False


	def sherpa_get_client_keycloakid(self, client_id):
		clients = self.get_clients()
		for client in clients:
			if client_id == client.get('clientId'):
				return client["id"]
		return None


	def sherpa_get_organization_id(self, organization_name=None, organization_alias=None):
		if organization_name is not None:
			query = {"name": organization_name}
		elif organization_alias is not None:
			query = {"alias": organization_alias}
		else:
			return None
		organizations = self.get_organizations(query=query)
		for organization in organizations:
			if organization["name"] == organization_name or organization["alias"] == organization_alias:
				return organization["id"]
		return None


	# def sherpa_component_exists(self, component_id, parent, provider_type):
	# 	query = {"parent":parent, "type":provider_type}
	# 	self.logger.trace("query: {}", query)
	# 	components = self.get_components(query=query)
	# 	for component in components:
	# 		self.logger.trace("component: {}", component)
	# 		self.logger.trace("component_id: {}", component["id"])
	# 		if component["id"] == component_id:
	# 			return True
	# 	return False


	# def sherpa_delete_component_childs(self, component_id):
	# 	query = {"parent": component_id}
	# 	self.logger.trace("query: {}", query)
	# 	components = self.get_components(query=query)
	# 	for component in components:
	# 		self.logger.debug("Deleting component_id: {}", component["id"])
	# 		self.delete_component(component["id"])


	# def sherpa_idp_exists(self, idp_alias):
	# 	idps = self.get_idps()
	# 	for idp in idps:
	# 		self.logger.trace("idp: {}", idp)
	# 		self.logger.trace("idp alias: {}", idp["alias"])
	# 		if idp["alias"] == idp_alias:
	# 			return True
	# 	return False


	def sherpa_get_authentication_flow(self, flow_alias):
		authentication_flows = self.get_authentication_flows()
		for authentication_flow in authentication_flows:
			self.logger.trace("sherpa_get_authentication_flow(). Searching: {}, current: {}", flow_alias, authentication_flow["alias"])
			if authentication_flow["alias"] == flow_alias:
				return authentication_flow
		self.logger.debug("sherpa_get_authentication_flow(). Flow '{}' not found.", flow_alias)
		return None


	# def sherpa_get_subflow_by_id(self, flow_alias, execution_id):
	# 	executions = self.get_authentication_flow_executions(flow_alias)
	# 	self.logger.debug("Getting execution flow with id: {} from authentication flow: {}. Executions: {}", execution_id, flow_alias, executions)
	# 	for execution in executions:
	# 		self.logger.trace("sherpa_get_subflow_by_id(). Searching: '{}', current: '{}'.", execution_id, execution["id"])
	# 		if "flowId" in execution:
	# 			if execution["flowId"] == execution_id:
	# 				return execution
	# 	return None


	# def sherpa_get_subflow_by_alias(self, flow_alias, execution_alias):
	# 	executions = self.get_authentication_flow_executions(flow_alias)
	# 	self.logger.debug("Getting subflow with alias: {} from authentication flow: {}. Executions: {}", execution_alias, flow_alias, executions)
	# 	for execution in executions:
	# 		self.logger.trace("sherpa_get_subflow_by_alias(). Searching: '{}' in: '{}'.", execution_alias, execution)
	# 		if "displayName" in execution:
	# 			if execution["displayName"] == execution_alias:
	# 				return execution
	# 	return None


	def sherpa_create_realm(self, realm_json_file, temp_file):
		shutil.copyfile(realm_json_file, temp_file)
		self.properties.replace(temp_file)
		with open(temp_file) as json_file:
			json_data = json.load(json_file)
			self.logger.trace("json_data: {}", json_data)
			self.create_realm(json_data, skip_exists=True)


	# def sherpa_set_default_default_client_scopes(self, client_scopes):
	# 	self.logger.debug("Setting default default client scopes with: {}", client_scopes)
	# 	current_scopes = self.get_default_default_client_scopes()
	# 	self.logger.trace("Current default default client scopes: {}", current_scopes)
	# 	for current_scope in current_scopes:
	# 		self.logger.trace("Processing possible removal of default default client scope. id: {}, name: {}, protocol: {}", current_scope["id"], current_scope["name"], current_scope["protocol"])
	# 		if current_scope["name"] not in client_scopes:
	# 			self.logger.debug("Deleting default default client scope: {}", current_scope["name"])
	# 			self.delete_default_default_client_scope(current_scope["id"])
	# 	for new_scope in client_scopes:
	# 		add_scope = True
	# 		for current_scope in current_scopes:
	# 			if current_scope["name"] == new_scope:
	# 				add_scope = False
	# 		if add_scope:
	# 			new_scope_id = self.get_client_scope_id(new_scope)
	# 			self.logger.debug("Adding default default client scope: {}, id: {}", new_scope, new_scope_id)
	# 			self.add_default_default_client_scope(new_scope_id)


	# def sherpa_set_default_optional_client_scopes(self, client_scopes):
	# 	self.logger.debug("Setting default optional client scopes with: {}", client_scopes)
	# 	current_scopes = self.get_default_optional_client_scopes()
	# 	self.logger.trace("Current default optional client scopes: {}", current_scopes)
	# 	for current_scope in current_scopes:
	# 		self.logger.trace("Processing possible removal of default optional client scope. id: {}, name: {}, protocol: {}", current_scope["id"], current_scope["name"], current_scope["protocol"])
	# 		if current_scope["name"] not in client_scopes:
	# 			self.logger.debug("Deleting default optional client scope: {}", current_scope["name"])
	# 			self.delete_default_optional_client_scope(current_scope["id"])
	# 	for new_scope in client_scopes:
	# 		add_scope = True
	# 		for current_scope in current_scopes:
	# 			if current_scope["name"] == new_scope:
	# 				add_scope = False
	# 		if add_scope:
	# 			new_scope_id = self.get_client_scope_id(new_scope)
	# 			self.logger.debug("Adding default optional client scope: {}, id: {}", new_scope, new_scope_id)
	# 			self.add_default_optional_client_scope(new_scope_id)


	# def sherpa_update_realm_attributes(self, objects_folder, realm_name, temp_file):
	# 	self.logger.debug("Importing realm attributes")
	# 	for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
	# 		if directory_entry.is_file() and directory_entry.path.endswith(".json"):
	# 			self.logger.debug("Processing file: {}", directory_entry.path)
	# 			shutil.copyfile(directory_entry.path, temp_file)
	# 			self.properties.replace(temp_file)
	# 			with open(temp_file) as json_file:
	# 				json_data = json.load(json_file)
	# 				if "defaultDefaultClientScopes" in json_data:
	# 					self.logger.debug("Setting default default client scopes")
	# 					self.sherpa_set_default_default_client_scopes(json_data["defaultDefaultClientScopes"])
	# 					json_data.pop("defaultDefaultClientScopes")
	# 				if "defaultOptionalClientScopes" in json_data:
	# 					self.logger.debug("Setting default optional client scopes")
	# 					self.sherpa_set_default_optional_client_scopes(json_data["defaultOptionalClientScopes"])
	# 					json_data.pop("defaultOptionalClientScopes")
	# 				self.logger.trace("json_data: {}", json_data)
	# 				self.update_realm(realm_name, json_data)


	# def sherpa_import_components(self, objects_folder, realm_id, temp_file):
	# 	self.logger.debug("Importing components from: {}", objects_folder)
	# 	for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
	# 		if directory_entry.is_file() and directory_entry.path.endswith(".json"):
	# 			self.logger.debug("Processing file: {}", directory_entry.path)
	# 			shutil.copyfile(directory_entry.path, temp_file)
	# 			self.properties.replace(temp_file)
	# 			with open(temp_file) as json_file:
	# 				json_data = json.load(json_file)
	# 				self.logger.trace("Component definition: {}", json_data)
	# 				component_id = json_data["id"]
	# 				provider_type = json_data["providerType"]
	# 				if "parentId" in json_data:
	# 					parent = json_data["parentId"]
	# 				else:
	# 					parent = realm_id
	# 				if self.sherpa_component_exists(component_id, parent, provider_type):
	# 					self.logger.debug("Component '{}' already exists. Updating...", component_id)
	# 					self.update_component(component_id, json_data)
	# 				else:
	# 					self.logger.debug("Component '{}' does not exist. Creating...", component_id)
	# 					self.create_component(json_data)
	# 					self.logger.debug("Deleting default childs for component_id:  ", component_id)
	# 					self.sherpa_delete_component_childs(component_id)


	# def sherpa_import_idps(self, objects_folder, temp_file):
	# 	self.logger.debug("Importing ID providers from: {}", objects_folder)
	# 	for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
	# 		if directory_entry.is_file() and directory_entry.path.endswith(".json"):
	# 			self.logger.debug("Processing file: {}", directory_entry.path)
	# 			shutil.copyfile(directory_entry.path, temp_file)
	# 			self.properties.replace(temp_file)
	# 			with open(temp_file) as json_file:
	# 				json_data = json.load(json_file)
	# 				self.logger.trace("ID provider definition: {}", json_data)
	# 				idp_alias = json_data["alias"]
	# 				if self.sherpa_idp_exists(idp_alias):
	# 					self.logger.debug("ID provider '{}' already exists. Updating...", idp_alias)
	# 					self.update_idp(idp_alias, json_data)
	# 				else:
	# 					self.logger.debug("Identity provider '{}' does not exist. Creating...", idp_alias)
	# 					self.create_idp(json_data)


	# def sherpa_update_execution(self, authentication_execution, flow_alias):
	# 	self.logger.debug("Updating authentication flow executions")
	# 	authentication_execution_config = ""
	# 	if "config" in authentication_execution:
	# 		authentication_execution_config = authentication_execution["config"]
	# 		authentication_execution.pop("config", None)
	# 	self.logger.debug("Updating Authentication Flow Execution using: {}", authentication_execution)
	# 	self.update_authentication_flow_executions(authentication_execution, flow_alias)
	# 	if authentication_execution_config != "":
	# 		self.logger.debug("Creating execution using: {}", authentication_execution_config)
	# 		self.create_authenticator_config(authentication_execution_config, authentication_execution["id"])
	# 		self.logger.trace("Created execution config: {}", authentication_execution_config)


	# def sherpa_delete_execution(self, execution_id, flow_alias):
	# 	self.logger.debug("Deleting execution id: {}", execution_id)
	# 	execution = self.get_authentication_flow_execution(execution_id)
	# 	self.logger.debug("Execution to be deleted: {}", execution)
	# 	if "flowId" not in execution:
	# 		self.logger.debug("Execution is NOT subflow, deleting: {}", execution)
	# 		self.delete_authentication_flow_execution(execution_id)
	# 	else:
	# 		self.logger.debug("Execution is subflow, getting executions. Subflow: {}", execution)
	# 		subflow = self.get_authentication_flow_for_id(execution["flowId"])
	# 		self.logger.debug("Subflow (full): {}", subflow)
	# 		# delete childs first
	# 		if "authenticationExecutions" in subflow:
	# 			for authentication_execution in subflow["authenticationExecutions"]:
	# 				if "flowAlias" in authentication_execution:
	# 					self.logger.debug("Deleting subflow alias '{}'", authentication_execution["flowAlias"])
	# 					full_subflow = self.sherpa_get_subflow_by_alias(flow_alias, authentication_execution["flowAlias"])
	# 					self.logger.debug("Full subflow: '{}'", full_subflow)
	# 					self.sherpa_delete_execution(full_subflow["id"], flow_alias)
	# 		# then delete execution subflow
	# 		self.logger.debug("Finally deleting execution id: {}", execution_id)
	# 		self.delete_authentication_flow_execution(execution_id)


	# def sherpa_import_authentication_flows(self, objects_folder, temp_file):
	# 	self.logger.debug("Importing authentication flows")
	# 	for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
	# 		if directory_entry.is_file() and directory_entry.path.endswith(".json"):
	# 			self.logger.debug("Processing file: {}", directory_entry.path)
	# 			shutil.copyfile(directory_entry.path, temp_file)
	# 			self.properties.replace(temp_file)
	# 			with open(temp_file) as json_file:
	# 				authentication_flow = json.load(json_file)
	# 				authentication_executions = authentication_flow["authenticationExecutions"]
	# 				self.logger.trace("json_data: {}", authentication_flow)

	# 				# Create flow without executions (if flow does not exist)
	# 				authentication_flow.pop("authenticationExecutions", None)
	# 				self.logger.debug("Creating authentication flow using: {}", authentication_flow)
	# 				flow_alias = authentication_flow["alias"]
	# 				self.logger.trace("Flow alias: {}", flow_alias)
	# 				# create_authentication_flow() expects payload as dict, not string
	# 				self.create_authentication_flow(authentication_flow, skip_exists=True)

	# 				# Delete any current (level=0) executions from flow
	# 				current_executions = self.get_authentication_flow_executions(flow_alias)
	# 				self.logger.trace("Current executions for flow alias '{}': {}", flow_alias, current_executions)
	# 				for current_execution in current_executions:
	# 					if current_execution["level"] == 0:
	# 						self.logger.debug("Deleting execution: {}", current_execution)
	# 						self.sherpa_delete_execution(current_execution["id"], flow_alias)

	# 				# Add new executions
	# 				for authentication_execution in authentication_executions:
	# 					self.logger.debug("Processing execution: {}", authentication_execution)
	# 					if "alias" in authentication_execution:
	# 						# if subflow, delete and re-create
	# 						execution_alias = authentication_execution["alias"]
	# 						self.logger.debug("Searching subflow '{}' in flow '{}'", execution_alias, flow_alias)
	# 						execution_flow = self.sherpa_get_subflow_by_alias(flow_alias, execution_alias)
	# 						self.logger.debug("Subflow found: {}", execution_flow)
	# 						if execution_flow is not None:
	# 							self.sherpa_delete_execution(execution_flow["id"], flow_alias)
	# 						# add new execution flow
	# 						create_payload = {}
	# 						create_payload["alias"] = execution_alias
	# 						create_payload["type"] = "basic-flow"
	# 						self.logger.debug("Adding subflow: {}", create_payload)
	# 						self.create_authentication_flow_subflow(create_payload, flow_alias, skip_exists=False)
	# 						execution_flow = self.sherpa_get_subflow_by_alias(flow_alias, execution_alias)
	# 						self.logger.trace("Current subflow: {}", execution_flow)
	# 						update_payload = {}
	# 						update_payload["id"] = execution_flow["id"]
	# 						for attr, value in authentication_execution.items():
	# 							self.logger.debug("Set attr: {} with value: {} in the execution_flow", attr, value)
	# 							update_payload[attr] = value
	# 						self.logger.debug("Update execution in {} with: {}", flow_alias, update_payload)
	# 						self.sherpa_update_execution(update_payload, flow_alias)
	# 					else:
	# 						create_payload = {}
	# 						create_payload["provider"] = authentication_execution["providerId"]
	# 						self.logger.debug("Creating subflow using: {}", create_payload)
	# 						created_flow_execution = self.create_authentication_flow_execution(create_payload, flow_alias)
	# 						self.logger.trace("Created subflow: {}", created_flow_execution)
	# 						authentication_execution["id"] = created_flow_execution
	# 						self.sherpa_update_execution(authentication_execution, flow_alias)


	# def sherpa_get_execution_by_provider(self, flow_alias, execution_provider_id):
	# 	executions = self.get_authentication_flow_executions(flow_alias)
	# 	for execution in executions:
	# 		self.logger.trace("execution: {}", execution)
	# 		if execution["providerId"] == execution_provider_id:
	# 			return execution
	# 	return None


	# def sherpa_set_execution_attribute(self, flow_alias, execution_provider_id, attr_name, attr_value):
	# 	execution = self.sherpa_get_execution_by_provider(flow_alias, execution_provider_id)
	# 	self.logger.debug("Current execution: {}", execution)
	# 	execution[attr_name] = attr_value
	# 	self.logger.debug("Updating execution to: {}", execution)
	# 	self.update_authentication_flow_executions(execution, flow_alias)


	# def sherpa_import_client_scopes(self, objects_folder, temp_file):
	# 	self.logger.debug("Importing client scopes from: {}", objects_folder)
	# 	for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
	# 		if directory_entry.is_file() and directory_entry.path.endswith(".json"):
	# 			self.logger.debug("Processing file: {}", directory_entry.path)
	# 			shutil.copyfile(directory_entry.path, temp_file)
	# 			self.properties.replace(temp_file)
	# 			with open(temp_file) as json_file:
	# 				json_data = json.load(json_file)
	# 				self.logger.trace("Client scope definition: {}", json_data)
	# 				client_scope_name = json_data["name"]
	# 				client_scope_id = self.get_client_scope_id(client_scope_name)
	# 				if client_scope_id is not None:
	# 					self.logger.debug("Client scope '{}' already exists with internal id: '{}'. Updating attributes.", client_scope_name, client_scope_id)
	# 					# update_client_scope() does NOT update mappers.
	# 					self.update_client_scope(client_scope_id, json_data)
	# 					deployed_client_scope = self.get_client_scope(client_scope_id)
	# 					self.logger.debug("Deployed client scope: '{}'", deployed_client_scope)
	# 					if "protocolMappers" in deployed_client_scope:
	# 						deployed_mappers = deployed_client_scope["protocolMappers"]
	# 						for deployed_mapper in deployed_mappers:
	# 							deployed_mapper_id = deployed_mapper["id"]
	# 							deployed_mapper_name = deployed_mapper["name"]
	# 							self.logger.debug("Deleting deployed mapper '{}' ({}) from client_scope: {}", deployed_mapper_name, deployed_mapper_id, client_scope_name)
	# 							self.delete_mapper_from_client_scope(client_scope_id, deployed_mapper_id)
	# 					else:
	# 						self.logger.debug("Deployed client scope '{}' ({}) has NO protocol mappers.", client_scope_name, client_scope_id)
	# 					if "protocolMappers" in json_data:
	# 						new_mappers = json_data["protocolMappers"]
	# 						for new_mapper in new_mappers:
	# 							self.logger.debug("Adding mapper: '{}' to client_scope: {}", new_mapper, client_scope_name)
	# 							self.add_mapper_to_client_scope(client_scope_id, new_mapper)
	# 					else:
	# 						self.logger.debug("Updated client scope '{}' has NO protocol mappers.", client_scope_name)
	# 					self.logger.debug("Client scope '{}' updated.", client_scope_name)
	# 				else:
	# 					self.logger.debug("Client scope '{}' does not exist. Creating...", client_scope_name)
	# 					self.create_client_scope(json_data, skip_exists=True)


	def sherpa_import_clients(self, objects_folder, temp_file):
		self.logger.debug("Importing clients from: {}", objects_folder)
		for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
			if directory_entry.is_file() and directory_entry.path.endswith(".json"):
				self.logger.debug("Processing file: {}", directory_entry.path)
				shutil.copyfile(directory_entry.path, temp_file)
				self.properties.replace(temp_file)
				with open(temp_file) as json_file:
					json_data = json.load(json_file)
					self.logger.trace("Client definition: {}", json_data)
					client_id = json_data["clientId"]
					if self.sherpa_client_exists(client_id):
						client_keycloak_id = self.sherpa_get_client_keycloakid(client_id)
						self.logger.debug("Client '{}' already exists with internal id: {}. Updating...", client_id, client_keycloak_id)
						self.update_client(client_keycloak_id, json_data)
					else:
						self.logger.debug("Client '{}' does not exist. Creating...", client_id)
						self.create_client(json_data, skip_exists=True)


	def sherpa_import_users(self, objects_folder, temp_file):
		self.logger.debug("Importing users from: {}", objects_folder)
		for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
			if directory_entry.is_file() and directory_entry.path.endswith(".json"):
				self.logger.debug("Processing file: {}", directory_entry.path)
				shutil.copyfile(directory_entry.path, temp_file)
				self.properties.replace(temp_file)
				with open(temp_file) as json_file:
					json_data = json.load(json_file)
					self.logger.trace("User definition: {}", json_data)
					self.create_user(json_data, exist_ok=True)


	def sherpa_import_organizations(self, objects_folder, temp_file):
		self.logger.debug("Importing organizations from: {}", objects_folder)
		for directory_entry in sorted(os.scandir(objects_folder), key=lambda path: path.name):
			if directory_entry.is_file() and directory_entry.path.endswith(".json"):
				self.logger.debug("Processing file: {}", directory_entry.path)
				shutil.copyfile(directory_entry.path, temp_file)
				self.properties.replace(temp_file)
				with open(temp_file) as json_file:
					json_data = json.load(json_file)
					self.logger.trace("Organization definition: {}", json_data)
					self.create_organization(json_data)

	def sherpa_add_user_to_organization(self, username, organization_alias=None, organization_name=None):
		user_id = self.get_user_id(username)
		self.logger.trace("user_id: {}", user_id)
		if organization_alias is not None:
			organization_id = self.sherpa_get_organization_id(organization_alias=organization_alias)
		elif organization_name is not None:
			organization_id = self.sherpa_get_organization_id(organization_name=organization_name)
		else:
			self.logger.error("No organization specified. Received parameters: organization_alias: {}, organization_name: {}", organization_alias, organization_name)
			return None
		self.logger.trace("organization_id: {}", organization_id)
		return self.organization_user_add(user_id=user_id, organization_id=organization_id)


	# def sherpa_assign_roles_to_client(self, client, role_names):
	# 	client_id = self.get_client_id(client)
	# 	self.logger.debug("client_id: {}", client_id)
	# 	user_id = self.get_client_service_account_user(client_id)["id"]
	# 	self.logger.debug("user_id: {}", user_id)
	# 	realm_management_client_id = self.get_client_id("realm-management")
	# 	for role_name in role_names:
	# 		role = self.get_client_role(realm_management_client_id, role_name)
	# 		self.logger.debug("role: {}", role)
	# 		self.assign_client_role(client_id=realm_management_client_id, user_id=user_id, roles=role)


	def sherpa_assign_realm_role_to_client(self, client, role_name):
		client_id = self.get_client_id(client)
		self.logger.debug("client_id: {}", client_id)
		user_id = self.get_client_service_account_user(client_id)["id"]
		self.logger.debug("user_id: {}", user_id)
		role = self.get_realm_role(role_name)
		self.logger.debug("role_id: {}", role)
		self.assign_realm_roles(user_id=user_id, roles=[role])


	def sherpa_logout_user_sessions(self, user_id=None, username=None, email=None, client_keycloak_id=None, client_id=None):
		""" Logout user ONLINE sessions.

		:param user_id: User id
		:type user_id: str
		:param username: username
		:type username: str
		:param email: email
		:type email: str
		:param client_keycloak_id: Client's keycloak id
		:type client_keycloak_id: str
		:param client_id: client_id
		:type client_id: str

		:returns: Keycloak server response
		:rtype: bytes
		"""

		if user_id is None:
			if username is not None:
				user_id = self.get_user_id(username=username)
			elif email is not None:
				user_id = self.get_user_id(email=email)
		if user_id is None:
			self.logger.warn("No user found. Received parameters: user_id: {}, username: {}, email: {}", user_id, username, email)

		if client_keycloak_id is None:
			if client_id is not None:
				client_keycloak_id = self.sherpa_get_client_keycloakid(client_id=client_id)

		if client_keycloak_id is None:
			self.logger.debug("No Client specified, logout ALL user (online) sessions.")
			return self.user_logout(user_id)
		else:
			self.logger.debug("Logout user sessions for client: {}", client_keycloak_id)
			return self.sherpa_logout_user_client_sessions(user_id=user_id, client_keycloak_id=client_keycloak_id)


	def sherpa_get_user_client_offlinesessions(self, user_id=None, username=None, email=None, client_keycloak_id=None, client_id=None):
		""" Logout user sessions.

		:param user_id: User id
		:type user_id: str
		:param username: username
		:type username: str
		:param email: email
		:type email: str
		:param client_keycloak_id: Client's keycloak id
		:type client_keycloak_id: str
		:param client_id: client_id
		:type client_id: str

		:returns: Keycloak server response
		:rtype: bytes
		"""

		if user_id is None:
			if username is not None:
				user_id = self.get_user_id(username=username)
			elif email is not None:
				user_id = self.get_user_id(email=email)
		if user_id is None:
			self.logger.error("No user found. Received parameters: user_id: {}, username: {}, email: {}", user_id, username, email)

		if client_keycloak_id is None:
			if client_id is not None:
				client_keycloak_id = self.sherpa_get_client_keycloakid(client_id=client_id)

		if client_keycloak_id is None:
			self.logger.error("No Client found. Received parameters: client_id: {}, keycloak_client_id: {}.", client_id, client_keycloak_id)
		else:
			self.logger.debug("Getting user offline sessions for client: {}", client_keycloak_id)
			return self.get_user_client_offlinesessions(user_id=user_id, client_id=client_keycloak_id)
