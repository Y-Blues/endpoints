# app="all"
from ycappuccino_api.core.api import IActivityLogger
from ycappuccino_api.endpoints.api import IEndpoint
import traceback

from src.main.python.decorator_app import Layer

import os
import pelix.remote
import logging
import json
from src.main.python import UrlPath, EndpointResponse
from pelix.ipopo.decorators import (
    ComponentFactory,
    Requires,
    Validate,
    Invalidate,
    Provides,
    BindField,
    UnbindField,
    Instantiate,
    Property,
)
from ycappuccino_api.endpoints.api import IRightManager, IHandlerEndpoint
from ycappuccino_api.core.api import IService

_logger = logging.getLogger(__name__)

"""
    generic servlet to access to the rest api
"""


@ComponentFactory("Endpoint-Factory")
@Requires("_log", IActivityLogger.__name__, spec_filter="'(name=main)'")
@Requires("_right_manager", IRightManager.__name__, optional=True)
@Provides(specifications=[pelix.http.HTTP_SERVLET, IEndpoint.__name__])
@Instantiate("http")
@Requires(
    "_handler_endpoints",
    specification=IHandlerEndpoint.__name__,
    aggregate=True,
    optional=True,
)
@Requires("_services", specification=IService.__name__, aggregate=True, optional=True)
@Property("_servlet_path", pelix.http.HTTP_SERVLET_PATH, "/api")
@Property("_reject", pelix.remote.PROP_EXPORT_REJECT, pelix.http.HTTP_SERVLET)
@Layer(name="ycappuccino_endpoints")
class Endpoint(IEndpoint):

    def __init__(self):
        super(IEndpoint, self).__init__()
        self._log = None
        self._handler_endpoints = None
        self._map_handler_endpoints = {}

        self._file_dir = None
        self._right_manager = None

    def do_GET(self, request, response):
        """ """
        w_path = request.get_path()
        w_header = request.get_headers()
        self._log.info("get path={}".format(w_path))

        if "swagger.json" in w_path:
            w_resp = self.get_swagger_descriptions(w_path, w_header)
        else:
            w_resp = self.get(w_path, w_header)
        response.send_content(
            w_resp.get_status(), w_resp.get_json(), "application/json"
        )

    def do_POST(self, request, response):
        """ """
        w_header = request.get_headers()
        w_resp = None
        w_data = request.read_data()
        w_path = request.get_path()

        if w_header["Content-Type"] == "multipart/form-data":
            # need to parse multipart

            self.upload_media(w_path, w_header, w_data)
            print(w_data)
        else:
            w_str = w_data.decode()
            w_json = None
            if w_str is not None and w_str != "":
                w_json = json.loads(w_str)
            self._log.info("post path={}, data={}".format(w_path, w_str))

            w_resp = self.post(w_path, w_header, w_json)

        if w_resp.get_header() is not None:
            for key, value in w_resp.get_header().items():
                response.set_header(key, value)

        response.send_content(
            w_resp.get_status(), w_resp.get_json(), "application/json"
        )

    def do_PUT(self, request, response):
        """ """
        w_str = request.read_data().decode()
        w_path = request.get_path()
        w_header = request.get_headers()
        w_json = None
        if w_str is not None and w_str != "":
            w_json = json.loads(w_str)
        self._log.info("put path={}, data={}".format(w_path, w_str))

        w_resp = self.put(w_path, w_header, w_json)
        response.send_content(
            w_resp.get_status(), w_resp.get_json(), "application/json"
        )

    def do_DELETE(self, request, response):
        """ """
        w_path = request.get_path()
        w_header = request.get_headers()
        self._log.info("delete path={}".format(w_path))

        w_resp = self.delete(w_path, w_header)
        response.send_content(
            w_resp.get_status(), w_resp.get_json(), "application/json"
        )

    def get_tenant(self, a_headers):
        if self._right_manager is not None:
            return None
        w_token = self._get_token_from_header(a_headers)
        if w_token is None:
            return None
        return self._right_manager.verify(w_token)

    def get_account(self, a_headers):
        if self._right_manager is not None:
            return None
        w_token = self.__get_token_from_header(a_headers)
        if w_token is None:
            return None
        return self._right_manager.verify(w_token)

    def find_service(self, a_service_name):
        if a_service_name not in self._map_services:
            # reset map of manager (TODO check why bind doesn't work)
            return None
        return self._map_services[a_service_name]

    def post(self, a_path, a_headers, a_body):
        try:
            w_url_path = UrlPath(
                "post", a_path, self.get_swagger_descriptions(a_path, a_headers)
            )

            if w_url_path.get_type() in self._map_handler_endpoints.keys():
                w_handler_endpoint = self._map_handler_endpoints[w_url_path.get_type()]
                return w_handler_endpoint.post(a_path, a_headers, a_body)
            return EndpointResponse(400)

        except Exception as e:
            w_body = {
                "data": {"error": str(e), "stack": traceback.format_exc().split("\n")}
            }
            return EndpointResponse(500, None, None, w_body)

    def put(self, a_path, a_headers, a_body):
        try:
            w_url_path = UrlPath(
                "put", a_path, self.get_swagger_descriptions(a_path, a_headers)
            )

            if w_url_path.get_type() in self._map_handler_endpoints.keys():
                w_handler_endpoint = self._map_handler_endpoints[w_url_path.get_type()]
                return w_handler_endpoint.put(a_path, a_headers, a_body)
            return EndpointResponse(400)
        except Exception as e:
            w_body = {
                "data": {"error": str(e), "stack": traceback.format_exc().split("\n")}
            }
            return EndpointResponse(500, None, None, w_body)

    def get_swagger_descriptions(self, a_path, a_headers):
        return self._map_handler_endpoints["swagger"].get(a_path, a_headers)

    def get(self, a_path, a_headers):
        try:
            w_url_path = UrlPath(
                "get", a_path, self.get_swagger_descriptions(a_path, a_headers)
            )

            if w_url_path.get_type() in self._map_handler_endpoints.keys():
                w_handler_endpoint = self._map_handler_endpoints[w_url_path.get_type()]
                return w_handler_endpoint.get(a_path, a_headers)
            return EndpointResponse(400)
        except Exception as e:
            w_body = {
                "data": {"error": str(e), "stack": traceback.format_exc().split("\n")}
            }
            return EndpointResponse(500, None, None, w_body)

    def delete(self, a_path, a_headers):
        try:
            w_url_path = UrlPath(
                "delete", a_path, self.get_swagger_descriptions(a_path, a_headers)
            )

            if w_url_path.get_type() in self._map_handler_endpoints.keys():
                w_handler_endpoint = self._map_handler_endpoints[w_url_path.get_type()]
                return w_handler_endpoint.delete(a_path, a_headers)
            return EndpointResponse(400)

        except Exception as e:
            w_body = {
                "data": {"error": str(e), "stack": traceback.format_exc().split("\n")}
            }
            return EndpointResponse(500, None, None, w_body)

    @BindField("_handler_endpoints")
    def bind_manager(self, field, a_handler_endpoint, a_service_reference):
        w_item_plurals = a_handler_endpoint.get_types()
        for w_item_plural in w_item_plurals:
            self._map_handler_endpoints[w_item_plural] = a_handler_endpoint

    @UnbindField("_handler_endpoints")
    def unbind_manager(self, field, a_handler_endpoint, a_service_reference):
        w_item_plurals = a_handler_endpoint.get_types()
        for w_item_plural in w_item_plurals:
            self._map_handler_endpoints[w_item_plural] = None

    @Validate
    def validate(self, context):
        self._log.info("Endpoint validating")

        w_data_path = os.getcwd() + "/data"
        if not os.path.isdir(w_data_path):
            os.mkdir(w_data_path)

        self._file_dir = os.path.join(w_data_path, "files")
        if not os.path.isdir(self._file_dir):
            os.mkdir(self._file_dir)
        self._log.info("Endpoint validated")

    @Invalidate
    def invalidate(self, context):
        self._log.info("Endpoint invalidating")

        self._log.info("Endpoint invalidated")
