import argparse
import json
import logging
import logging.handlers
import os
import SimpleHTTPServer
import SocketServer

DEFAULT_SERVER_PORT = 80


def init_syslog_logger(hostname, port=514):
    logging.basicConfig()
    logger = logging.getLogger(__name__)
    handler = logging.handlers.SysLogHandler(
        address=(hostname, port))
    logger.addHandler(handler)
    return logger


class AlertingRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    extensions_map = SimpleHTTPServer.SimpleHTTPRequestHandler.extensions_map.copy()
    extensions_map.update({".php": "text/html"})

    def send_alert_to_syslog(self, additional_data=None):
        logging_data_format = "Access To: %s\nServer Forensics Data:%s"
        server_forensics_data = self.get_forensics_data_from_request()
        logging_data = logging_data_format % (
            self.path, server_forensics_data)

        if additional_data:
            logging_data += "\nAdditionalData:%s"
            logging_data = logging_data % (additional_data)

        alerts_logger = logging.getLogger(__name__)
        alerts_logger.info(logging_data)

    def get_forensics_data_from_request(self):
        forensics_report = {}
        forensics_report["client_address"] = self.address_string()
        forensics_report["command"] = str(self.command)
        forensics_report["path"] = self.path
        forensics_report["request_version"] = self.request_version
        forensics_report["headers"] = str(self.headers)
        forensics_report["protocol_version"] = self.protocol_version
        return json.dumps(forensics_report)

    def do_GET(self):
        self.send_alert_to_syslog()
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        # In addition to the regular alert data, we add to it the Post data
        post_data_string = self.rfile.read(int(self.headers['Content-Length']))
        self.send_alert_to_syslog("PostData:" + post_data_string)
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)


def main(syslog_server, webroot_directory):
    if not os.path.isdir(webroot_directory):
        print "Error: %s web directory isn't exists" % (webroot_directory)
        return
    os.chdir(webroot_directory)

    alerts_logger = init_syslog_logger(hostname=syslog_server)
    alerts_logger.setLevel(logging.ERROR)

    trap_server = SocketServer.TCPServer(
        ("0.0.0.0", DEFAULT_SERVER_PORT), AlertingRequestHandler)

    print "Starting listening to http requests"
    trap_server.serve_forever()

if __name__ == '__main__':

    arguments_parser = argparse.ArgumentParser(prog=__file__)
    arguments_parser.add_argument("--webroot-directory", "-d", default="./webRoot", type=str,
                                  help="The root directory for the HTTP server")
    arguments_parser.add_argument("--syslog-server", "-s", default=None,
                                  type=str, required=True,
                                  help="The syslog server that the deceptive user will report the request to it")

    parsed_arguments = arguments_parser.parse_args()
    main(parsed_arguments.syslog_server, parsed_arguments.webroot_directory)
