from ConfigReader import ConfigReader
from DataModels import WebsocketPacket
import datetime


class EventHandler:
    def __init__(self, config_path, database_connector):
        """
        Server facing event handler.

        Parameters:
            - config_path (str) :: The path to the microservice config file
        """

        self.config = ConfigReader(config_path).config
        self.db = database_connector
        self.packet_headers = None
        self.event_ids = [
            "db_query",
            "search_query"
        ]

    def handle_event(self, packet):
        """
        Handles the events for each packet. 
        Parameters:
            - packet (WebsocketPacket) :: An instance of the WebsocketPacket

        Returns:
            - response_packet (WebsocketPacket) :: A response WebsocketPacket
        """

        self.packet_headers = {
            "id": packet.id,
            "connection_id": packet.connection_id,
            "timestamp": int(datetime.datetime.now().timestamp()),
            "is_encrypted": packet.is_encrypted,
            "is_compressed": packet.is_compressed,
            "event": packet.event,
            "polling_timeout": packet.polling_timeout,
            "event_data": None
        }

        if packet.event not in self.event_ids:

            self.packet_headers['event_data'] = self.format_event_data(
                False, False, "Could not locate that service")
            payload = self.format_packets()
            self.packet_headers = None
            return payload

        idx = self.event_ids.index(packet.event)

        if len(packet.event_data.keys()) == 0:
            self.packet_headers['event_data'] = self.format_event_data(
                False, False, "No event data was sent")

            payload = self.format_packets()
            self.packet_headers = None
            return payload

        if idx == 0:
            # db_query
            query = packet.event_data['query']
            self.packet_headers['event_data'] = self.db_query_executor(query)

        elif idx == 1:
            self.packet_headers['event_data'] = None

        payload = self.format_packets()
        self.packet_headers = None

        return payload

    def db_query_executor(self, query, security_policy=True):
        """
        Executes the queries passed to it as the 'backplane' user in mariadb. Disallows
        the use of the UPDATE or DELETE query (thus putting the database into readonly mode)
        if the security_policy is True.

        Parameters:
            - query (str) :: A valid MariaDB query
            security_policy (bool) (optional) :: If True then the read-only security policy will
                                                 be adopted, disallowing UPDATE/DELETE queries

        Returns:
            - success (bool) :: True or False depending on whether or not the query was executed successfully.
                                All data returned by the query is in the self.packet_headers var
        """
        service_name = "Vestra.DBConnector.Master"
        if not self.packet_headers:
            raise Exception(
                "Cannot query without packet header being set due to security policy")

        if security_policy:
            operator = query.split(" ")[0]
            if operator.lower() == "delete" or operator.lower() == "update":
                self.packet_headers['event_data'] = self.format_event_data(
                    service_name, False, "Cannot execute query due to security policy")
                return False

        try:
            cursor = self.db.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
            if results:
                # since ast.literal_eval doesn't work on datetime objects, we need to convert each datetime
                # object to a unix int
                for result in results:
                    keys = list(result.keys())
                    for k in keys:
                        if isinstance(result[k], datetime.date):
                            result[k] = int(result[k].timestamp())
            payload = self.format_event_data(service_name, True, results)
            return payload

        except Exception as e:
            payload = self.format_event_data(service_name, False, e)
            return payload

    def format_packets(self):
        return WebsocketPacket.parse_obj(self.packet_headers)

    def format_event_data(self, service, success, content):
        return {
            "service": service,
            "success": success,
            "content": content
        }

    def release_headers(self):
        self.packet_headers = None
