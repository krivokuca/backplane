# Backplane

Backplane is a secure, websocket-based microservice communication and orchestration platform. It allows a network of servers to setup, deploy and communicate with eachother via the Backplane Client & Server API.

## Installation

Before installation, the following system environment variables need to be set:

- `BACKPLANE_CERT_FILE` :: The full file path to the microservice.cert certificate file
- `BACKPLANE_PRIV_KEY` :: The full file path to the private key
- `BACKPLANE_PUB_KEY` :: The full file path to the public key
- `BACKPLANE_KEY_PATH` :: The full file path to a directory in which your peers keys will be stored
- `BACKPLANE_DB_CONFIG` :: A dictionary with the keys `['username', 'password']`, correpsonding to the SQL username and password

After these have been set, you can clone the Git repository and drag and drop the `backplane` folder into your project home. You can then import it as you would any other project.

## Example

A simple example of a SQL query being executed via Backplane:

```py
from backplane.Client import Client
from backplane.DataModels import WebsocketPacket

bp_client = Client("/path/to/microservice.conf")
is_connected = bp_client.connect("peer_id")

if not is_connected:
    raise Exception("Could not connect to peer")

mysql_query = "SELECT COUNT(*) AS `row_count` FROM `mytable` WHERE `date` BETWEEN '2020-01-01' AND '2020-05-30';"

@bp_client.poll
def handle_query():
    return WebsocketPacket(
        is_encrypted=False,
        is_compressed=False,
        event="db_query",
        polling_timeout=60,
        event_data={
            "query" : mysql_query
        }
    )

results = handle_query()
```
