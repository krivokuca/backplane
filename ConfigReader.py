import os
import json
import ast


class ConfigReader:
    def __init__(self, config_path):
        """
        Responsible for parsing and reading the `microservice.conf` file
        """
        self.config_path = config_path
        self.config = None
        if not os.path.isfile(self.config_path):
            raise FileNotFoundError("Config path file is not found")
        with open(self.config_path) as f:
            self.config = ast.literal_eval(f.read())
