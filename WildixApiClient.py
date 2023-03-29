import jwt
import time
import hashlib
import requests


class WildixApiClient:
    """
    A class used to interface the Wildix API
    Based on Wildix documentation https://docs.wildix.com/wms/index.html
    Author: Pierre Anken
    Company: Netkum AG - Switzerland
    """

    def __init__(self, config):

        mandatory_config_fields = ['pbx_secret_key', 'app_id', 'app_name', 'pbx_host']
        for field in mandatory_config_fields:
            if not config.get(field):
                raise ValueError(f"{field} key missing in config.")

        self._secret = config["pbx_secret_key"]
        self._app_id = config["app_id"]
        self._app_name = config["app_name"]
        self._host = config["pbx_host"]

    def _generate_request_string(self, data, url, method) -> str:

        # Create bas request string. This part is common for all API requests
        request_string = "{}{}host:{};x-app-id:{};{}".format(
            method,
            url,
            self._host,
            self._app_id,
            self.get_canonical_data(data)
        )
        return request_string

    def get_canonical_data(self, data: dict) -> str:

        canonical_data = ''
        if data:
            data_sorted = dict(sorted(data.items(), key=lambda item: item[0]))
            for key, value in data_sorted.items():
                new_str = self.get_canonical_data(value) if type(value) is dict else value.strip()
                canonical_data += f'{key}:{new_str};'

        return canonical_data

    def _generate_jwt(self, request_string):
        """
        Method to create JWT Token to authenticate with Wildix PBX
        """

        hash_string = hashlib.sha256(request_string.encode() if request_string else '')
        timestamp = round(time.time())
        expire = 60

        payload = {
            'iss': self._app_name,
            'iat': timestamp,
            'exp': timestamp + expire,
            'sign': {
                'alg': 'sha256',
                'headers': {
                    '0': 'Host',
                    '1': 'X-APP-ID',
                },
                'hash': hash_string.hexdigest(),
            },
        }

        encoded_jwt = jwt.encode(payload, self._secret, algorithm='HS256')
        return encoded_jwt

    def _perform_request(self, url, method='GET', data=None):

        request_string = self._generate_request_string(data, url, method)
        print(request_string)
        jwt_token = self._generate_jwt(request_string)
        headers = {'Host': self._host, 'X-APP-ID': self._app_id, 'Authorization': 'Bearer {}'.format(jwt_token)}

        encoded_url = "https://" + self._host + url
        print('encoded_url:', encoded_url)

        return requests.request(
            method=method,
            url=encoded_url,
            data=data,
            headers=headers
        )

    def query_get(self, url, data):
        return self._perform_request(data=data, url=url)

    def query_post(self, url, data):
        return self._perform_request(data=data, url=url, method="POST")
