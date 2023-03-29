# Wildix API

This client enable you to perform get and post requests on the Wildix API.
It is based on Wildix documentation: https://docs.wildix.com/wms/index.html


### Use example

```python
xxx_config = {
    'pbx_secret_key': 'xxxxxxxxx',
    'app_id': 'xxxxxxxxx',
    'app_name': 'xxxxxxxxx',
    'pbx_host': 'xxxxxxxxx.wildixin.com',
}

client = WildixApiClient(xxx_config)
response = client.query_get(url="/api/v1/Phonebooks", data={})
```
