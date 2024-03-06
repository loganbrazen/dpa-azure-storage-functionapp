import azure.functions as func
import logging
import requests
from azure.storage.blob import BlobServiceClient

app = func.FunctionApp()
staging_container_name = 'staging'
quarantine_container_name = 'quarantine'
production_container_name = 'production'
storage_account_connection_string = 'DefaultEndpointsProtocol=https;AccountName=testdpa0229stgacct;AccountKey=zOYwo7mlywhHCmTiTgN4k2e1/XOnipyPfgMGwV/s9+MQB7Cy+eusHgZM0DaTUTX6HKZXMRHO04q5+AStWQlR5Q==;EndpointSuffix=core.windows.net'

@app.blob_trigger(arg_name="myblob", path="staging/{name}",
                               connection="AzureWebJobsStorage") 
def blob_trigger1(myblob: func.InputStream):
    logging.info(f"Python blob trigger function processed blob"
                f"Name: {myblob.name}"
                f"Blob Size: {myblob.length} bytes")
    content = myblob.read()
    response = requests.post('https://52.201.88.227:5000/scan/binary/v2', verify=False, data=content, timeout=20)
    logging.info(f'Status code: {response.status_code}')
    if response.status_code == 200:
        json = response.json()  # this is the raw JSON
        logging.info(f'Verdict: {json}')

        # Create a blob service client
        blob_service_client = BlobServiceClient.from_connection_string(storage_account_connection_string)
        logging.info(f'blob service client connected...') 

        # Get the source and destination containers
        source_container_client = blob_service_client.get_container_client(staging_container_name)
        destination_container_client = None

        if 'Malicious' in json['verdict']:
            destination_container_client = blob_service_client.get_container_client(quarantine_container_name)
            logging.info(f"Moving blob {myblob.name} from {staging_container_name} to {quarantine_container_name}")
        else:
            destination_container_client = blob_service_client.get_container_client(production_container_name)
            logging.info(f"Moving blob {myblob.name} from {staging_container_name} to {production_container_name}")
        
        destination_container_client.upload_blob(name=myblob.name, data=content)
        source_container_client.delete_blob(myblob.name)
        