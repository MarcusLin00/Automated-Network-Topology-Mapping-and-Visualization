import requests
import json
import logging
import urllib
from urllib.parse import urlparse

# Define constants
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
TEST_URL = "http://45.61.49.78/razor/r4z0r.mips"
TIMEOUT = 10  # seconds
url = TEST_URL.rstrip('.')
# url = url + '/' 
if not urlparse(url).scheme:
                url = f"http://{url}"  # Add "http://" if no scheme is provided
def test_urlhaus_api():
    # Prepare the data to be sent in the POST request
    data = {"url": url}
    
    logging.info(f"Querying URLHaus API with URL: {URLHAUS_API_URL}")
    logging.debug(f"Data being sent: {data}")
    try:
        # Send the POST request to the URLHaus API
        print("querying with url",URLHAUS_API_URL)
        print("data", data)
        response = requests.post(URLHAUS_API_URL, data=data, timeout=TIMEOUT)

        # Check if the request was successful
        if response.status_code == 200:
            print("Status Code:", response.status_code)
            print("Headers:", response.headers)

            try:
                # Parse and print the JSON response
                json_response = response.json()
                print("JSON Response:", json.dumps(json_response, indent=2))

                # Check for known fields to verify if the API responded correctly
                if 'query_status' in json_response:
                    print(f"Query Status: {json_response['query_status']}")
                    if json_response['query_status'] == 'ok':
                        print("URL found in URLHaus database.")
                    elif json_response['query_status'] == 'no_results':
                        print("URL not found in URLHaus database.")
                    else:
                        print("Unexpected query status.")
                else:
                    print("Unexpected response structure:", json_response)
            except json.JSONDecodeError:
                print("Failed to parse JSON response.")
        else:
            print("Failed to retrieve data. Status Code:", response.status_code)

    except requests.RequestException as e:
        print("Error communicating with URLHaus API:", e)

# Run the test function
if __name__ == "__main__":
    test_urlhaus_api()
