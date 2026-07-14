import requests

API_KEY = "6irXyUaRVa3GJKP2bMEYg8sGdICO2AxV9qTqWJ3h"

URL = "https://api.quantumnumbers.anu.edu.au"

headers = {
    "x-api-key": API_KEY
}

params = {
    "length": 32,
    "type": "uint8"
}

try:

    response = requests.get(
        URL,
        headers=headers,
        params=params,
        timeout=10
    )

    print("="*60)
    print("STATUS :", response.status_code)
    print("="*60)

    if response.status_code == 200:

        data = response.json()

        print("\nQuantum Random Numbers\n")

        print(data)

    else:

        print(response.text)

except Exception as e:

    print("ERROR :", e)