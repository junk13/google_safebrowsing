import threading
import requests
from flask import Flask, request, jsonify

api_key = 'API_KEY_HERE'

app = Flask(__name__)
api_endpoint = 'https://safebrowsing.googleapis.com/v4'
cached_status = {}
payload = {'client': {'clientId': 'Python Safe Browsing Client',
                      'clientVersion': '0.1'
                      },
           'threatInfo': {'threatTypes': ['THREAT_TYPE_UNSPECIFIED',
                                          'MALWARE',
                                          'SOCIAL_ENGINEERING',
                                          'UNWANTED_SOFTWARE',
                                          'POTENTIALLY_HARMFUL_APPLICATION'],

                          'platformTypes': ['ANY_PLATFORM'],
                          'threatEntryTypes': ['URL']
                          }
           }


@app.route('/api')
def api():
    url = request.args.get('url')
    if url:
        if url not in cached_status:
            check(url)

        status = {'status': cached_status[url]}
        return jsonify(status)
    return jsonify({})


def check(url):
    payload['threatInfo']['threatEntries'] = [{'url': url}]
    response = requests.post(f'{api_endpoint}/threatMatches:find?key={api_key}', json=payload)
    response.raise_for_status()
    cached_status[url] = 'unsafe' if response.json() else 'safe'


@app.before_first_request
def refresh_status():
    threading.Timer(600.0, refresh_status).start()
    for url in cached_status:
        check(url)


if __name__ == '__main__':
    app.run()
