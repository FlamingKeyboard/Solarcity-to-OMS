import json
import requests
import datetime
import hashlib
import hmac
import base64
import pprint
#import time
#import datetime
from datetime import date, timedelta

#STARTTIME15MIN should equal the previous day
#ENDTIME15MIN should equal today's date

Today=date.today()
Yesterday=date.today() - timedelta(1)

print Today
print Yesterday

# Put your username and password here
USERNAME = raw_input('Username: ')
PASSWORD = raw_input('Password: ')
STARTTIME15MIN = Yesterday
ENDTIME15MIN   = Today
STARTTIMEDAILY = Yesterday
ENDTIMEDAILY   = Today

#STARTTIME15MIN = raw_input('Start Date 15 min (IE: 2016-12-13): ')
#ENDTIME15MIN   = raw_input('End Date 15 min   (IE: 2016-12-14): ')
#STARTTIMEDAILY = raw_input('Start Date daily  (IE: 2016-10-1 ): ')
#ENDTIMEDAILY   = raw_input('End Date daily    (IE: 2016-12-14): ')

# OAuth2 settings
CLIENT_ID = 'powerguide_api_dev'
CLIENT_SECRET = ' '
SCOPE = 'https://api.solarcity.com/solarguard/'

auth_data = {'grant_type': 'password', 
      'username':USERNAME,
      'password':PASSWORD,
      'scope':SCOPE}

headers = {'Authorization':'Basic '+ base64.b64encode(CLIENT_ID+':'+CLIENT_SECRET)}

r = requests.post('https://login.solarcity.com/issue/oauth2/token', headers=headers, data=auth_data)
print r.json()
access_token = r.json()['access_token']
print 'Obtained Access Token'

headers = {'Authorization': 'Bearer '+access_token}

# Request list of Customers records
r = requests.get('https://api.solarcity.com/powerguide/v1.0/customers', 
      headers=headers, 
      params = {'Size':10,'Page':1})

# Request Customer detail for first customer record
guid = r.json()['Data'][0]['GUID']
customer_detail = requests.get('https://api.solarcity.com/powerguide/v1.0/customers/'+guid, 
      headers=headers, 
      params = {'IsDetailed':'true'})

print 'CUSTOMER'
pprint.pprint(customer_detail.json())

# Request Installation Detail
installation_guid = customer_detail.json()['Installations'][0]['GUID']
installation_detail = requests.get('https://api.solarcity.com/powerguide/v1.0/installations/'+installation_guid, 
      headers=headers, 
      params = {'IncludeDevices':'true'})

print 'INSTALLATION DETAIL'
pprint.pprint(installation_detail.json())

# Request Time Series Generation data by 15 minute interval 
r = requests.get('https://api.solarcity.com/powerguide/v1.0/measurements/'+installation_guid, 
      headers=headers, 
      params = {'StartTime': STARTTIME15MIN, 
      'EndTime': ENDTIME15MIN,
      'Period': 'QuarterHour',
      'IsByDevice': 'true'})
print '15 Minute MEASUREMENTS'
pprint.pprint(r.json())

# Request Time Series Generation data by daily interval
r = requests.get('https://api.solarcity.com/powerguide/v1.0/measurements/'+installation_guid, 
      headers=headers, 
      params = {'StartTime': STARTTIMEDAILY, 
      'EndTime': ENDTIMEDAILY,
      'Period': 'Day',
      'IsByDevice': 'true'})
print 'Daily MEASUREMENTS'
pprint.pprint(r.json())

# Update the customer ID to your Operations Management Suite workspace ID
customer_id = ' '

# For the shared key, use either the primary or the secondary Connected Sources client authentication key   
shared_key = " "

# The log type is the name of the event that is being submitted
log_type = 'SolarCity'

my_data = r.json()

json_data = [{
    "Username":USERNAME,
    "Latitude": my_data['Latitude'],
    "Longitude": my_data['Longitude'],
    "Timestamp": my_data['Timestamp'],
    "Voltage": my_data['Voltage'],
    "Current": my_data['Current'],
    "CumulativekWh": my_data['CumulativekWh'],
    "EnergyInIntervalkWh": my_data['EnergyInIntervalkWh'],
    "DataStatus": my_data['DataStatus']
}]
body = json.dumps(json_data)

#####################
######Functions######  
#####################

# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash).encode('utf-8')  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code == 202):
        print 'Accepted'
    else:
        print "Response code: {}".format(response.status_code)

post_data(customer_id, shared_key, body, log_type)
