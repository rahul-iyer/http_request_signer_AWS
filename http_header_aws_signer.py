import sys, os, base64, datetime, hashlib, hmac 
import requests
import urlparse


class AwsSignerV4(object):

	def __init__(self, method, service, region, endpoint, request_paramters=""):
		self.method = method
		self.service = service
		self.region = region
		urls = urlparse.urlparse(endpoint)
		self.host = urls.hostname
		self.canonical_uri = urls.path
		self.request_paramters = request_paramters

	def signer(self, key, msg):
		return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

	def getSignatureKey(self,key, dateStamp, regionName, serviceName):
		kDate = self.signer(('AWS4' + key).encode('utf-8'), dateStamp)
		kRegion = self.signer(kDate, regionName)
		kService = self.signer(kRegion, serviceName)
		kSigning = self.signer(kService, 'aws4_request')
		return kSigning


	def sign(self):
		access_key = os.environ.get('AWS_ACCESS_KEY_ID')
		secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
		if access_key is None or secret_key is None:
			print 'No access key is available.'
			sys.exit()

		t = datetime.datetime.utcnow()
		amzdate = t.strftime('%Y%m%dT%H%M%SZ')
		datestamp = t.strftime('%Y%m%d')

		canonical_querystring = "" # add accordingly if you are passing parameters in the link itself
		# if you have any other header information, add it here and make sure its alphabetically sorted.
		canonical_headers = ("content-type:application/json" + '\n' if (self.method == "POST" or self.method == "PUT") else "") +'host:' + self.host + '\n' + 'x-amz-date:' + amzdate + '\n'

		signed_headers =("content-type;" if (self.method == "POST" or self.method == "PUT") else "") + 'host;x-amz-date'
		payload_hash = hashlib.sha256(self.request_paramters).hexdigest()
		canonical_request = self.method + '\n' + self.canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

		algorithm = 'AWS4-HMAC-SHA256'
		credential_scope = datestamp + '/' + self.region + '/' + self.service + '/' + 'aws4_request'
		string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()

		signing_key = self.getSignatureKey(secret_key, datestamp, self.region, self.service)
		signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

		authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

		return {'Authorization':authorization_header, 'x-amz-date':amzdate}



