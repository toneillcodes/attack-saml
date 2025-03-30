#!/bin/bash
keytool -genkeypair -keyalg RSA -alias samlsigning -dname "CN=saml.example.edu,O=Example University,L=Los Angeles,ST=CA,C=US" -validity 3650 -keysize 2048 -storepass changeit -keypass changeit -keystore samlKeystore.jks
keytool -exportcert -alias samlsigning -rfc -storepass changeit -keypass changeit -keystore samlKeystore.jks -file samlsigning.crt
sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/ { /-----BEGIN CERTIFICATE-----/d; /-----END CERTIFICATE-----/d; p }' samlsigning.crt > trimmed_samlsigning.crt
#cat saml-signing.crt | tail -n +2 | head -n -1 > trimmed_samlsigning.crt
