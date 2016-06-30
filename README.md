# Webhook_Sigature_Verification

This sample signature verification examples is to provide the ability to verify the signature of the webhook messages the client receives from Payeezy API. The message format is in json. The sample payload of the webhook message is as below. 


Examples are provided for both Cert and PROD environments and their root certificates are added. Use the appropriates files in their respective environments. The signature in the payload is formed using a combination of keys that are part of the message. 

You have to combine the data that is part of the webhook to verify the signature as shown in the java examples. Please refer to SignatureTestPROD.java and SignatureTestCERT.java on how to verify the webhook signature to ensure that the messages are coming from FD.


String data ="event=transaction+amount=1099+currency=USD+ref_data=VEVTVA==+status=approved+transaction_id=ET147471+transaction_tag=26376554+transaction_time=1406223305215+transaction_type=authorize";



