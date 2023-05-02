public class AWSWebService {

    //Public  static awsKeySet = 'AKIASCXQHDM5LOXGEGGV';
    String awsKeySet = 'AKIASCXQHDM5LOXGEGGV';
    String Content_Type;
    String acessType;
    String sigver;
    String formattedexpire;

    public AWSWebService() {
        Content_Type ='multipart/form-data';
        acessType ='public-read-write';

        Datetime expire = system.now().addDays(1);
        formattedexpire = expire.formatGmt('yyyy-MM-dd')+'T'+ expire.formatGmt('HH:mm:ss')+'.'+expire.formatGMT('SSS')+'Z';        
    }

    string policy { 

        get {

            return 
                '{ "expiration": "'+formattedexpire+'","conditions": [ {"bucket": "AAAAA" } ,{ "acl": "'+acessType+'" },'+
                '{"content-type":"'+Content_Type+'"},'+
                '{"success_action_redirect": ""},' +
                '["starts-with", "$key",""] ]}';               
        }
    }

    public String getPolicy() {
        return EncodingUtil.base64Encode(Blob.valueOf(policy));
    }

    public String getSignedPolicy() {    
        return make_sig(EncodingUtil.base64Encode(Blob.valueOf(policy)));        
    }

    private String make_sig(string canonicalBuffer) {

        if(canonicalBuffer == null || awsKeySet == null) {

            System.debug('~~~ came here evaluated null');
            System.debug('~~~ canonicalbuffer = '+ canonicalBuffer);
            System.debug('~~~ awsKeySet : '+ awsKeySet);
            return null;
        }

        String macUrl ;

        //Blob mac = Crypto.generateMac('HmacSHA1', blob.valueof(canonicalBuffer),blob.valueof(awsKeySet.AWS_Secret_Key__c));
        Blob mac = Crypto.generateMac('HmacSHA1', blob.valueof(canonicalBuffer),blob.valueof(awsKeySet));
        macUrl = EncodingUtil.base64Encode(mac);                
        return macUrl;

    }

    public void invokeWS() {
        //String endpoint = 'https://s3.ap-southeast-2.amazonaws.com';
        String endpoint = 'callout:Archive_Accounts';
        String bucket = 'archive-accounts';
        String AWSAccessKeyId='AKIASCXQHDM5LOXGEGGV' ;
        String timestamp = datetime.now().formatGmt('EEE, d MMM yyyy HH:mm:ss Z');

        Http http=new Http();
        HttpRequest request=new HttpRequest();
        request.setEndpoint(endpoint);
        request.setMethod('GET');

        request.setHeader('Host',bucket+'.'+'s3.amazonaws.com');
        request.setHeader('Date',timestamp);
        //request.setHeader('Authorization','AWS '+AWSAccessKeyId+':'+getSignedPolicy());

        HttpResponse res = http.send(request);
        system.debug('Body is'+res.getBody());
    }

}