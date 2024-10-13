package com.sap.ppservice.cloud

class NegativeSecurityTest extends TestSuperClass {

    def stageConfig = null
    public def coreServicesUtils = null
    def setX = "set +x;"

    NegativeSecurityTest(script, globalPipelineEnvironment, stageConfig, targetSpace, buildSummary) {
        super(script, globalPipelineEnvironment, targetSpace, buildSummary)
        this.stageConfig = stageConfig
        this.coreServicesUtils = new CoreServicesUtils(script)
    }


    //***********************************************MY SPACE***************************************
    int negativeCount = 0
    List<Map> testResults = []


    def doNegativeSecurityTest(setX = "set +x;") {
        this.setX = setX
		
        script.dockerExecuteOnKubernetes(script: script, dockerImage: 'opps.int.repositories.cloud.sap/opps-pipeline', stashContent: []) {

                script.retry (3){ deployUtils.loginTargetSpace(stageConfig)}
                script.LOG('Start Negative Security test ...')

                 // Iterate over each groupName with it's group of endpoints
                stageConfig.endpointGroups.each { groupName, group ->
                    script.LOG("Processing ${groupName} group with ${group.authType} authentication.")

                       //Processing groups having Token Authorisation
                       if(group.authType == "tokenAuth") {
                           String jwtToken = coreServicesUtils.retrieveTokenFromServiceKey(group.serviceInstance, group.serviceKey, true)
                           String incorrectJwtToken=  coreServicesUtils.retrieveTokenFromServiceKey(group.incorrectServiceInstance, group.incorrectServiceKey, true)

                           group.endpoints.each { endpoint ->
                            runTests(endpoint, "tokenAuth", jwtToken, incorrectJwtToken, "", "") 
                              if (["Calculation", "Data-Upload"].contains(groupName)) {
                                testResults += TooLargePayloadTest(endpoint.url, endpoint.methods, groupName, jwtToken)
                               }
                           }
                       }   
                       //Processing Groups having Basic Authentication         
                       else {
                                String username = group.usernameID;
                                String password = group.usernamePassword;
                                group.endpoints.each { endpoint ->
                                        if (groupName.startsWith("Availability_Check")) {
                                            testResults += ProxyNotAllowedTest(endpoint.url, endpoint.methods, username, password)
                                        } 
                                        else {
                                            runTests(endpoint, "basicAuth", "", "", username, password)
                                        }
                                }
                        }

                } 

                printTestResultsSummary()
        }
    }

    void runTests(Map endpoint, String authType, String jwtToken, String incorrectJwtToken, String username, String password ) {
        switch(authType) {

            case "tokenAuth": 
                testResults += MissingAuthenticationTest(endpoint.url, endpoint.methods)
                testResults += WrongAuthenticationTest(endpoint.url, endpoint.methods, "tokenAuth", incorrectJwtToken)
                testResults += HttpVerbTamperingTest(endpoint.url, endpoint.methods, "tokenAuth", jwtToken)
                testResults += UseOfHttpInsteadOfHttpsTest(endpoint.url, endpoint.methods, "tokenAuth", jwtToken)
                break

            case "basicAuth":
                testResults += MissingAuthenticationTest(endpoint.url, endpoint.methods)
                testResults += WrongAuthenticationTest(endpoint.url, endpoint.methods, "basicAuth", username, password)
                testResults += HttpVerbTamperingTest(endpoint.url, endpoint.methods, "basicAuth", username, password)
                testResults += UseOfHttpInsteadOfHttpsTest(endpoint.url, endpoint.methods, "basicAuth", username, password)
                break

            default: 
                script.LOG("Error: Unknown authentication type '${authType}' for endpoint ${endpoint.url} ")  
                break
        }    
        
    }

    String performCurl(String url, String method, String authToken = null) {
        def command = "${setX}curl -s -o /dev/null -w '%{http_code}' -X ${method}"
        if (authToken) {
               command += " -H 'Authorization: Bearer ${authToken}'"
        }
        //we need a minimal req body in those cases
        if( method in ["POST", "PATCH", "PUT"] ){
              command += " -H 'Content-Type: application/json' -d {}" 
        }
        //strip the key if present for POST
        if( method in ["POST"] && url.indexOf("(") > 0 ){
            url = url.substring(0,url.indexOf("(")) 
        }
        command += " '${url}'"
        try {
            return script.sh(script: command, returnStdout: true).trim()
        } catch (Exception e) {
            script.LOG("Failed to execute curl command: ${e.message}")
            throw e
        }
    }

    String performCurlBasicAuth(String url, String method, String username, String password) {
        def command = "${setX}curl -s -o /dev/null -w '%{http_code}' -X ${method} -u ${username}:${password} "
        if( method in ["POST", "PATCH", "PUT"] ){
              command += " -H 'Content-Type: application/json' -d {}"
        }
         //strip the key if present for POST
        if( method in ["POST"] && url.indexOf("(") > 0 ){
            url = url.substring(0,url.indexOf("(")) 
        }
        command += " '${url}'"
        try {
            return script.sh(script: command, returnStdout: true).trim()
        } catch (Exception e) {
            script.LOG("Failed to execute curl command: ${e.message}")
            throw e
        }
    }


    private void printTestResultsSummary() {
        StringBuffer sb = new StringBuffer();
        sb.append("------------********************************** START OF NEGATIVE AUTOMATED TESTS **************************************************-------------------------------\n")
        sb.append("-------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
        sb.append("\nTest Results Summary:(Endpoints with their respective Tests. Link at: https://wiki.one.int.sap/wiki/pages/viewpage.action?spaceKey=OPP&title=OPPS+Negative+Tests)\n")
        sb.append("--------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
        sb.append("---------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")


        Map<String, List> testsByEndpoint = new LinkedHashMap<>()
        Map<String, String> endpointGroupNames = new LinkedHashMap<>()

        // Initialize the map with endpoint URLs in defined order
        // Assume 'endpointGroups' is accessible and ordered as in your 'config.yml'
            stageConfig.endpointGroups.each { groupName, group ->
            group.endpoints.each { endpoint ->
                testsByEndpoint[endpoint.url] = [] // Initialize list for each endpoint
                endpointGroupNames[endpoint.url] = groupName
            }
        }

           // Organize tests by their endpoint URLs
             testResults.each { result ->
                testsByEndpoint[result.url]?.add(result)
            }

        // Iterate over each endpoint and print its tests
        testsByEndpoint.each { url, results ->
            String groupName = endpointGroupNames[url]
            sb.append("Endpoint: ${groupName} :${url}\n")
            results.each { result ->
                String status = result.passed ? "PASSED" : "FAILED"
                sb.append("  - ${result.testName} : Received: ${result.received} : ${status}\n")
            }
            sb.append("----------------------------------------------------------------------------------------------------\n")
        }

        // Count and list failed tests
        List<String> failedTests = testResults.findAll { !it.passed }
        sb.append("------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
        sb.append("Total tests: ${testResults.size()}, Failed tests: ${failedTests.size()} \n")
        sb.append("------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
        

        // Provide a brief summary of failures if any
        if (!failedTests.isEmpty()) {
            sb.append("Failed Tests Summary:\n")
            failedTests.each { failedTest ->
                sb.append("  - ${failedTest.testName} at ${failedTest.url} (Expected: ${failedTest.expected}, Received: ${failedTest.received})\n")
            }
            sb.append("------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
        }
        sb.append("------------********************************** END OF NEGATIVE AUTOMATED TESTS **************************************************---------------------------------\n")
        script.echo sb.toString()

        if (failedTests.size() > 0) {
            script.error("Some tests have failed. Failing the build. Please have a look above which one's failed.")
        }
    }



    

  
    //++++++++++++++****************TESTS*****  +++++++++++++++++++++++++++++++++++++++++++++++++
    
    Map MissingAuthenticationTest(String url, methods) {
        def result = []
        for(method in methods){
            def response = performCurl(url, method, null)
            result.add([
                testName: "Missing Authentication (${method})",
                url: url,
                passed: response == '401',
                expected: '401',
                received: response
            ])
        }
        return result
    }
    
    Map WrongAuthenticationTest(String url, methods, String authType, String authToken = null, String username = null, String password = null) {
        def result = []
        for(method in methods){
            def response
            if (authType == "tokenAuth" && authToken) {
                response = performCurl(url, method, authToken)
            } else {
                response = performCurlBasicAuth(url, method, username, password)
            } 
            result.add([
                testName: "Wrong Authentication (${method})",
                url: url,
                passed: response == '403',
                expected: '403',
                received: response
            ])
        }
        return result
    }


    
    Map HttpVerbTamperingTest(String url, intendedMethods, String authType, String authToken = null, String username = null, String password = null) {
        // Define all HTTP methods you want to test against.
        List<String> allHttpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        //tamperedMethods is now a list of 'wrong' HTTP methods
        List<String> tamperedMethods = allHttpMethods - intendedMethods
        
        List<Map> tamperedResults = []

        tamperedMethods.each{method-> 
            def response
            if(authType=="tokenAuth") {
                response= performCurl(url, method,authToken)
            } else {
                response = performCurlBasicAuth(url,method, username, password)
            }

            boolean passed= response in ['405', '403']

            tamperedResults .add([
                method: method,
                passed: passed,
                response: response
            ])
        }
        boolean overallPassed = tamperedResults.every {it.passed}
        String detailedResults= tamperedResults.collect { "${it.method}: ${it.response}" }.join("; ")
        return [
             testName: "HTTP Verb Tampering",
             url: url,
             passed: overallPassed,
             expected: '405 or 403 for all incorrect methods',
             received: detailedResults
        ]
    }

    Map UseOfHttpInsteadOfHttpsTest(String url, methods, String authType, String authToken = null, String username = null, String password = null) {
        def httpEndpoint = url.replace('https://', 'http://')
        def result = []
        for(method in methods){
            def response
            if (authType == "tokenAuth") {
                response = performCurl(httpEndpoint, method, authToken)
            } else {
                response = performCurlBasicAuth(httpEndpoint, method, username, password)
            }
            result.add([
                testName: "Use Of 'Http' Instead Of Https Test (${method})",
                url: url,
                passed: response == '301',
                expected: '301',
                received: response
            ])
        }
        return result
    }


    Map TooLargePayloadTest(String url, methods, String groupName, String authToken = null) {
       def method = methods[0] //we expect only one method
       script.LOG("Entering Too large Paylaod Test for group: ${groupName}")

         // Customizing payload based on the group
        if (groupName == "Calculation") {
              def baseXML = """
                        <PriceCalculate xmlns="http://www.nrf-arts.org/IXRetail/namespace/" InternalMajorVersion="2" InternalMinorVersion="1">
                            <ARTSHeader ActionCode="Calculate" MessageType="Request">
                                <MessageID>9a89f2edfd1e413ea147e334b9c2ed4b</MessageID>
                                <DateTime>2307-01-13T04:48:30.427-05:00</DateTime>
                                <BusinessUnit>1101</BusinessUnit>
                                <MasterDataSourceSystemID>QI5CLNT800</MasterDataSourceSystemID>
                            </ARTSHeader>
                            <PriceCalculateBody TransactionType="SaleTransaction" netPriceFlag="true">
                                <TransactionID>9a89f2edfd1e413ea147e334b9c2ed4b</TransactionID>
                                <DateTime>2307-01-13T04:48:30.427-05:00</DateTime>
                                <ShoppingBasket>
                                    <LineItem>
                                    <SequenceNumber>1</SequenceNumber>
                                    <MerchandiseHierarchy ID="1">RFXX200</MerchandiseHierarchy>
                                    <Sale ItemType="Stock" NonDiscountableFlag="false" FixedPriceFlag="false">
                                        <TaxIncludedInPriceFlag>false</TaxIncludedInPriceFlag>
                                        <NonPieceGoodFlag>false</NonPieceGoodFlag>
                                        <FrequentShopperPointsEligibilityFlag>true</FrequentShopperPointsEligibilityFlag>
                                        <NotConsideredByPriceEngineFlag>false</NotConsideredByPriceEngineFlag>
                                        <ItemID>R1TA0201</ItemID>
                                    </Sale>
                                    <Quantity Units="1" UnitOfMeasureCode="PCE">2</Quantity>
                                    </LineItem>
                                </ShoppingBasket>
                            </PriceCalculateBody>
                        </PriceCalculate>
                    """
                script.writeFile(file:"payload.xml", text: baseXML)
                // Add comments to increase payload size
                def comment = "<!-- 00000 -->\n"
                int commentRepeats = 50000
                StringBuilder largePayload = new StringBuilder()

                for (int i = 1; i <= commentRepeats; i++) {
                    largePayload.append(comment)
                }

                script.writeFile(file: "payload.xml", text: largePayload.toString(), append: true)

        } else {
            // This is a simple payload for the Data-Upload Endpoint (with 7mb zeroes)
             script.sh(script: 'head -c 7000000 /dev/zero >> payload.xml', returnStdout: true).trim()
        }

       def curlCommand = """
            ${setX}curl --http1.1 -X ${method} \\
            -H "Transfer-Encoding: chunked" \\
            -H "Content-Type: application/xml" \\
            -H "Authorization: Bearer ${authToken}" \\
            -T payload.xml \\
            "${url}"
        """
        // Execute the curl command and capture the output
        def response = script.sh(script: curlCommand, returnStdout: true).trim() 
        script.LOG("Curl response: ${response}")

        // Check if the response includes the expected HTTP 413 status code
        boolean passed = response.contains('413')
        String expected = '413'
        String received = passed ? '413' : 'Received response not containing expected 413 status'

       // Cleanup: remove the payload file to save space
        script.sh(script: "rm -f payload.xml", returnStdout: true)
        script.echo("Temporary payload file removed.")

        return [
            testName: "Too Large Payload Test",
            url: url,
            passed: passed,
            expected: expected,
            received: received
        ]
    }
      

    Map ProxyNotAllowedTest(String url, methods, String username = null, String password = null) {
         def method = methods[0] //we expect only one method
        def response = performCurlBasicAuth(url, method, username, password)
        return [
            testName: "Proxy not Allowed",
            url: url,
            passed:  response == '400',
            expected: '400',
            received: response
        ]
    }
}