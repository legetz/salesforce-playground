@IsTest
private class JwtSignerServiceTest {
  @IsTest
  static void generateJwtFallsBackToRegularRole() {
    User testUser = createUser(
      'fallback',
      '11111111-1111-1111-1111-111111111111'
    );

    System.runAs(testUser) {
      JwtSignerService.JwtResponse response = JwtSignerService.generateJwt();

      System.assertEquals('external-app', response.appKey);
      System.assertEquals('https://your-api.example', response.audience);
      System.assertEquals('regular', response.role);
      System.assertEquals(testUser.CustomerId__c, response.subject);
      System.assertEquals('test.jwt.signature', response.token);
      System.assertNotEquals(null, response.issuedAtEpochSeconds);
      System.assertNotEquals(null, response.expiresAtEpochSeconds);
      System.assert(
        response.expiresAtEpochSeconds > response.issuedAtEpochSeconds
      );
    }
  }

  @IsTest
  static void generateJwtRequiresCustomerId() {
    User testUser = createUser('missingcustomer', null);

    System.runAs(testUser) {
      try {
        JwtSignerService.generateJwt();
        System.assert(
          false,
          'Expected an AuraHandledException when CustomerId__c is blank.'
        );
      } catch (AuraHandledException ex) {
        System.assert(ex.getMessage().contains('Customer ID is required'));
      }
    }
  }

  private static User createUser(String key, String customerId) {
    Profile profile = [
      SELECT Id
      FROM Profile
      WHERE Id = :UserInfo.getProfileId()
      LIMIT 1
    ];
    String uniqueValue = String.valueOf(DateTime.now().getTime()) + key;
    User testUser = new User(
      Alias = key.left(8),
      Email = uniqueValue + '@example.com',
      EmailEncodingKey = 'UTF-8',
      LastName = 'Test User',
      LanguageLocaleKey = 'en_US',
      LocaleSidKey = 'en_US',
      ProfileId = profile.Id,
      TimeZoneSidKey = 'America/Los_Angeles',
      Username = uniqueValue + '@example.com'
    );

    if (customerId != null) {
      testUser.CustomerId__c = customerId;
    }

    insert testUser;
    return testUser;
  }
}
