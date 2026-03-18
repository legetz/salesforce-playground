public with sharing class JwtSignerService {
  private static final String DEFAULT_ROLE = 'regular';
  private static final String PERMISSION_SET_MATCH_TYPE = 'PermissionSet';

  public class JwtResponse {
    @AuraEnabled
    public String appKey;
    @AuraEnabled
    public String audience;
    @AuraEnabled
    public Long expiresAtEpochSeconds;
    @AuraEnabled
    public Long issuedAtEpochSeconds;
    @AuraEnabled
    public String role;
    @AuraEnabled
    public String subject;
    @AuraEnabled
    public String token;
  }

  @AuraEnabled
  public static JwtResponse generateJwt() {
    JwtSignerConfig__mdt config = getActiveConfig();
    User currentUser = [
      SELECT Id, Name, Email, CustomerId__c
      FROM User
      WHERE Id = :UserInfo.getUserId()
    ];

    if (String.isBlank(currentUser.CustomerId__c)) {
      throwHandledException('Customer ID is required before generating a JWT.');
    }

    String resolvedRole = resolveRole(config, currentUser.Id);
    Integer validitySeconds = getValiditySeconds(
      config.TokenLifetimeSeconds__c
    );
    Datetime issuedAt = Datetime.now();
    Datetime expiresAt = issuedAt.addSeconds(validitySeconds);

    Auth.JWT jwt = new Auth.JWT();
    jwt.setIss(config.Issuer__c);
    jwt.setSub(currentUser.CustomerId__c);
    jwt.setAud(config.Audience__c);
    jwt.setValidityLength(validitySeconds);
    jwt.setAdditionalClaims(buildAdditionalClaims(currentUser, resolvedRole));

    try {
      JwtResponse response = new JwtResponse();
      response.appKey = config.AppKey__c;
      response.audience = config.Audience__c;
      response.expiresAtEpochSeconds = toEpochSeconds(expiresAt);
      response.issuedAtEpochSeconds = toEpochSeconds(issuedAt);
      response.role = resolvedRole;
      response.subject = currentUser.CustomerId__c;
      response.token = getSignedToken(jwt, config.CertificateDeveloperName__c);
      return response;
    } catch (Exception ex) {
      throwHandledException(
        'JWT signing failed. Check the certificate developer name in JWT Signer Config metadata.'
      );
      return null;
    }
  }

  private static JwtSignerConfig__mdt getActiveConfig() {
    List<JwtSignerConfig__mdt> configs = [
      SELECT
        DeveloperName,
        AppKey__c,
        Audience__c,
        CertificateDeveloperName__c,
        FallbackRole__c,
        Issuer__c,
        IsActive__c,
        TokenLifetimeSeconds__c
      FROM JwtSignerConfig__mdt
      WHERE IsActive__c = TRUE
      ORDER BY DeveloperName
      LIMIT 2
    ];

    if (configs.isEmpty()) {
      throwHandledException(
        'No active JWT signer config metadata record was found.'
      );
    }
    if (configs.size() > 1) {
      throwHandledException(
        'Multiple active JWT signer config metadata records were found. Keep only one active record for this demo.'
      );
    }

    return configs[0];
  }

  private static Integer getValiditySeconds(Decimal configuredSeconds) {
    if (configuredSeconds == null || configuredSeconds <= 0) {
      return 300;
    }

    return configuredSeconds.intValue();
  }

  private static String resolveRole(JwtSignerConfig__mdt config, Id userId) {
    Set<String> assignedPermissionSetNames = new Set<String>();
    for (PermissionSetAssignment assignment : [
      SELECT PermissionSet.Name
      FROM PermissionSetAssignment
      WHERE AssigneeId = :userId
    ]) {
      if (
        assignment.PermissionSet != null &&
        !String.isBlank(assignment.PermissionSet.Name)
      ) {
        assignedPermissionSetNames.add(assignment.PermissionSet.Name);
      }
    }

    List<JwtUserRoleRule__mdt> matchingRules = [
      SELECT
        DeveloperName,
        AppKey__c,
        IsActive__c,
        MatchType__c,
        Priority__c,
        ResolvedRole__c,
        TargetApiName__c
      FROM JwtUserRoleRule__mdt
      WHERE
        IsActive__c = TRUE
        AND AppKey__c = :config.AppKey__c
        AND MatchType__c = :PERMISSION_SET_MATCH_TYPE
      ORDER BY Priority__c DESC, DeveloperName ASC
    ];

    for (JwtUserRoleRule__mdt rule : matchingRules) {
      if (assignedPermissionSetNames.contains(rule.TargetApiName__c)) {
        return rule.ResolvedRole__c;
      }
    }

    if (!String.isBlank(config.FallbackRole__c)) {
      return config.FallbackRole__c;
    }

    return DEFAULT_ROLE;
  }

  private static Map<String, Object> buildAdditionalClaims(
    User currentUser,
    String resolvedRole
  ) {
    Map<String, Object> claims = new Map<String, Object>{
      'customer_id' => currentUser.CustomerId__c,
      'role' => resolvedRole
    };

    if (!String.isBlank(currentUser.Email)) {
      claims.put('email', currentUser.Email);
    }
    if (!String.isBlank(currentUser.Name)) {
      claims.put('name', currentUser.Name);
    }

    return claims;
  }

  private static String getSignedToken(
    Auth.JWT jwt,
    String certificateDeveloperName
  ) {
    if (Test.isRunningTest()) {
      return 'test.jwt.signature';
    }

    Auth.JWS jws = new Auth.JWS(jwt, certificateDeveloperName);
    return jws.getCompactSerialization();
  }

  private static Long toEpochSeconds(Datetime value) {
    return value.getTime() / 1000;
  }

  private static void throwHandledException(String message) {
    AuraHandledException ex = new AuraHandledException(message);
    ex.setMessage(message);
    throw ex;
  }
}
