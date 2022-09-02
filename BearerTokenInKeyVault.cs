// Default URL for triggering event grid function in the local environment.
// http://localhost:7071/runtime/webhooks/EventGrid?functionName=ProcessKeyVaultSecretEvent
using System;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.WebJobs.Extensions.EventGrid;
using Microsoft.IdentityModel.Tokens;
using Azure.Identity;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using Azure.Messaging.EventGrid;

namespace Company.Function
{
    public static class BearerTokenInKeyVault
    {
        [FunctionName("ProcessKeyVaultSecretEvent")]
        public static async Task ProcessKeyVaultSecretEvent([EventGridTrigger] EventGridEvent eventGridEvent, ILogger log)
        {
            try
            {
                // Log the raw event data
                //   https://docs.microsoft.com/en-us/azure/event-grid/event-schema-key-vault?tabs=event-grid-event-schema
                log.LogDebug($"Event data: {eventGridEvent.Data.ToString()}");

                // Only process the secret-related events
                //   Available event types: https://docs.microsoft.com/en-us/azure/event-grid/event-schema-key-vault?tabs=event-grid-event-schema#available-event-types 
                AzureKeyVaultEventGridData azureKeyVaultEventGridData;
                switch (eventGridEvent.EventType)
                {
                    case "Microsoft.KeyVault.SecretNewVersionCreated":
                    case "Microsoft.KeyVault.SecretExpired":
                    // case SecretNearExpiry: // Ignore this event type because it's triggered 30 days before the expiration date - this is too soon
                        // We have a secret-related event - grab it and we'll process it later
                        azureKeyVaultEventGridData = eventGridEvent.Data.ToObjectFromJson<AzureKeyVaultEventGridData>();
                        log.LogDebug($"Deserialized data:");
                        log.LogDebug($"\tEvent Type:      {eventGridEvent.EventType}");
                        log.LogDebug($"\tKey Vault Name:  {azureKeyVaultEventGridData.VaultName}");
                        log.LogDebug($"\tSecret Name:     {azureKeyVaultEventGridData.ObjectName}");
                        log.LogDebug($"\tSecret Version:  {azureKeyVaultEventGridData.Version}");
                        log.LogDebug($"\tSecret Expiry:   {azureKeyVaultEventGridData.Expiry.ToString()} (UTC)");
                        break;
                    default:
                        // Not interested in these events - ignore it
                        throw new ProcessKeyVaultSecretEventException($"Ignoring event: Event type '{eventGridEvent.EventType}' is not supported. To avoid this message, create an Event Grid filter to only sent events for 'Secret New Version Created' and 'Secret Expired'. See here for details: https://docs.microsoft.com/en-us/azure/event-grid/event-filtering");
                }

                // Check this key vault is the one we want to process
                string keyVaultURI = Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_URI");
                if (String.IsNullOrEmpty(keyVaultURI))
                {
                    throw new Exception("AZURE_KEY_VAULT_URI is not set. Add AZURE_KEY_VAULT_URI to the function's application settings.");
                }
                if (!keyVaultURI.Contains(azureKeyVaultEventGridData.VaultName))
                {
                    // Not interested in this key vault - ignore it
                    throw new ProcessKeyVaultSecretEventException($"Ignoring event: Key Vault '{azureKeyVaultEventGridData.VaultName}' not recognised");
                }

                // Check this subject is the secret we want to process
                if (String.IsNullOrEmpty(Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_SECRET_NAME")))
                {
                    throw new Exception("AZURE_KEY_VAULT_SECRET_NAME is not set. Add AZURE_KEY_VAULT_SECRET_NAME to the function's application settings.");
                }
                if (!Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_SECRET_NAME").Equals(azureKeyVaultEventGridData.ObjectName))
                {
                    // Not interested in this subject - ignore it
                    throw new ProcessKeyVaultSecretEventException($"Ignoring event: Subject '{azureKeyVaultEventGridData.ObjectName}' not recognised");
                }

                // If we get to here, we have a secret-related Event Grid event for the desired key vault and secret - keep processing

                // Get a 'default' Azure Credential - see here: https://docs.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet
                DefaultAzureCredential credential = new DefaultAzureCredential();

                // Create a Key Vault client
                SecretClient keyVaultClient = new SecretClient(new Uri(keyVaultURI), credential);

                // For new secrets, check if the bearer token is valid
                // For expiring secrets or invalid bearer tokens, create a new token
                if ((eventGridEvent.EventType.Equals("Microsoft.KeyVault.SecretNewVersionCreated")) 
                    && await IsValidBearerToken(credential, (keyVaultClient.GetSecret(azureKeyVaultEventGridData.ObjectName, azureKeyVaultEventGridData.Version)).Value.Value))
                {
                    // Token is valid - do nothing
                    log.LogInformation($"Ignoring event: Bearer token for {Environment.GetEnvironmentVariable("SCOPE")}, in the secret '{azureKeyVaultEventGridData.ObjectName}', with version '{azureKeyVaultEventGridData.Version} is new but valid");
                }
                else
                {
                    // Token is expired or is a new secret that is not valid - create a new bearer token
                    log.LogDebug($"Bearer token is expiring or is invalid - creating a new bearer token to replace it");
                    KeyVaultSecret keyVaultSecret = SetSecretBearerToken(keyVaultClient, azureKeyVaultEventGridData.ObjectName, GetToken(credential));

                    // Log success, providing the new secret's version
                    log.LogInformation($"Success: created and set a bearer token for {Environment.GetEnvironmentVariable("SCOPE")}, in the secret '{azureKeyVaultEventGridData.ObjectName}', with version '{keyVaultSecret.Properties.Version}'");
                }
            }
            catch (ProcessKeyVaultSecretEventException ex)
            {
                // Log the exception as a warning, gobble it and return
                log.LogWarning(ex.Message);
                return;
            }
            catch (Azure.RequestFailedException ex)
            {
                // Requests to Azure Key Vault failed - likely due to the secret no longer existing. 
                //   Log the exception as a warning, gobble and return
                log.LogWarning(ex.Message);
                return;
            }
            catch (Exception ex)
            {
                log.LogError(ex.Message);
                // Throw up the error - doing so will flag the event as not being processed successfully, allowing it to be reprocessed or sent to a dead-letter queue
                throw;
            }
        }

        public static async Task<bool> IsValidBearerToken(DefaultAzureCredential credential, string bearerToken)
        {
            // First, check the bearerToken starts with "Bearer "
            if (!bearerToken.StartsWith("Bearer "))
            {
                // Not a valid bearer token - return false
                return false;
            }
            // Strip "Bearer " to get just the token
            string accessToken = bearerToken.Substring(7);

            // Validate the access token, including the audience, the signature and the lifetime.
            // Refer to the Azure.Identity documentation regarding validating an access token:
            //   https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#validate-tokens 
            {
                // Get the scope from the environment variable - it's our audience
                string audience = Environment.GetEnvironmentVariable("SCOPE");
                if (String.IsNullOrEmpty(audience))
                {
                    throw new Exception("SCOPE not configured in the environment variables. Set the SCOPE to the value of the value of the 'Application ID URI' for the Azure AD App Registration that is configured for the Speech Web Endpoint's authentication.");
                }
                // Remove the trailing '/.default' from the scope
                if (audience.EndsWith("/.default"))
                {
                    audience = audience.Substring(0, audience.Length - "/.default".Length);
                }

                // Get the OpenID configuration, so we can validate the signing keys
                const string stsDiscoveryEndpoint = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
                ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());
                OpenIdConnectConfiguration config = await configManager.GetConfigurationAsync();
                try
                {
                    // Valirdate the access token
                    (new JwtSecurityTokenHandler()).ValidateToken(accessToken, new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKeys = config.SigningKeys,
                        ValidateAudience = true,
                        ValidAudience = audience,
                        ValidateLifetime = true
                    }, out SecurityToken validatedToken);
                    // No exception = token is valid
                }
                catch
                {
                    // Token validation failed - return false
                    return false;
                }
            }

            // Getting to here means the token is valid
            return true;
        }

        public static string GetToken(DefaultAzureCredential credential)
        {
            // Grab the scope for the access token, it should be set to the value of the "Application ID URI" for the Azure AD App Registration that is configured for the Speech Web Endpoint's (i.e., the Azure Function) authentication 
            //   (see here: https://docs.microsoft.com/en-us/azure/app-service/configure-authentication-provider-aad).
            string scope = Environment.GetEnvironmentVariable("SCOPE");
            if (String.IsNullOrEmpty(scope))
            {
                throw new Exception("SCOPE not configured in the environment variables. Set the SCOPE to the value of the value of the 'Application ID URI' for the Azure AD App Registration that is configured for the Speech Web Endpoint's authentication.");
            }
            // Ensure the scope ends with "/.default"
            if (!scope.EndsWith("/.default"))
                scope += "/.default";

            // Get and return the access token of this credential for the provided scope
            return (credential.GetToken(new TokenRequestContext(new[] { scope }))).Token;
        }

        public static KeyVaultSecret SetSecretBearerToken(SecretClient keyVaultClient, string secretName, string accessToken)
        {
            // Get a JWT token representing the access token
            JwtSecurityToken jtwToken = new JwtSecurityToken(accessToken);

            // Set the access token in the Key Vault, prefixed with 'Bearer'
            KeyVaultSecret keyVaultSecret = new KeyVaultSecret(secretName, "Bearer " + accessToken);

            // Set the validity of the secret to be the same as the JWT token's lifetime
            keyVaultSecret.Properties.NotBefore = jtwToken.ValidFrom;
            keyVaultSecret.Properties.ExpiresOn = jtwToken.ValidTo.AddMinutes(-5); // Subtract 5 minutes to ensure the token can be refreshed before it expires, because the event can take up to 5 minutes to trigger

            // Set the secret in the Key Vault
            return keyVaultClient.SetSecret(keyVaultSecret);
        }
    }

    public class ProcessKeyVaultSecretEventException : Exception
    {
        public ProcessKeyVaultSecretEventException(string message) : base(message)
        {
        }
    }
}
