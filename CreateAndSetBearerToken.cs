using System;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Azure.Identity;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;

namespace Company.Function
{
    public static class CreateAndSetBearerToken
    {
        [FunctionName("CreateAndSetBearerToken")]
        public static async Task Run([TimerTrigger("0 30 0 * * *")]TimerInfo timer, ILogger log)
        {
            log.LogInformation($"CreateAndSetBearerToken: triggered at {DateTime.Now}");

            try
            {
                // Get the 'default' Azure Credential - see here: https://docs.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet
                DefaultAzureCredential credential = new DefaultAzureCredential();

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

                // Get the access token of this credential for the provided scope
                string token = (await credential.GetTokenAsync(new TokenRequestContext(new[] { scope }))).Token;
                
                // Set the access token in the Key Vault, prefixed with 'Bearer'
                SecretClient keyVaultClient = new SecretClient(new Uri(Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_URI")), credential);
                KeyVaultSecret keyVaultSecret = await keyVaultClient.SetSecretAsync(Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_SECRET_NAME"), "Bearer " + token);

                // Log success, providing the Secret's version
                log.LogInformation($"CreateAndSetBearerToken: successfully created and set a Bearer token in the Secret with version '{keyVaultSecret.Properties.Version}'");
            }
            catch (Exception ex)
            {
                log.LogError(ex.Message);
            }
        }
    }
}
