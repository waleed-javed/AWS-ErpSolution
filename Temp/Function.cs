using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DataModel;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using System.Text;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Temp
{
    public class Functions
    {
        private static readonly AmazonDynamoDBConfig configDbClient = new AmazonDynamoDBConfig { MaxErrorRetry = 3, Timeout = TimeSpan.FromSeconds(7) };
        private static readonly AmazonDynamoDBClient awsDynamoDbClient = new AmazonDynamoDBClient(configDbClient);
        private static readonly DynamoDBContextConfig dynamoDBContextConfig = new DynamoDBContextConfig { ConsistentRead = true, IgnoreNullValues = true, SkipVersionCheck = true };
        private static AmazonCognitoIdentityProviderClient cognitoClient = new AmazonCognitoIdentityProviderClient();

        private static readonly AmazonDynamoDBConfig configForInit = new AmazonDynamoDBConfig { MaxErrorRetry = 1, Timeout = TimeSpan.FromSeconds(3) };
        private static AmazonDynamoDBClient awsDynamoDbClientForInit = new AmazonDynamoDBClient(configForInit);


        public Functions()
        {
        }

        public void UpdateCacheData(ILambdaContext context)
        {
            //Create a management client 
            AmazonSimpleSystemsManagementClient ssmClient = new AmazonSimpleSystemsManagementClient();

            string stageName = "Dev";
            List<string> parameterNames = new List<string> { "AWSSigV4",   "Cognito", "DefaultPassword",  "StateMachineArn"};
            List<string> fullNames = parameterNames.Select(s => $"/ErpSolution/{stageName}/{s}").ToList(); //make full names list

            fullNames.ForEach(f => {
                GetParameterRequest getParameterRequest = new GetParameterRequest()
                {
                    Name = f,
                    WithDecryption = true
                };
                GetParameterResponse getParameterResponse = ssmClient.GetParameterAsync(getParameterRequest).Result;
                string value = getParameterResponse.Parameter.Value;

                Communication.DAL.ComDAL.CacheDataRecord cacheDataRecord = new Communication.DAL.ComDAL.CacheDataRecord()
                {
                    Key = f,
                    Value = Convert.ToBase64String(Encoding.UTF8.GetBytes(value)),
                    CreatedDate = DateTime.UtcNow,
                    LastModifiedDate = DateTime.UtcNow
                };

                cacheDataRecord.Save();
            });

        }


        public void DeleteUsersFromCognitoSystem(APIGatewayProxyRequest request, ILambdaContext context)
        {
            /// Delete All users form cognito pool for system update purposes 

            string userPoolId = "";
            //create a lisitng request to congito
            ListUsersRequest listUsersRequest = new ListUsersRequest
            {
                UserPoolId = userPoolId
            };

            //List user Response
            ListUsersResponse listUsersResponse = cognitoClient.ListUsersAsync(listUsersRequest).Result;
            listUsersResponse.Users.ForEach(u =>
            {
                AdminDeleteUserRequest adminDeleteUserRequest = new AdminDeleteUserRequest
                {
                    Username = u.Username,
                    UserPoolId = userPoolId
                };
            });

        }
    }
}
