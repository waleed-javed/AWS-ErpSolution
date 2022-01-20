using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

using Amazon.CognitoIdentity;
using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;
using Authentication;
using Amazon.S3;
using System.Net.Http;
using Amazon.XRay.Recorder.Handlers.AwsSdk;
using Newtonsoft.Json;
using System.Text;
using Amazon.CodeDeploy.Model;
using Amazon.CodeDeploy;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Erp
{
    public class Functions
    {
        private static readonly string stageName;
        private static string isXrayTracingEnabled;
        private static readonly CognitoDetails cognitoDetails = new CognitoDetails();
        private static IAmazonS3 s3Client;
        readonly Communication.Helper.HelperFunctions hFunctions;
        private static readonly HttpClient httpClient = new HttpClient();

        static Functions()
        {
            try
            {
                isXrayTracingEnabled = Environment.GetEnvironmentVariable("XRayTracingState");
                if (string.IsNullOrEmpty(isXrayTracingEnabled))
                {
                    AWSSDKHandler.RegisterXRayForAllServices();
                }
                stageName = Environment.GetEnvironmentVariable("StageName") ?? "Dev";
                cognitoDetails = JsonConvert.DeserializeObject<CognitoDetails>(GetParameterValue("Cognito"));
              
            }
            catch (Exception ex)
            {
                LambdaLogger.Log($"EXCEPTION: {ex.Message} - {ex.StackTrace}");
            }
        }

        public Functions()
        {
        }


        /// fetch the details from cache in order to have secure enviorment
        public static string GetParameterValue(string parameterName)
        {
            string fullName = $"/ErpSolution/{stageName}/{parameterName}";

            Communication.DAL.ComDAL.CacheDataRecord cacheData = new Communication.DAL.ComDAL.CacheDataRecord();
            if (cacheData == null || string.IsNullOrEmpty(cacheData.Value))
            {
                return string.Empty;
            }

            return Encoding.UTF8.GetString(Convert.FromBase64String(cacheData.Value));
        }

        ///Assistive function to inject headers and return api response, called at multiple places in code file
        private static APIGatewayProxyResponse APIResponse(int statusCode, dynamic body)
        {
            Dictionary<string, string> securityHeaders = new Dictionary<string, string> {
                    { "Content-Type", "application/json" },
                    { "Access-Control-Allow-Origin", "*" },
                    { "X-Frame-Options", "DENY"},
                    { "Content-Security-Policy", "default-src https:"},
                    { "Strict-Transport-Security", "max-age=86400;"},
                    { "X-Content-Type-Options", "nosniff"}
            };
            APIGatewayProxyResponse response = new APIGatewayProxyResponse
            {
                StatusCode = statusCode,
                Headers = securityHeaders
            };

            if (body != null)
            {
                response.Body = JsonConvert.SerializeObject(body);
            }

            return response;
        }

        /// <summary>
        /// Lambda PreTrafficHook for status report on deployment cycle execution
        /// </summary>
        /// <param name="request"></param>
        /// <param name="context"></param>
        public void UpdateUserProfileRole(PutLifecycleEventHookExecutionStatusRequest request, ILambdaContext context)
        {
            string stageName = Environment.GetEnvironmentVariable("StageName");
            string newVersion = Environment.GetEnvironmentVariable("NewVersion");
            context.Logger.Log($"{stageName} - {newVersion}");
            AmazonCodeDeployClient codeDeployClient = new AmazonCodeDeployClient();
            request.Status = "Succeeded";

            PutLifecycleEventHookExecutionStatusResponse resp = codeDeployClient.PutLifecycleEventHookExecutionStatusAsync(request).Result;

            context.Logger.Log($"Execution status code: {resp.HttpStatusCode}");
        }

        /// <summary>
        ///             A function which will be executed everytime a user role has to be added
        /// </summary>
        /// <param name="request"></param>
        /// <param name="context"></param>
        /// <returns>
        ///             API Response with HTTP CODE and STATUS Message
        /// </returns>
        public APIGatewayProxyResponse UpdateUserProfileRole(APIGatewayProxyRequest request, ILambdaContext context)
        {
           
            try
            {
                ///checking for context and logging to see if have the request properly
                context.Logger.LogLine(JsonConvert.SerializeObject(request));
                context.Logger.LogLine(JsonConvert.SerializeObject(request.RequestContext.Authorizer.Claims));
                
                ///mapping
                string phoneNumber = string.Empty;
                string receipientId = string.Empty;
                string cUserId =Authentication.Functions.GetUserGUID(request, context);
                request.RequestContext.Authorizer.Claims.TryGetValue("phone_number", out phoneNumber);

                ///step 0. get profile of the requester
                Communication.DAL.ComDAL.UserDataDataRecord userProfileRecord = Communication.DAL.ComDAL.UserDataDataRecord.QueryUserProfile(cUserId);

                ///need to save phoneNumber if not already saved
                if (string.IsNullOrEmpty(userProfileRecord.PhoneNumber))
                {
                    userProfileRecord.PhoneNumber = phoneNumber;
                    Communication.DAL.ComDAL.UserDataDataRecord udi = new Communication.DAL.ComDAL.UserDataDataRecord(phoneNumber, cUserId);
                    udi.Save();
                }

                // de-marshalling a request packet into a name-value pairing list witholding all the attributes
                Communication.RequetModel.CommunicationRequest.UserProfileRequest userProfileRequest = JsonConvert.DeserializeObject<Communication.RequetModel.CommunicationRequest.UserProfileRequest>(hFunctions.ConvertToPascalCase(request.Body));


                userProfileRequest.UserProfileFields.AsParallel().ForAll(attribute => { 
                
                    // only authorize is the user is an admin in role
                    if(attribute.Name == "custom:uid" && attribute.Value != null)
                    {
                        if (userProfileRecord.IsAuthorized == null)
                        {
                            userProfileRecord.IsAuthorized = Communication.DAL.ComDAL.UserDataDataRecord.IsAdminAccessPrivilege(userProfileRecord);
                        }
                        
                    }
                    if(attribute.Name == "receipientId" && attribute.Value != null)
                    {
                        receipientId = attribute.Value;
                    }
                });

                ///handling roles differently as it can be more than one
                List<string> roles = new List<string>();
                bool updateUserRoles = false;
               
                userProfileRequest.UserProfileFields.ForEach(attr => { 
                    if(attr.Name == nameof(userProfileRecord.Roles))
                    {
                        roles.Add(attr.Value);
                        updateUserRoles = true;
                        return;
                    }
                });
                    
                if (updateUserRoles)
                {
                    /// FOR THE SAKE OF THIS PROTOTYPE PROJECT I AM ASSUMING THE USER WILL ALWAYS PASS RECEIPIENT ID 
                    /// IF THE ID IS not passed, the system will most likely crash as no null handling is done for this particular case.
                    Communication.DAL.ComDAL.UserDataDataRecord uddr =Communication.DAL.ComDAL.UserDataDataRecord.QueryUserProfile(receipientId);

                    uddr.Roles = roles; //adding all the roles
                    uddr.Save();

                    return APIResponse((int)HttpStatusCode.OK, new { message = "Updated Successfully." });

                }


                return APIResponse((int)HttpStatusCode.Forbidden, new { message = "Not Authorized Request." });
            }
            catch (Exception ex)
            {
                context.Logger.LogLine($"Exception: {ex.Message} - {ex.StackTrace}");
                return APIResponse((int)HttpStatusCode.InternalServerError, new { message = "Something went wrong, please try again." });
            }
        }

        /// <summary>
        ///             A function which will be executed everytime a user role has to be removed
        /// </summary>
        /// <param name="request"></param>
        /// <param name="context"></param>
        /// <returns>
        ///             API Response with HTTP CODE and STATUS Message
        /// </returns>
        public APIGatewayProxyResponse DeleteUserProfileRole(APIGatewayProxyRequest request, ILambdaContext context)
        {

            try
            {
                //checking for context and logging to see if have the request properly
                context.Logger.LogLine(JsonConvert.SerializeObject(request));
                context.Logger.LogLine(JsonConvert.SerializeObject(request.RequestContext.Authorizer.Claims));
                string receipientId = string.Empty;
                string cUserId = Authentication.Functions.GetUserGUID(request, context);

                Communication.RequetModel.CommunicationRequest.UserProfileRequest userProfileRequest = JsonConvert.DeserializeObject<Communication.RequetModel.CommunicationRequest.UserProfileRequest>(hFunctions.ConvertToPascalCase(request.Body));

                ///step 0. get profile of the requester
                Communication.DAL.ComDAL.UserDataDataRecord userProfileRecord = Communication.DAL.ComDAL.UserDataDataRecord.QueryUserProfile(cUserId);

                userProfileRequest.UserProfileFields.AsParallel().ForAll(attribute => {

                    // only authorize is the user is an admin in role
                    if (attribute.Name == "custom:uid" && attribute.Value != null)
                    {
                        if (userProfileRecord.IsAuthorized == null)
                        {
                            userProfileRecord.IsAuthorized = Communication.DAL.ComDAL.UserDataDataRecord.IsAdminAccessPrivilege(userProfileRecord);
                        }

                    }
                    if (attribute.Name == "receipientId" && attribute.Value != null)
                    {
                        receipientId = attribute.Value;
                    }
                });

                ///handling roles differently as it can be more than one
                List<string> roles = new List<string>();
                bool updateUserRoles = false;

                userProfileRequest.UserProfileFields.ForEach(attr => {
                    if (attr.Name == nameof(userProfileRecord.Roles))
                    {
                        roles.Remove(attr.Value);
                        updateUserRoles = true;
                        return;
                    }
                });

                if (updateUserRoles)
                {
                    /// FOR THE SAKE OF THIS PROTOTYPE PROJECT I AM ASSUMING THE USER WILL ALWAYS PASS RECEIPIENT ID 
                    /// IF THE ID IS not passed, the system will most likely crash as no null handling is done for this particular case.
                    Communication.DAL.ComDAL.UserDataDataRecord uddr = Communication.DAL.ComDAL.UserDataDataRecord.QueryUserProfile(receipientId);

                    uddr.Roles = roles; //adding all the roles
                    uddr.Save();

                    return APIResponse((int)HttpStatusCode.OK, new { message = "Roles Updated Successfully." });

                }


                return APIResponse((int)HttpStatusCode.Forbidden, new { message = "Not Authorized Request." });
            }
            catch (Exception ex)
            {
                context.Logger.LogLine($"Exception: {ex.Message} - {ex.StackTrace}");
                return APIResponse((int)HttpStatusCode.InternalServerError, new { message = "Something went wrong, please try again." });
            }
        }


    }
}
