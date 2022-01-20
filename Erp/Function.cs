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


        // fetch the details from cache in order to have secure enviorment
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

        //Assistive function to inject headers and return api response, called at multiple places in code file
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


        public APIGatewayProxyResponse UpdateUserProfileRole(APIGatewayProxyRequest request, ILambdaContext context)
        {
           
            try
            {
                //checking for context and logging to see if have the request properly
                context.Logger.LogLine(JsonConvert.SerializeObject(request));
                context.Logger.LogLine(JsonConvert.SerializeObject(request.RequestContext.Authorizer.Claims));
                
                //mapping
                string phoneNumber = string.Empty;
                string cUserId =Authentication.Functions.GetUserGUID(request, context);
                request.RequestContext.Authorizer.Claims.TryGetValue("phone_number", out phoneNumber);

              

                Communication.RequetModel.CommunicationRequest.UserProfileRequest userProfileRequest = JsonConvert.DeserializeObject<Communication.RequetModel.CommunicationRequest.UserProfileRequest>(hFunctions.ConvertToPascalCase(request.Body));
                if(userProfileRequest.UserID == null || userProfileRequest.Role == null)
                {
                    return APIResponse((int)HttpStatusCode.BadRequest, new { message = "Incomplete Parameters" });
                }
                // step 0. get profile
                Communication.DAL.ComDAL.UserDataDataRecord userProfileRecord = Communication.DAL.ComDAL.UserDataDataRecord.QueryUserProfile(cUserId);

                //need to save phoneNumber if not already saved
                if (string.IsNullOrEmpty(userProfileRecord.PhoneNumber))
                {
                    userProfileRecord.PhoneNumber = phoneNumber;
                    Communication.DAL.ComDAL.UserDataDataRecord udi = new Communication.DAL.ComDAL.UserDataDataRecord(phoneNumber, cUserId);
                    udi.Save();
                }

                if (userProfileRecord.IsAuthorized!=null && userProfileRecord.IsAuthorized == true )
                {

                    // write role allocation logic here
                    Communication.DAL.ComDAL.UserDataDataRecord receipientRecord = Communication.DAL.ComDAL.UserDataDataRecord.QueryUserProfile(userProfileRequest.UserID);
                    /// check for the user that has to be upgraded in role
                    Communication.DAL.ComDAL.UserDataDataRecord.setRoles(receipientRecord, userProfileRequest.Role);
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


        public APIGatewayProxyResponse DeleteUserProfileRole(APIGatewayProxyRequest request, ILambdaContext context)
        {

            try
            {
                //checking for context and logging to see if have the request properly
                context.Logger.LogLine(JsonConvert.SerializeObject(request));
                context.Logger.LogLine(JsonConvert.SerializeObject(request.RequestContext.Authorizer.Claims));
                string cUserId = Authentication.Functions.GetUserGUID(request, context);

                Communication.RequetModel.CommunicationRequest.UserProfileRequest userProfileRequest = JsonConvert.DeserializeObject<Communication.RequetModel.CommunicationRequest.UserProfileRequest>(hFunctions.ConvertToPascalCase(request.Body));
                if (userProfileRequest.UserID == null || userProfileRequest.Role == null)
                {
                    return APIResponse((int)HttpStatusCode.BadRequest, new { message = "Incomplete Parameters" });
                }
                // step 0. get profile
                Communication.DAL.ComDAL.UserDataDataRecord userProfileRecord = Communication.DAL.ComDAL.UserDataDataRecord.QueryUserProfile(cUserId);


                if (userProfileRecord.IsAuthorized != null && userProfileRecord.IsAuthorized == true)
                {

                    // write role allocation logic here
                    Communication.DAL.ComDAL.UserDataDataRecord receipientRecord = Communication.DAL.ComDAL.UserDataDataRecord.QueryUserProfile(userProfileRequest.UserID);
                    /// check for the user that has to be upgraded in role
                    Communication.DAL.ComDAL.UserDataDataRecord.removeRoles(receipientRecord, userProfileRequest.Role);
                    return APIResponse((int)HttpStatusCode.OK, new { message = "Role Removed Successfully." });
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
