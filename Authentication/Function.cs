using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.XRay.Recorder.Handlers.AwsSdk;
using Newtonsoft.Json;
using Amazon.SimpleEmailV2;
using System.Text;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider.Model;
using System.Security.Cryptography;
using Amazon.CodeDeploy;

using Amazon.CodeDeploy.Model;


// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace Authentication
{
    //Required classes for initial setup of cognito
    public class CognitoDetails
    {

        public string CognitoUserPoolId { get; set; }
        public string CognitoClientId { get; set; }
        public string CognitoClientSecret { get; set; }
        public string CognitoIdentityPoolId { get; set; }
    }

    public class ErrorResponseStatus
    {
        public int statusCode { get; set; }
        public string message { get; set; }
    }
    public class Functions
    {
        //Environmental variables
        private static readonly string stageName;
        private static string isXrayTracingEnabled;
        private static string defaultPassword;
        private static CognitoDetails cognitoDetails = new CognitoDetails();
        private static AmazonCognitoIdentityProviderClient cognitoClient = new AmazonCognitoIdentityProviderClient();
        private static AmazonSimpleEmailServiceV2Client amazonSimpleEmailClient = new AmazonSimpleEmailServiceV2Client();
        private static CognitoUserPool cognitoUserPool;        

        private static readonly dynamic internalServerErrorMessage = new { message = "Something went wrong. Please try again later." };
        private static readonly dynamic badRequestErrorMessage = new { message = "Invalid request." };


        public Functions()
        {
        }

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
                defaultPassword = GetParameterValue("DefaultPassword");
                cognitoDetails = JsonConvert.DeserializeObject<CognitoDetails>(GetParameterValue("Cognito"));
                cognitoUserPool = new CognitoUserPool(cognitoDetails.CognitoUserPoolId, cognitoDetails.CognitoClientId, cognitoClient, cognitoDetails.CognitoClientSecret);
            }
            catch (Exception ex)
            {
                LambdaLogger.Log($"EXCEPTION: {ex.Message} - {ex.StackTrace}");
            }


        }

        /// <summary>
        /// Create User
        /// 
        /// </summary>
        
        public void CreateUserPTH(PutLifecycleEventHookExecutionStatusRequest request, ILambdaContext context)
        {
            string stageName = Environment.GetEnvironmentVariable("StageName");
            string newVersion = Environment.GetEnvironmentVariable("NewVersion");
            context.Logger.Log($"{stageName} - {newVersion}");
            AmazonCodeDeployClient codeDeployClient = new AmazonCodeDeployClient();
            request.Status = "Succeeded";

            PutLifecycleEventHookExecutionStatusResponse resp = codeDeployClient.PutLifecycleEventHookExecutionStatusAsync(request).Result;

            context.Logger.Log($"Execution status code: {resp.HttpStatusCode}");
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

        //Calcuting hash for Assitive purposes
        private static string CalculateSecretHash(string username)
        {
            const string HMAC_SHA256_ALGORITHM = "HmacSHA256";

            KeyedHashAlgorithm keyedHashAlgorithm = KeyedHashAlgorithm.Create(HMAC_SHA256_ALGORITHM);
            keyedHashAlgorithm.Key = Encoding.UTF8.GetBytes(cognitoDetails.CognitoClientSecret);
            byte[] computedHash = keyedHashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes($"{username}{cognitoDetails.CognitoClientId}"));

            return Convert.ToBase64String(computedHash);
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


        /// 
        /// Start the Create the User Process  
        /// First setup deafault profiels and then start the cration request
        /// initiate the cognito 
        /// use SRP to setup the user profile in the cognito user pool and cognito authorizer system

        public (bool IsSuccess, ErrorResponseStatus status) CreateCognitoUserProfile(dynamic requestBody, ILambdaContext context, string guid="")
        {
            try
            {
                ///PHONE NUMBER IS USED A DEFAULT AS IT IS MORE LESS LIKELY TO GET HACKED 

                /// Start by creating a temporary setup password for the user 
                /// and add other cognito attributes as per desired system requirementa
                string username = ((string)requestBody.phoneNumber).Replace("+", string.Empty);
                string uid = Guid.NewGuid().ToString();
                string tempPassword = $"{Convert.ToBase64String(Guid.NewGuid().ToByteArray())}1%";
                //check for password preferences
                if(requestBody.useDefaultPassword != null && requestBody.useDefaultPassword)
                {
                    tempPassword = defaultPassword;
                }
                //set guid to uid if not empty
                if (!string.IsNullOrEmpty(guid))
                {
                    uid = guid;
                }

                //set attributes for new user that is being created
                List<AttributeType> userAttributes = new List<AttributeType>()
                {
                     new AttributeType() { Name = "phone_number", Value = (string)requestBody.phoneNumber},
                     new AttributeType() { Name = "phone_number_verified", Value = "true" },
                     new AttributeType() { Name = "custom:uid", Value = uid }
                };
                //now check if email is provided
                if (requestBody.includeEmailAttribute != null && requestBody.includeEmailAttribute)
                {
                    userAttributes.Add(new AttributeType() { Name = "email", Value = requestBody.email });
                    userAttributes.Add(new AttributeType() { Name = "email_verified", Value = "true" });
                }

                // create defaults
                AdminCreateUserRequest createUserRequest = new AdminCreateUserRequest()
                {
                    MessageAction = MessageActionType.SUPPRESS,
                    TemporaryPassword = "1q2w3e4R%T",
                    UserAttributes = userAttributes,
                    Username = username,
                    UserPoolId = cognitoDetails.CognitoUserPoolId,

                };

                cognitoClient = new AmazonCognitoIdentityProviderClient(Amazon.RegionEndpoint.GetBySystemName(cognitoDetails.CognitoUserPoolId.Split("_")[0]));
                var createUserResponse = cognitoClient.AdminCreateUserAsync(createUserRequest).Result;

                if (createUserResponse.HttpStatusCode != HttpStatusCode.OK)
                {
                    return (false, 
                        new ErrorResponseStatus() 
                        { 
                            statusCode = (int)createUserResponse.HttpStatusCode, 
                            message = "Something went wrong when creating user. Please try again later." 
                        });
                }

                AdminSetUserPasswordRequest setUserPasswordRequest = new AdminSetUserPasswordRequest()
                {
                    Permanent = true,
                    Username = username,
                    Password = tempPassword,
                    UserPoolId = cognitoDetails.CognitoUserPoolId
                };

                AdminSetUserPasswordResponse userPasswordResponse = cognitoClient.AdminSetUserPasswordAsync(setUserPasswordRequest).Result;
                if (userPasswordResponse.HttpStatusCode != HttpStatusCode.OK)
                {
                    return (false, new ErrorResponseStatus() { statusCode = (int)userPasswordResponse.HttpStatusCode, message = "Something went wrong when creating user. Please try again later." });
                }

                return (true, null);
            }
            catch (Exception ex)
            {
                context.Logger.LogLine($"ERROR:CreateUser:{ex.Message} - {ex.StackTrace}");
                if (ex.InnerException is UsernameExistsException exception)
                {
                    return (false, new ErrorResponseStatus() { statusCode = (int)exception.StatusCode, message = "User already exists. Please login to continue." });
                }

                return (false, new ErrorResponseStatus() { statusCode = (int)HttpStatusCode.InternalServerError, message = "Something went wrong. Please try again later." });
            }

        }


        private static (bool isSuccess, AuthFlowResponse authFlowResponse, ErrorResponseStatus status) InitiateCognitoAuth(dynamic requestBody, ILambdaContext context)
        {
            try
            {
                // find the cognito user from pool
                CognitoUser cognitoUser = new CognitoUser((string)requestBody.phoneNumber, cognitoDetails.CognitoClientId, cognitoUserPool, cognitoClient, cognitoDetails.CognitoClientSecret);
                // init the authentication request
                InitiateCustomAuthRequest initiateCustomAuthRequest = new InitiateCustomAuthRequest()
                {
                    AuthParameters = new Dictionary<string, string>() { { "USERNAME", (string)requestBody.phoneNumber }, { "SECRET_HASH", CalculateSecretHash((string)requestBody.phoneNumber) } },
                    ClientMetadata = new Dictionary<string, string>() { }
                };

                //redirect the response
                AuthFlowResponse authFlowResponse = cognitoUser.StartWithCustomAuthAsync(initiateCustomAuthRequest).Result;
                return (true, authFlowResponse, null);

            }
            catch (Exception ex)
            {
                context.Logger.LogLine($"EXCEPTION: {ex.Message} - {ex.StackTrace}");
                return (false, null, new ErrorResponseStatus() { statusCode = (int)HttpStatusCode.InternalServerError, message = "Something went wrong. Please try again later." });
            }
        }

        //create the user
        public APIGatewayProxyResponse CreateUser(APIGatewayProxyRequest request, ILambdaContext context)
        {
            
            APIGatewayProxyResponse response = null;
            try
            {
                dynamic requestBody = JsonConvert.DeserializeObject(request.Body);
                //profile creation status
                (bool isSuccess, ErrorResponseStatus status) createUserStatus = CreateCognitoUserProfile(requestBody, context);

                if (createUserStatus.isSuccess == false)
                {
                    return response = APIResponse(createUserStatus.status.statusCode, new { createUserStatus.status.message });
                }

                // authorization status
                (bool isSuccess, AuthFlowResponse authFlowResponse, ErrorResponseStatus status) initiateAuthStatus = InitiateCognitoAuth(requestBody, context);

                if (initiateAuthStatus.isSuccess == false)
                {
                    return response = APIResponse(initiateAuthStatus.status.statusCode, new { initiateAuthStatus.status.message });
                }
                // verify the otp from email
                return response = APIResponse((int)HttpStatusCode.OK, new { sessionId = initiateAuthStatus.authFlowResponse.SessionID, message = "User successfully created. Please verify OTP to continue." });

            }
            catch (Exception ex)
            {
                context.Logger.LogLine($"EXCEPTION: {ex.Message} - {ex.StackTrace}");

                return response = APIResponse((int)HttpStatusCode.InternalServerError, internalServerErrorMessage);
            }
           

        }

        // verification of user that has created the account
        public APIGatewayProxyResponse VerifyConfirmationCode(APIGatewayProxyRequest request, ILambdaContext context)
        {
           
            APIGatewayProxyResponse response = null;
            try
            {
                dynamic requestBody = JsonConvert.DeserializeObject(request.Body);
                string username = ((string)requestBody.phoneNumber).Replace("+", string.Empty);
                ConfirmSignUpRequest confirmSignUpRequest = new ConfirmSignUpRequest()
                {
                    ClientId = cognitoDetails.CognitoClientId,
                    SecretHash = CalculateSecretHash(username),
                    ConfirmationCode = requestBody.confirmationCode,
                    Username = username
                };

                cognitoClient = new AmazonCognitoIdentityProviderClient(Amazon.RegionEndpoint.GetBySystemName(cognitoDetails.CognitoUserPoolId.Split("_")[0]));
                ConfirmSignUpResponse confirmSignUpResponse = cognitoClient.ConfirmSignUpAsync(confirmSignUpRequest).Result;

                context.Logger.LogLine(JsonConvert.SerializeObject(confirmSignUpResponse));
                return response = APIResponse((int)HttpStatusCode.OK, new { message = "Confirmation code successfully verified." });
            }
            catch (Exception ex)
            {
                context.Logger.LogLine($"EXCEPTION: {ex.Message} - {ex.StackTrace}");
                return response = APIResponse((int)HttpStatusCode.InternalServerError, internalServerErrorMessage);
            }

        }

        public APIGatewayProxyResponse VerifyOTP(APIGatewayProxyRequest request, ILambdaContext context)
        {
           
            APIGatewayProxyResponse response = null;
            try
            {
                dynamic requestBody = JsonConvert.DeserializeObject(request.Body);

                RespondToCustomChallengeRequest respondToCustomChallengeRequest = new RespondToCustomChallengeRequest()
                {
                    SessionID = (string)requestBody.sessionId,
                    ChallengeParameters = new Dictionary<string, string>() { { "ANSWER", (string)requestBody.code }, { "USERNAME", (string)requestBody.phoneNumber }, { "SECRET_HASH", CalculateSecretHash((string)requestBody.phoneNumber) } },

                };

                CognitoUser cognitoUser = new CognitoUser((string)requestBody.phoneNumber, cognitoDetails.CognitoClientId, cognitoUserPool, cognitoClient, cognitoDetails.CognitoClientSecret);
                AuthFlowResponse authFlowResponse = cognitoUser.RespondToCustomAuthAsync(respondToCustomChallengeRequest).Result;



                context.Logger.LogLine(JsonConvert.SerializeObject(authFlowResponse));

                string loginSessionId = Guid.NewGuid().ToString();
                return response = APIResponse((int)HttpStatusCode.OK, new { authToken = authFlowResponse.AuthenticationResult.IdToken, accessToken = authFlowResponse.AuthenticationResult.AccessToken, refreshAuthToken = authFlowResponse.AuthenticationResult.RefreshToken, loginSessionId });

            }
            catch (Exception ex)
            {
                context.Logger.LogLine($"EXCEPTION: {ex.Message} - {ex.StackTrace}");
                if (ex.InnerException is NotAuthorizedException)
                {
                    return response = APIResponse((int)HttpStatusCode.Unauthorized, new { message = "Invalid OTP. Please try again." });
                }
                return response = APIResponse((int)HttpStatusCode.InternalServerError, internalServerErrorMessage);
            }
        }

        public APIGatewayProxyResponse VerifyEmailOTP(APIGatewayProxyRequest request, ILambdaContext context)
        {
           
            APIGatewayProxyResponse response = null;
            try
            {

                dynamic requestBody = JsonConvert.DeserializeObject(request.Body);
                string accessToken = requestBody.accessToken;

                VerifyUserAttributeRequest verifyUserAttributeRequest = new VerifyUserAttributeRequest()
                {
                    AccessToken = accessToken,
                    AttributeName = "email",
                    Code = (string)requestBody.code
                };

                VerifyUserAttributeResponse verifyUserAttributeResponse = cognitoClient.VerifyUserAttributeAsync(verifyUserAttributeRequest).Result;

                if (verifyUserAttributeResponse.HttpStatusCode != HttpStatusCode.OK)
                {
                    return response = APIResponse((int)verifyUserAttributeResponse.HttpStatusCode, new { message = "Something went wrong. Please try again later" });
                }

                string cUserId =GetUserGUID(request, context);

                Communication.DAL.ComDAL.UserDataDataRecord userData = Communication.DAL.ComDAL.UserDataDataRecord.QueryUserProfile(cUserId);
                userData.IsEmailVerified = true;
                userData.Save();
                return response = APIResponse((int)HttpStatusCode.OK, new { message = "Email address successfully verified." });

            }
            catch (Exception ex)
            {
                context.Logger.LogLine($"EXCEPTION: {ex.Message} - {ex.StackTrace}");
                if (ex.InnerException is NotAuthorizedException)
                {
                    return response = APIResponse((int)HttpStatusCode.Unauthorized, new { message = "Invalid OTP. Please try again." });
                }
                return response = APIResponse((int)HttpStatusCode.InternalServerError, internalServerErrorMessage);
            }
        }

        public static string GetUserGUID(APIGatewayProxyRequest request, ILambdaContext context)
        {
            string userGuid = string.Empty;
            bool? valueExists = request?.RequestContext?.Authorizer?.Claims?.TryGetValue("custom:uid", out userGuid);

            if (valueExists.HasValue == false)
            {
                return string.Empty;
            }

            if (valueExists.Value == false)
            {
                request.RequestContext.Authorizer.Claims.TryGetValue("sub", out userGuid);
            }

            return userGuid;
        }

        public APIGatewayProxyResponse Login(APIGatewayProxyRequest request, ILambdaContext context)
        {
           
            APIGatewayProxyResponse response = null;
            try
            {
                dynamic requestBody = JsonConvert.DeserializeObject(request.Body);

                (bool isSuccess, AuthFlowResponse authFlowResponse, ErrorResponseStatus status) startSrpStatus = StartCognitoSrpAuth(requestBody, context);

                if (startSrpStatus.isSuccess == false)
                {
                    return response = APIResponse(startSrpStatus.status.statusCode, new { startSrpStatus.status.message });
                }

                string loginSessionId = Guid.NewGuid().ToString();
                return response = APIResponse((int)HttpStatusCode.OK, new { authToken = startSrpStatus.authFlowResponse.AuthenticationResult.IdToken, accessToken = startSrpStatus.authFlowResponse.AuthenticationResult.AccessToken, refreshAuthToken = startSrpStatus.authFlowResponse.AuthenticationResult.RefreshToken, loginSessionId });
            }
            catch (Exception ex)
            {
                context.Logger.LogLine($"EXCEPTION: {ex.Message} - {ex.StackTrace}");
                return response = APIResponse((int)HttpStatusCode.InternalServerError, internalServerErrorMessage);
            }
          
        }

        // login with phone number functionality
        public APIGatewayProxyResponse LoginWithPhoneNumber(APIGatewayProxyRequest request, ILambdaContext context)
        {
           
            APIGatewayProxyResponse response = null;
            try
            {
                dynamic requestBody = JsonConvert.DeserializeObject(request.Body);

                (bool isSuccess, AdminGetUserResponse adminGetUserResponse, ErrorResponseStatus status) adminGetUserStatus = GetCognitoUser(((string)requestBody.phoneNumber).Replace("+", string.Empty), context);

                if (adminGetUserStatus.isSuccess == false)
                {
                    return response = APIResponse(adminGetUserStatus.status.statusCode, new { adminGetUserStatus.status.message });
                }

                (bool isSuccess, AuthFlowResponse authFlowResponse, ErrorResponseStatus status) initiateAuthStatus = InitiateCognitoAuth(requestBody, context);

                if (initiateAuthStatus.isSuccess == false)
                {
                    return response = APIResponse(initiateAuthStatus.status.statusCode, new { initiateAuthStatus.status.message });
                }

                return response = APIResponse((int)HttpStatusCode.OK, new { sessionId = initiateAuthStatus.authFlowResponse.SessionID, message = "Please verify OTP." });

            }
            catch (Exception ex)
            {
                context.Logger.LogLine($"EXCEPTION: {ex.Message} - {ex.StackTrace}");
                if (ex.InnerException is NotAuthorizedException)
                {
                    return response = APIResponse((int)HttpStatusCode.Unauthorized, new { message = "User not found." });
                }
                return response = APIResponse((int)HttpStatusCode.InternalServerError, internalServerErrorMessage);
            }
            
        }

        // fetch cognito user for logging in using phone number
        private static (bool isSuccess, AdminGetUserResponse adminGetUserResponse, ErrorResponseStatus status) GetCognitoUser(string username, ILambdaContext context)
        {
            try
            {
                AdminGetUserRequest adminGetUserRequest = new AdminGetUserRequest
                {
                    Username = username,
                    UserPoolId = cognitoDetails.CognitoUserPoolId
                };
                AdminGetUserResponse adminGetUserResponse = cognitoClient.AdminGetUserAsync(adminGetUserRequest).Result;
                return (true, adminGetUserResponse, null);
            }
            catch (Exception ex)
            {
                if (ex.InnerException is UserNotFoundException)
                {
                    return (false, null, new ErrorResponseStatus() { statusCode = (int)HttpStatusCode.BadRequest, message = "User not found. Please create account first." });
                }
                context.Logger.LogLine($"EXCEPTION: {ex.Message} - {ex.StackTrace}");
                return (false, null, new ErrorResponseStatus() { statusCode = (int)HttpStatusCode.InternalServerError, message = "Something went wrong. Please try again later." });
            }
        }


        private static (bool isSuccess, AuthFlowResponse authFlowResponse, ErrorResponseStatus status) StartCognitoSrpAuth(dynamic requestBody, ILambdaContext context, bool useDefaultPassword = false)
        {
            try
            {
                CognitoUser cognitoUser = new CognitoUser((string)requestBody.email, cognitoDetails.CognitoClientId, cognitoUserPool, cognitoClient, cognitoDetails.CognitoClientSecret);
                InitiateSrpAuthRequest initiateSrpAuthRequest = new InitiateSrpAuthRequest()
                {
                    Password = useDefaultPassword ? defaultPassword : (string)requestBody.password,
                };

                AuthFlowResponse authFlowResponse = cognitoUser.StartWithSrpAuthAsync(initiateSrpAuthRequest).Result;
                return (true, authFlowResponse, null);

            }
            catch (Exception ex)
            {
                if (ex.InnerException is UserNotFoundException)
                {
                    return (false, null, new ErrorResponseStatus() { statusCode = (int)HttpStatusCode.BadRequest, message = "User not found." });
                }
                if (ex.InnerException is UnauthorizedAccessException)
                {
                    return (false, null, new ErrorResponseStatus() { statusCode = (int)HttpStatusCode.BadRequest, message = "Invalid credentials." });
                }
                context.Logger.LogLine($"EXCEPTION: {ex.Message} - {ex.StackTrace}");
                return (false, null, new ErrorResponseStatus() { statusCode = (int)HttpStatusCode.InternalServerError, message = "Something went wrong. Please try again later." });
            }
        }

    }
}
