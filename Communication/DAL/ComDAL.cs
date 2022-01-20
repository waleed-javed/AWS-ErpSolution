using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DataModel;
using Amazon.Lambda.Core;
using System;
using System.Collections.Generic;
using System.Text;

namespace Communication.DAL
{

    public partial class ComDAL
    {
        private static readonly AmazonDynamoDBConfig configDbClient = new AmazonDynamoDBConfig { MaxErrorRetry = 3, Timeout = TimeSpan.FromSeconds(7) };
        private static readonly AmazonDynamoDBClient awsDynamoDbClient = new AmazonDynamoDBClient(configDbClient);
        private static readonly DynamoDBContextConfig dynamoDBContextConfig = new DynamoDBContextConfig { ConsistentRead = true, IgnoreNullValues = true, SkipVersionCheck = true };

        public ComDAL()
        {

        }

        //Each class is has its own attributes and methods
        [DynamoDBTable("CacheData")]
        public class CacheDataRecord
        {

            [DynamoDBHashKey]
            public string Key { get; set; } //Name of resource
            [DynamoDBProperty]
            public string Value { get; set; } // values stored
            [DynamoDBProperty]
            public DateTime CreatedDate { get; set; }
            [DynamoDBProperty]
            public DateTime LastModifiedDate { get; set; }


            public CacheDataRecord() { }


            // query to minimize init time of lambda (for cold start)
            public static CacheDataRecord GetItem(string key)
            {
                try
                {
                    using DynamoDBContext dbContext = new DynamoDBContext(awsDynamoDbClient, dynamoDBContextConfig);
                    var cacheData = dbContext.LoadAsync<CacheDataRecord>(key).Result;
                    return cacheData;
                }
                catch (Exception ex)
                {
                    LambdaLogger.Log($"ERROR getting key ({key}): {ex.Message}");
                }

                return new CacheDataRecord();
            }

            public bool Save()
            {
                try
                {
                    using DynamoDBContext dbContext = new DynamoDBContext(awsDynamoDbClient, dynamoDBContextConfig);
                    dbContext.SaveAsync(this).Wait();
                    return true;

                }
                catch (Exception ex)
                {
                    throw ex;
                }

            }
        }


        [DynamoDBTable("UserData")]
        public partial class UserDataDataRecord
        {
            [DynamoDBHashKey]
            public string PK { get; set; } //uid
            [DynamoDBRangeKey]
            public string SK { get; set; } //USERPROFILE
            public string FirstName { get; set; } //sent in request packet
            [DynamoDBProperty]
            public string LastName { get; set; } // sent in request packet
            [DynamoDBProperty]
            public string Email { get; set; } // recorded when created
            [DynamoDBProperty]
            public bool? IsEmailVerified { get; set; } // recorded when created in authorizer
            [DynamoDBProperty]
            public string PhoneNumber { get; set; } // recorded when created
            [DynamoDBProperty]
            public bool? IsPhoneNumberVerified { get; set; }
            [DynamoDBProperty]
            public DateTime CreatedDate { get; set; } //set when created
            [DynamoDBProperty]
            public List<string> Roles { get; set; } // can add multiple roles
            [DynamoDBProperty]
            public bool? IsAuthorized { get; set; } // should be an admin 
            [DynamoDBProperty]
            public DateTime LastModifiedDate { get; set; } // last modification record
            
            // methods
            public UserDataDataRecord()
            {
                    
            }
            public UserDataDataRecord(string propValue, string userGuid)
            {
                PK = propValue;
                SK = userGuid;
                CreatedDate = DateTime.UtcNow;
            }

            public static void setRoles( UserDataDataRecord record,string role)
            {
                //setting roles  
                record.Roles.Add(role);
                record.Save();
                
            }
            public static void removeRoles(UserDataDataRecord record, string role)
            {
                record.Roles.Remove(role);
                record.Save();
            }
            public static UserDataDataRecord QueryUserProfile(string userGuid)
            {
                try
                {
                    using DynamoDBContext dbContext = new DynamoDBContext(awsDynamoDbClient, dynamoDBContextConfig);
                    UserDataDataRecord uddr = dbContext.LoadAsync<UserDataDataRecord>(userGuid, "USERPROFILE").Result;
                    return uddr ?? new UserDataDataRecord() { PK = userGuid, SK = "USERPROFILE", CreatedDate = DateTime.UtcNow };
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }
            public static bool DeleteUserByGuid(string userguid)
            {

                try
                {
                    using DynamoDBContext dbContext = new DynamoDBContext(awsDynamoDbClient, dynamoDBContextConfig);
                    UserDataDataRecord uddr = dbContext.LoadAsync<UserDataDataRecord>(userguid, "USERPROFILE").Result;
                    if(uddr != null)
                    {
                        uddr.Delete();
                        return true;
                    }
                    return false;

                }
                catch(Exception )
                {
                    throw;
                }
            }

            public bool Save()
            {
                try
                {
                    using DynamoDBContext dbContext = new DynamoDBContext(awsDynamoDbClient, dynamoDBContextConfig);
                    LastModifiedDate = DateTime.UtcNow;
                    dbContext.SaveAsync(this).Wait();
                    return true;

                }
                catch (Exception ex)
                {
                    throw ex;
                }

            }

            public bool Delete()
            {
                try
                {
                    using DynamoDBContext dbContext = new DynamoDBContext(awsDynamoDbClient, dynamoDBContextConfig);
                    dbContext.DeleteAsync(this).Wait();
                    return true;
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }

        }

    }

}

