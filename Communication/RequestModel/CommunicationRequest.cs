using System;
using System.Collections.Generic;
using System.Text;

namespace Communication.RequetModel
{
    public class CommunicationRequest
    {


        public class UserProfileRequest
        {
            public List<UserProfileRequestItem> UserProfileFields { get; set; }
            }

        public class UserProfileRequestItem
        {
            public string Value { get; set; }
            public string Name { get; set; }
        }

    }
}
