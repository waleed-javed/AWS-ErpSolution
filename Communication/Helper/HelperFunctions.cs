using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Communication.Helper
{
    public class HelperFunctions
    {
        public string ConvertToPascalCase(string jsonString)
        {
            try
            {
                return JsonConvert.SerializeObject(JsonConvert.DeserializeObject<Dictionary<string, dynamic>>(jsonString).ToDictionary(x => string.Concat(char.ToUpper(x.Key.First()).ToString(), x.Key.Substring(1)), x => x.Value));
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

    }
}
