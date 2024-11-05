using Microsoft.Identity.Client;
using Microsoft.InformationProtection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MIPSDKLiveDemo
{
    public class AuthDelegateImplementation : IAuthDelegate
    {
        private ApplicationInfo _appInfo;
        // Microsoft Authentication Library IPublicClientApplication
        private IPublicClientApplication _app;
        public AuthDelegateImplementation(ApplicationInfo appInfo)
        {
            _appInfo = appInfo;
        }
        public string AcquireToken(Identity identity, string authority, string resource, string claims)
        {
            string[] scopes = new string[] { resource[resource.Length - 1].Equals('/') ? $"{resource}.default" : $"{resource}/.default" };
            return AuthClass.SignInUserAndGetTokenUsingMSAL(scopes).Result;
        }

    }

}
