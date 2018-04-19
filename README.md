# Owin.Security.CAS.Enhanced
Add a way to log out

Add
## CasAuthenticationOptions
### Properties
* `CasSignOutHandler` 

1. Install the NuGet package

    `PM> install-package Owin.Security.CAS.Enhanced`

2.Add Code

##ExternalLoginCallback Function
Before SignInManager.SignInAsync(appUser), you should add
     appUser.ExternalIdentity = (await AuthenticationManager.GetExternalLoginInfoAsync()).ExternalIdentity;

##ApplicationUser:IdentityUser Class
Add Properties
    public ClaimsIdentity ExternalIdentity { get; set; }

#ApplicationClaimsIdentityFactory : ClaimsIdentityFactory<ApplicationUser, string>
Add Code
        public override Task<ClaimsIdentity> CreateAsync(UserManager<ApplicationUser, string> manager, ApplicationUser user, string authenticationType)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            ClaimsIdentity id = new ClaimsIdentity(authenticationType, this.UserNameClaimType, this.RoleClaimType);
            id.AddClaim(new Claim(this.UserIdClaimType, this.ConvertIdToString(user.Id), "http://www.w3.org/2001/XMLSchema#string"));
            id.AddClaim(new Claim(this.UserNameClaimType, user.UserName, "http://www.w3.org/2001/XMLSchema#string"));
            id.AddClaim(new Claim("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider", "ASP.NET Identity", "http://www.w3.org/2001/XMLSchema#string"));
            if (manager.SupportsUserClaim && user.ExternalIdentity != null)
                user.ExternalIdentity.Claims.ToList().ForEach(claim =>
                {
                    if (!id.HasClaim(p => p.Type == claim.Type))
                        id.AddClaim(claim);
                });
            return Task.FromResult(id);
        }
     

# Owin.Security.CAS
Owin.Security.CAS is an [OWIN](http://owin.org) authentication provider for [CAS](https://github.com/Jasig/cas)

## Quick Start
Too much on your plate to read through documentation?  Need to get CAS authentication added to your MVC solution now?  Here's what you need to do.

1. Install the NuGet package

    `PM> install-package Owin.Security.CAS`

2. Open **App_Start/Startup.Auth.cs**
3. Add `using Owin.Security.CAS;` to the end of the `using` statements
4. Paste the following code below the `// Uncomment the following lines to enable logging in with third party login providers` line

    ```c#
    CasAuthenticationOptions casOptions = new CasAuthenticationOptions()
    {
        CasServerUrlBase = "https://your.cas.server.com/cas"
    };
    app.UseCasAuthentication(casOptions);
    ```

5. DONE!

## Installing
Using NuGet [![NuGet Status](http://nugetstatus.com/Owin.Security.CAS.png)](http://nugetstatus.com/packages/Owin.Security.CAS)

    PM> install-package Owin.Security.CAS

Using zip file

1. [Download the zip file](https://github.com/noelbundick/Owin.Security.CAS/archive/master.zip) by clicking on the **Download Zip File** button on the project home page on GitHub
2. Extract the zipped files. An **Owin.Security.CAS-master** folder will be created.
3. In Visual Studio, right click on your solution and select **Add > Existing Project**. The **Add Existing Project** window will appear
4. Navigate to **Owin.Security.CAS > Owin.Security.CAS.csproj** and click **Open**.  The project will now be in your solution.
5. Make your project dependenent on **Owin.Security.CAS** so that any updates you download and unzip in the **Owin.Security.CAS-master** folder will cause the dll to be recompiled
  1. Selecting **Project > Project Dependencies** from the Visual Studio menu. The **Project Dependencies** window will appear.
  2. Select the **Dependencies** tab
  3. Select your project from the **Projects** dropdown
  4. Check **Owin.Security.CAS** in the **Depends on** area
  5. Click **OK**
6. Add a reference to the **Owin.Security.CAS** project so that it can be used in your code
  1. In the **References** section of your solution, right-click and select **Add Reference...**.  The **Reference Manager** window willl appear.
  2. Select **Solution > Projects**
  3. Check the box for **Owin.Security.CAS**
  4. Select **OK**
  5. You should now see **Owin.Security.CAS** under **References**

## Enabling CAS Authentication
CAS authentication is enabled by calling `app.UseCasAuthentication();` in the `ConfigureAuth()` method in **App_Start/Startup.Auth.cs**.  `UseCasAuthentication()` takes a `CasAuthenticationOptions` object that contains configuration options needed for connecting to your CAS server.  At a minmum, the `CasAuthenticationOptions` object needs to have the `CasServerUrlBase` property set to the URL to your CAS server.

See the **Examples** section for some sample imlementations

## CasAuthenticationOptions
### Properties
* `AuthenticationMode`
* `AuthenticationType` - String that appears in the button, and that is used for **dbo.AspNetUserLogins.LoginProvider** in the DB.  Default: `CAS`
* `BackchannelHttpHandler`
* `BackchannelTimeout`
* `CallbackPath`
* `Caption` - String that will replace "CAS" in the tool tip of the button. Default: `CAS`
* `CasServerUrlBase` - String containing the URL to your CAS server
* `Description`
* `NameClaimType`
* `NameIdentifierAttribute`
* `Provider`
* `SignInAsAuthenticationType`
* `StateDataFormat`
* `TicketValidator`

### Methods
* `Equals()`
* `GetHashCode()`
* `GetType()`
* `ToString()`

## Examples
### Adding Texas A&M CAS (called NetID) to an ASP.NET MVC Web Application
This example is based on the default **ASP.NET Web Application - MVC** template, using **Individual User Accounts** Authentication.

Open **App_Start/Startu.Auth.cs** and make the following modifications
* Add `using Owin.Security.CAS;`
* Add the following code below the `// Uncomment the following lines to enable logging in with third party login providers` section 
```c#
CasAuthenticationOptions casOptions = new CasAuthenticationOptions()
{
    AuthenticationType = "Net ID", // change "CAS" to "Net ID" on the button and in DB
    Caption = "Net ID", // change "CAS" to "Net ID" in tool tip
    CasServerUrlBase = "https://cas-dev.tamu.edu/cas"
};
app.UseCasAuthentication(casOptions);
```

[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/noelbundick/Owin.Security.CAS/blob/master/LICENSE.md)
[![Build Status](https://www.myget.org/BuildSource/Badge/owin-security-cas?identifier=f61417a1-8dfe-49f2-9981-b9d44c5b234e)](https://www.myget.org/)

