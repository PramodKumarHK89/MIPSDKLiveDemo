using Microsoft.InformationProtection;
using Microsoft.InformationProtection.File;
using Microsoft.InformationProtection.Protection;
using MIPSDKLiveDemo;
using System.Configuration;

class Program
{
    static void Main(string[] args)
    {
        // Initialize MSAL and trigger sign-in .
        AuthClass.InitializeMSAL();
        var username = AuthClass.SignInUserAndGetAccountUsingMSAL(new string[] { "user.read" }).Result;
        Console.WriteLine(string.Format("Logged in user {0}", username.Username));
        // Initialize Wrapper for File SDK operations.

        MIP.Initialize(MipComponent.File);

        // Create ApplicationInfo, setting the clientID from Microsoft Entra App Registration as the ApplicationId.
        ApplicationInfo appInfo = new ApplicationInfo()
        {
            ApplicationId = ConfigurationManager.AppSettings.Get("ClientId"),
            ApplicationName = ConfigurationManager.AppSettings.Get("app:Name"),
            ApplicationVersion = ConfigurationManager.AppSettings.Get("app:Version")
        };

        // Instantiate the AuthDelegateImpl object, passing in AppInfo.
        AuthDelegateImplementation authDelegate = new AuthDelegateImplementation(appInfo);

        // Create MipConfiguration Object
        MipConfiguration mipConfiguration = new MipConfiguration(appInfo, "mip_data", Microsoft.InformationProtection.LogLevel.Info, false);

        // Create MipContext using Configuration
        MipContext mipContext = MIP.CreateMipContext(mipConfiguration);

        // Initialize and instantiate the File Profile.
        // Create the FileProfileSettings object.
        // Initialize file profile settings to create/use local state.
        var profileSettings = new FileProfileSettings(mipContext,
                                 CacheStorageType.InMemory,
                                 new ConsentDelegateImplementation());

        // Load the Profile async and wait for the result.
        var fileProfile = Task.Run(async () => await MIP.LoadFileProfileAsync(profileSettings)).Result;

        // Create a FileEngineSettings object, then use that to add an engine to the profile.
        // This pattern sets the engine ID to user1@tenant.com, then sets the identity used to create the engine.
        var engineSettings = new FileEngineSettings("user1@tenant.com", authDelegate, "", "en-US");
        engineSettings.Identity = new Identity("user1@tenant.com");

        var fileEngine = Task.Run(async () => await fileProfile.AddEngineAsync(engineSettings)).Result;

        // List sensitivity labels from fileEngine and display name and id
        foreach (var label in fileEngine.SensitivityLabels)
        {
            Console.WriteLine(string.Format("{0} : {1}", label.Name, label.Id));

            if (label.Children.Count != 0)
            {
                foreach (var child in label.Children)
                {
                    Console.WriteLine(string.Format("{0}{1} : {2}", "\t", child.Name, child.Id));
                }
            }
        }

        //Set paths and label ID
        //string inputFilePath = "<input-file-path>";
        //string labelId = "<label-id>";
        //string outputFilePath = "<output-file-path>";


        Console.Write("Enter a label identifier from above: ");
        var labelId = Console.ReadLine();

        // Prompt for path inputs
        Console.Write("Enter an input file path: ");
        string inputFilePath = Console.ReadLine();

        Console.Write("Enter an output file path: ");
        string outputFilePath = Console.ReadLine();

        Console.Write("Assign User-Defined permision ?(yes/no) ");
        string UsedDefined = Console.ReadLine();


        string actualOutputFilePath = outputFilePath;
        string actualFilePath = inputFilePath;

        //Create a file handler for that file
        //Note: the 2nd inputFilePath is used to provide a human-readable content identifier for admin auditing.
        var handler = Task.Run(async () => await fileEngine.CreateFileHandlerAsync(inputFilePath, actualFilePath, true)).Result;

        if (handler.Protection != null)
        {
            Console.WriteLine(string.Format("InputFile : {0} is protected.[handler.Protection != null] && Protection Type {1}", inputFilePath, handler.Protection.ProtectionDescriptor.ProtectionType.ToString()));
        }
        else
        {
            Console.WriteLine(string.Format("InputFile : {0} is NOT protected.[handler.Protection == null]", inputFilePath));
        }
        var PreLabel = handler.Label;
        if (PreLabel != null)
        {
            if (PreLabel.Label == null)
            {
                Console.WriteLine(string.Format("InputFile : {0} has NO Label. IsProtectionAppliedFromLabel {1}", inputFilePath, PreLabel.IsProtectionAppliedFromLabel));
            }
            else
            {
                Console.WriteLine(string.Format("InputFile : {0} has Label {1}. IsProtectionAppliedFromLabel {2}", inputFilePath, PreLabel.Label.Name,
                    PreLabel.IsProtectionAppliedFromLabel));
            }
        }
        else
        {
            Console.WriteLine(string.Format("InputFile : {0} has NO Label and  NO IsProtectionAppliedFromLabel", inputFilePath));
        }

        LabelingOptions labelingOptions = new LabelingOptions()
        {
            AssignmentMethod = AssignmentMethod.Privileged
        };
        List<string> users = new List<string>()
                    {
                        "pramkum@pramkumlab.onmicrosoft.com",
                        "david@pramkumlab.onmicrosoft.com"
                    };
        // Create a List<string> of the Rights the above users should have. 
        List<string> rights = new List<string>()
                    {
                        "View",
                        "Edit"
                    };
        // Create a UserRights object containing the defined users and rights.
        UserRights userRights = new UserRights(users, rights);
        // Add them to a new List<UserRights>
        List<UserRights> userRightsList = new List<UserRights>()
                    {
                        userRights
                    };

        ProtectionDescriptor protectionDescriptor = new ProtectionDescriptor(userRightsList);
        ProtectionSettings protectionSettings = new ProtectionSettings();

        if (UsedDefined.Equals("yes", StringComparison.InvariantCultureIgnoreCase))
        {
            try
            {
                handler.SetProtection(protectionDescriptor, protectionSettings);
                handler.SetLabel(fileEngine.GetLabelById(labelId), labelingOptions, new ProtectionSettings());
            }
            catch (Microsoft.InformationProtection.Exceptions.JustificationRequiredException ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Console.Write("The file already has a Label. Please provide justification to apply");
                string justification = Console.ReadLine();

                labelingOptions.IsDowngradeJustified = true;
                labelingOptions.JustificationMessage = justification;

                handler.SetLabel(fileEngine.GetLabelById(labelId), labelingOptions, new ProtectionSettings());
            }
        }
        else
        {
            try
            {// Set a label on input file	
                handler.SetLabel(fileEngine.GetLabelById(labelId), labelingOptions, new ProtectionSettings());
            }
            catch (Microsoft.InformationProtection.Exceptions.AdhocProtectionRequiredException ex)
            {
                Console.WriteLine($"The Label that you are trying to apply needs Access Control Info {ex.Message}\r\n. Please confirm by typing yes to assign user-defined permission");
                Console.ReadLine();
                try
                {
                    handler.SetProtection(protectionDescriptor, protectionSettings);
                    handler.SetLabel(fileEngine.GetLabelById(labelId), labelingOptions, new ProtectionSettings());                    
                }
                catch (Microsoft.InformationProtection.Exceptions.JustificationRequiredException ex2)
                {
                    Console.WriteLine($"Error: {ex2.Message}");
                    Console.Write("The file already has a Label. Please provide justification to apply");
                    string justification = Console.ReadLine();

                    labelingOptions.IsDowngradeJustified = true;
                    labelingOptions.JustificationMessage = justification;

                    handler.SetLabel(fileEngine.GetLabelById(labelId), labelingOptions, new ProtectionSettings());
                }
            }
            catch (Microsoft.InformationProtection.Exceptions.JustificationRequiredException ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Console.Write("The file already has a Label. Please provide justification to apply");
                string justification = Console.ReadLine();

                labelingOptions.IsDowngradeJustified = true;
                labelingOptions.JustificationMessage = justification;

                handler.SetLabel(fileEngine.GetLabelById(labelId), labelingOptions, new ProtectionSettings());
            }
        }

        // Commit changes, save as outputFilePath
        var result = Task.Run(async () => await handler.CommitAsync(outputFilePath)).Result;

        // Create a new handler to read the labeled file metadata
        var handlerModified = Task.Run(async () => await fileEngine.CreateFileHandlerAsync(outputFilePath, actualOutputFilePath, true)).Result;

        // Get the label from output file
        var contentLabel = handlerModified.Label;
        // contentLabel.Label.
        Console.WriteLine(string.Format("Label committed to output file: {0}", outputFilePath));

        if (handlerModified.Protection != null)
        {
            Console.WriteLine(string.Format("OutputFile : {0} is protected.[handlerModified.Protection != null] & ProtectionType {1}", outputFilePath,handlerModified.Protection.ProtectionDescriptor.ProtectionType.ToString()));
        }
        else
        {
            Console.WriteLine(string.Format("OutputFile : {0} is NOT protected.[handlerModified.Protection == null]", outputFilePath));
        }
        if (contentLabel != null)
        {
            if (contentLabel.Label == null)
            {
                Console.WriteLine(string.Format("OutputFile : {0} has NO Label. IsProtectionAppliedFromLabel {1}", outputFilePath, contentLabel.IsProtectionAppliedFromLabel));
            }
            else
            {
                Console.WriteLine(string.Format("OutputFile : {0} has Label {1}. IsProtectionAppliedFromLabel {2}", outputFilePath, contentLabel.Label.Name,
                    contentLabel.IsProtectionAppliedFromLabel));
            }
        }
        else
        {
            Console.WriteLine(string.Format("OutputFile : {0} has NO Label and has NO Protectio", outputFilePath));
        }
        Console.WriteLine("Press a key to continue.");
        Console.ReadKey();
        // Application Shutdown
        handler = null; // This will be used in later quick starts.
        fileEngine = null;
        fileProfile = null;
        mipContext.ShutDown();
        mipContext = null;
    }
}
