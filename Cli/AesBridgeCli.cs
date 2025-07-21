using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Text;
using System.IO;
using AesBridge;


var rootCommand = new RootCommand("AES Encryption/Decryption CLI for AesBridge-DotNet.");

var actionArgument = new Argument<string>(
    name: "action",
    description: "Action to perform: 'encrypt' or 'decrypt'."
);
actionArgument.FromAmong("encrypt", "decrypt");
rootCommand.AddArgument(actionArgument);

var modeOption = new Option<string>(
    name: "--mode",
    description: "Encryption mode."
);
modeOption.IsRequired = true;
modeOption.FromAmong("cbc", "gcm", "legacy");
rootCommand.AddOption(modeOption);

var dataOption = new Option<string>(
    name: "--data",
    description: "Data to encrypt (UTF-8 string) or decrypt (base64 string)."
);
dataOption.IsRequired = true;
rootCommand.AddOption(dataOption);

var passphraseOption = new Option<string>(
    name: "--passphrase",
    description: "Passphrase for key derivation."
);
passphraseOption.IsRequired = true;
rootCommand.AddOption(passphraseOption);

var b64Option = new Option<bool>(
    name: "--b64",
    description: "Accept base64 encoded input and returns base64 encoded output."
);
rootCommand.AddOption(b64Option);


rootCommand.SetHandler(async (InvocationContext ctx) =>
{
    string action = ctx.ParseResult.GetValueForArgument(actionArgument);
    string mode = ctx.ParseResult.GetValueForOption(modeOption)!;
    string dataString = ctx.ParseResult.GetValueForOption(dataOption)!;
    string passphrase = ctx.ParseResult.GetValueForOption(passphraseOption)!;
    bool b64 = ctx.ParseResult.GetValueForOption(b64Option);

    try
    {
        byte[] data;

        if (action == "encrypt")
        {
            if (b64)
            {
                data = Convert.FromBase64String(dataString);
            }
            else
            {
                data = Encoding.UTF8.GetBytes(dataString);
            }

            string result;
            switch (mode)
            {
                case "cbc":
                    result = AesBridge.Cbc.Encrypt(data, passphrase);
                    break;
                case "gcm":
                    result = AesBridge.Gcm.Encrypt(data, passphrase);
                    break;
                case "legacy":
                    result = AesBridge.Legacy.Encrypt(data, passphrase);
                    break;
                default:
                    throw new ArgumentException($"Unsupported encryption mode: {mode}");
            }
            Console.WriteLine(result);
        }
        else  // action == "decrypt"
        {
            data = Encoding.UTF8.GetBytes(dataString);
            byte[] decryptedBytes;

            switch (mode)
            {
                case "cbc":
                    decryptedBytes = AesBridge.Cbc.Decrypt(data, passphrase);
                    break;
                case "gcm":
                    decryptedBytes = AesBridge.Gcm.Decrypt(data, passphrase);
                    break;
                case "legacy":
                    decryptedBytes = AesBridge.Legacy.DecryptToBytes(data, passphrase);
                    break;
                default:
                    throw new ArgumentException($"Unsupported decryption mode: {mode}");
            }

            if (b64)
            {
                Console.WriteLine(Convert.ToBase64String(decryptedBytes));
            }
            else
            {
                Console.WriteLine(Encoding.UTF8.GetString(decryptedBytes));
            }
        }

        ctx.ExitCode = 0;
    }
    catch (FormatException e)
    {
        Console.Error.WriteLine($"Error: Invalid base64 string provided when --b64 was used for encryption. {e.Message}");
        ctx.ExitCode = 1;
    }
    catch (Exception e)
    {
        Console.Error.WriteLine($"Error: {e.Message}");
        ctx.ExitCode = 1;
    }
});

return await rootCommand.InvokeAsync(args);
