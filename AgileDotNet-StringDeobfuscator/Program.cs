using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace AgileDotNet_StringDeobfuscator
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("----AgileDotNet (aka CliSecure) String Decryptor----\n\n");

            bool hasSucceeded = false;
            while (!hasSucceeded)
            {
                Console.Write("Exe Path: ");
                string path = Console.ReadLine();

                // Some cleaning
                path = path.Replace("\"", "");

                try
                {
                    if (string.IsNullOrEmpty(path) && !Path.GetExtension(path).ToLower().Equals(".exe"))
                    {
                        throw new Exception("Enter a valid .exe path.");
                    }

                    // Load the assembly
                    var assemblyDef = AssemblyDef.Load(path);
                    var unsafeAssembly = Assembly.UnsafeLoadFrom(path);

                    // Find the location where key is located
                    TypeDef typeDef = null;
                    assemblyDef.Modules.ToList().ForEach(x => typeDef = x.GetTypes().Where(y => y.Name.Equals("<AgileDotNetRT>")).FirstOrDefault());

                    if (typeDef is null)
                    {
                        throw new Exception("This does not appear to be an Agile.NET assembly.");
                    }

                    // Get Field where key is located
                    var fieldDef = typeDef.Fields.ToList().Where(x => x.Name.Equals("pRM=")).FirstOrDefault();

                    if (fieldDef is null)
                    {
                        throw new Exception("Could not find byte[] pRM= key.");
                    }

                    // Store the key. If cannot obtain initial value, get from unsafe assembly (this is 99% of all cases as array is declared and assigned separately)
                    byte[] key = fieldDef.InitialValue;

                    if (key is null)
                    {
                        var info = unsafeAssembly.ManifestModule.ResolveField(fieldDef.MDToken.ToInt32());

                        key = info.GetValue(null) as byte[];
                    }

                    int decryptCount = 0;

                    assemblyDef.Modules.ToList().ForEach(x =>
                    {
                        x.GetTypes().ToList().ForEach(y =>
                        {
                            y.Methods.ToList().ForEach(method =>
                            {
                                if (method.HasBody && method.Body.HasInstructions)
                                {
                                    for (int i = 0; i < method.Body.Instructions.Count; i++)
                                    {
                                        /*
                                         * String signature is;
                                         * i : ldstr [cryptic_string]
                                         * i + 1 : call string '<AgileDotNetRt>'::'oRM='(string)
                                         */

                                        if (method.Body.Instructions[i].OpCode == OpCodes.Ldstr &&
                                            method.Body.Instructions[i + 1].OpCode == OpCodes.Call &&
                                            method.Body.Instructions[i + 1].Operand.ToString().Contains("oRM="))
                                        {

                                            // Store the 'encrypted' operand
                                            string operand = method.Body.Instructions[i].Operand.ToString();

                                            string decrypted = StringDecrypt(operand, key);

                                            // Replace with decrypted equivalent
                                            method.Body.Instructions[i].Operand = decrypted;

                                            // Remove the method call
                                            method.Body.Instructions[i + 1].OpCode = OpCodes.Nop;

                                            decryptCount++;

                                            // Compensate for call when a string is found
                                            i++;
                                        }
                                    }
                                }
                            });
                        });
                    });                    

                    // Write the new PE with deobfuscated strings
                    ModuleWriterOptions options = new ModuleWriterOptions(assemblyDef.ManifestModule);

                    options.MetadataOptions.Flags = options.MetadataOptions.Flags | MetadataFlags.PreserveAll;

                    // For Agile.NET and KoiVM virtualization - thanks to @ribthegreat99OrN0P
                    options.MetadataOptions.PreserveHeapOrder(assemblyDef.ManifestModule, true);

                    // Save the new PE
                    string newFile = $"{Path.GetFileNameWithoutExtension(path)}-cleanstrings.exe";
                    assemblyDef.Write($@"{Path.GetDirectoryName(path)}\{newFile}", options);

                    Console.WriteLine($"Done...saved as {newFile}\nDecrypted: {decryptCount}\nPress any key to exit...");

                    Console.ReadKey();

                    hasSucceeded = true;
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Something went wrong...\nMessage: {e.Message}\n\n{e.StackTrace}");
                }
            }
        }

        static string StringDecrypt(string operand, byte[] key)
        {
            try
            {
                StringBuilder sb = new StringBuilder();

                // Decrypt function used by obfuscator
                for (int i = 0; i < operand.Length; i++)
                {
                    sb.Append(Convert.ToChar(operand[i] ^ (char)key[i % key.Length]));
                }

                return sb.ToString();
            }
            catch
            {
                throw;
            }
        }
    }
}
