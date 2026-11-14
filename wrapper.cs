using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace WinPrivUp
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            Console.WriteLine("--- Windows Privilege Escalation Enumeration Wrapper ---");

            string script = FindScript();
            if (script == null)
            {
                Console.Error.WriteLine("[!] enum.ps1 was not found next to this executable or in the current directory.");
                return 2;
            }

            string shell = FindPowerShell();
            Console.WriteLine("[*] Script: " + script);
            Console.WriteLine("[*] Shell : " + shell);

            var arguments = new StringBuilder();
            arguments.Append("-NoProfile -ExecutionPolicy Bypass -File ");
            arguments.Append(Quote(script));

            foreach (string argument in args)
            {
                arguments.Append(' ');
                arguments.Append(Quote(argument));
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = shell,
                Arguments = arguments.ToString(),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = false
            };

            try
            {
                using (var process = new Process())
                {
                    process.StartInfo = startInfo;

                    // Read stdout/stderr on separate threads so a full pipe
                    // buffer cannot deadlock the parent process.
                    process.OutputDataReceived += (sender, eventArgs) =>
                    {
                        if (eventArgs.Data != null) { Console.WriteLine(eventArgs.Data); }
                    };
                    process.ErrorDataReceived += (sender, eventArgs) =>
                    {
                        if (eventArgs.Data != null) { Console.Error.WriteLine(eventArgs.Data); }
                    };

                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                    process.WaitForExit();

                    Console.WriteLine();
                    Console.WriteLine("--- Enumeration Complete (exit code {0}) ---", process.ExitCode);
                    return process.ExitCode;
                }
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("[!] Failed to start PowerShell: " + exception.Message);
                return 3;
            }
        }

        private static string FindScript()
        {
            string nextToExecutable = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "enum.ps1");
            if (File.Exists(nextToExecutable)) { return nextToExecutable; }

            string currentDirectory = Path.Combine(Directory.GetCurrentDirectory(), "enum.ps1");
            if (File.Exists(currentDirectory)) { return currentDirectory; }

            return null;
        }

        private static string FindPowerShell()
        {
            string systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string windowsPowerShell = Path.Combine(systemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            if (File.Exists(windowsPowerShell)) { return windowsPowerShell; }

            // Fall back to PATH resolution (PowerShell 7+ installs pwsh.exe).
            return "pwsh.exe";
        }

        private static string Quote(string value)
        {
            if (value == null) { return "\"\""; }
            if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) { return value; }

            var builder = new StringBuilder();
            builder.Append('"');

            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }

                if (character == '"')
                {
                    builder.Append('\\', (backslashes * 2) + 1);
                    builder.Append('"');
                }
                else
                {
                    builder.Append('\\', backslashes);
                    builder.Append(character);
                }

                backslashes = 0;
            }

            builder.Append('\\', backslashes * 2);
            builder.Append('"');
            return builder.ToString();
        }
    }
}
