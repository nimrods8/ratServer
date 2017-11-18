using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Reflection;
using System.Runtime.CompilerServices;

[assembly: SuppressIldasmAttribute()]
namespace RevereseTcpRat
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault( false );
            //
            // Loads Referenced Dlls when they are missing...
            AppDomain.CurrentDomain.AssemblyResolve += (sender, rgs) =>
            {
                Assembly assem = Assembly.GetExecutingAssembly();
                string[] names = assem.GetManifestResourceNames();
                AssemblyName an = assem.GetName();

                String resourceName = an.Name + "." + new AssemblyName( rgs.Name ).Name + ".dll";

                using( var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream( resourceName ) )
                {
                    Byte[] assemblyData = new Byte[stream.Length];
                    stream.Read( assemblyData, 0, assemblyData.Length );
                    return Assembly.Load( assemblyData );
                }
            };
            Application.Run( new Form1() );
        }
    }
}
