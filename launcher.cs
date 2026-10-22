using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("SSL Manager")]
[assembly: AssemblyDescription("Gerenciador de KeyStores (.JKS / .PFX) e Certificados Digitais")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("Open Source")]
[assembly: AssemblyProduct("SSL Manager")]
[assembly: AssemblyCopyright("MIT License")]
[assembly: AssemblyTrademark("")]
[assembly: ComVisible(false)]
[assembly: AssemblyVersion("2.7.0.0")]
[assembly: AssemblyFileVersion("2.7.0.0")]

class SplashForm : Form
{
    private const string CACHE_VERSION = "v2.7-os";

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    private readonly string[] _args;
    private string _statusText = "Iniciando SSL Manager...";
    private int _animPos = 0;
    private readonly System.Windows.Forms.Timer _animTimer;
    private IntPtr _splashHandle = IntPtr.Zero;

    public SplashForm(string[] args)
    {
        _args = args;
        this.FormBorderStyle = FormBorderStyle.None;
        this.StartPosition = FormStartPosition.CenterScreen;
        this.Size = new Size(430, 195);
        this.BackColor = Color.FromArgb(11, 17, 32);
        this.DoubleBuffered = true;
        this.ShowInTaskbar = false;
        this.Text = "Carregando...";
        this.TopMost = true;

        _animTimer = new System.Windows.Forms.Timer();
        _animTimer.Interval = 20;
        _animTimer.Tick += (s, e) =>
        {
            _animPos = (_animPos + 12) % (this.Width + 140);
            this.Invalidate(new Rectangle(0, this.Height - 45, this.Width, 45));
        };
    }

    public void StartLaunchSequence()
    {
        _splashHandle = this.Handle;
        _animTimer.Start();
        Thread worker = new Thread(LaunchBackend);
        worker.IsBackground = true;
        worker.Start();
    }

    private void UpdateStatus(string text)
    {
        if (this.IsDisposed) return;
        try
        {
            this.BeginInvoke((MethodInvoker)delegate
            {
                _statusText = text;
                this.Invalidate();
            });
        }
        catch { }
    }

    private IntPtr FindMainAppWindow()
    {
        IntPtr foundHwnd = IntPtr.Zero;
        EnumWindows((hWnd, lParam) =>
        {
            if (hWnd != _splashHandle && IsWindowVisible(hWnd))
            {
                StringBuilder sb = new StringBuilder(256);
                GetWindowText(hWnd, sb, 256);
                string title = sb.ToString();
                if (title.StartsWith("SSL Manager", StringComparison.OrdinalIgnoreCase))
                {
                    foundHwnd = hWnd;
                    return false;
                }
            }
            return true;
        }, IntPtr.Zero);
        return foundHwnd;
    }

    private void LaunchBackend()
    {
        try
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string localRuntimeExe = Path.Combine(baseDir, "SSLManager_runtime", "SSLManager.exe");

            if (!File.Exists(localRuntimeExe))
            {
                string distRuntimeExe = Path.Combine(baseDir, "dist", "SSLManager_runtime", "SSLManager.exe");
                if (File.Exists(distRuntimeExe))
                {
                    localRuntimeExe = distRuntimeExe;
                }
            }

            if (!File.Exists(localRuntimeExe))
            {
                string appDataDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "SSLManager",
                    CACHE_VERSION
                );
                localRuntimeExe = Path.Combine(appDataDir, "SSLManager.exe");

                if (!File.Exists(localRuntimeExe))
                {
                    UpdateStatus("Preparando ambiente na primeira execu\u00e7\u00e3o...");
                    ExtractEmbeddedRuntime(appDataDir);
                }
            }

            UpdateStatus("Abrindo interface principal...");

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = localRuntimeExe;
            psi.WorkingDirectory = Path.GetDirectoryName(localRuntimeExe);
            if (_args != null && _args.Length > 0)
            {
                psi.Arguments = "\"" + string.Join("\" \"", _args) + "\"";
            }
            psi.UseShellExecute = false;

            Process proc = Process.Start(psi);
            if (proc != null)
            {
                Stopwatch sw = Stopwatch.StartNew();
                while (sw.ElapsedMilliseconds < 6000)
                {
                    IntPtr mainHwnd = FindMainAppWindow();
                    if (mainHwnd != IntPtr.Zero)
                    {
                        SetForegroundWindow(mainHwnd);
                        break;
                    }
                    if (proc.HasExited)
                    {
                        break;
                    }
                    Thread.Sleep(25);
                }
            }

            CloseSplashSafe();
        }
        catch (Exception ex)
        {
            CloseSplashSafe();
            MessageBox.Show(
                "Erro ao iniciar o SSL Manager:\n" + ex.Message,
                "SSL Manager",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error
            );
        }
    }

    private void CloseSplashSafe()
    {
        if (this.IsDisposed) return;
        try
        {
            this.BeginInvoke((MethodInvoker)delegate
            {
                _animTimer.Stop();
                this.Close();
            });
        }
        catch { }
    }

    private static void ExtractEmbeddedRuntime(string targetDir)
    {
        try
        {
            string parentRoot = Directory.GetParent(targetDir).FullName;
            if (Directory.Exists(parentRoot))
            {
                foreach (string oldDir in Directory.GetDirectories(parentRoot))
                {
                    try { Directory.Delete(oldDir, true); } catch { }
                }
            }
        }
        catch { }

        Directory.CreateDirectory(targetDir);

        string tempZip = Path.Combine(Path.GetTempPath(), "ssl_manager_runtime_" + Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            using (Stream resStream = asm.GetManifestResourceStream("runtime.zip"))
            {
                if (resStream == null)
                {
                    throw new Exception("Recurso interno 'runtime.zip' n\u00e3o encontrado no execut\u00e1vel.");
                }
                using (FileStream fs = new FileStream(tempZip, FileMode.Create, FileAccess.Write))
                {
                    resStream.CopyTo(fs);
                }
            }
            ZipFile.ExtractToDirectory(tempZip, targetDir);
        }
        finally
        {
            if (File.Exists(tempZip))
            {
                try { File.Delete(tempZip); } catch { }
            }
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

        using (Pen borderPen = new Pen(Color.FromArgb(30, 41, 59), 2))
        {
            g.DrawRectangle(borderPen, 1, 1, this.Width - 2, this.Height - 2);
        }

        using (LinearGradientBrush topAccent = new LinearGradientBrush(
            new Rectangle(0, 0, this.Width, 4),
            Color.FromArgb(2, 132, 199),
            Color.FromArgb(56, 189, 248),
            LinearGradientMode.Horizontal))
        {
            g.FillRectangle(topAccent, 0, 0, this.Width, 4);
        }

        using (GraphicsPath shield = new GraphicsPath())
        {
            shield.AddPolygon(new PointF[] {
                new PointF(54f, 38f),
                new PointF(74f, 46f),
                new PointF(74f, 66f),
                new PointF(54f, 84f),
                new PointF(34f, 66f),
                new PointF(34f, 46f)
            });
            using (LinearGradientBrush sb = new LinearGradientBrush(
                new Rectangle(34, 38, 40, 46),
                Color.FromArgb(2, 132, 199),
                Color.FromArgb(3, 105, 161),
                LinearGradientMode.Vertical))
            using (Pen sp = new Pen(Color.FromArgb(56, 189, 248), 1.8f))
            {
                g.FillPath(sb, shield);
                g.DrawPath(sp, shield);
            }
        }
        using (SolidBrush lockBrush = new SolidBrush(Color.FromArgb(16, 185, 129)))
        {
            g.FillRectangle(lockBrush, 46, 58, 16, 13);
        }
        using (Pen arcPen = new Pen(Color.White, 2f))
        {
            g.DrawArc(arcPen, 49, 50, 10, 12, 180, 180);
        }

        using (Font brandFont = new Font("Segoe UI", 8.5f, FontStyle.Bold))
        using (SolidBrush brandBrush = new SolidBrush(Color.FromArgb(56, 189, 248)))
        {
            g.DrawString("KEYSTORE & PKCS#12", brandFont, brandBrush, 90, 36);
        }

        using (Font titleFont = new Font("Segoe UI", 17f, FontStyle.Bold))
        using (SolidBrush titleBrush = new SolidBrush(Color.FromArgb(248, 250, 252)))
        {
            g.DrawString("SSL Manager", titleFont, titleBrush, 87, 51);
        }

        using (Font subFont = new Font("Segoe UI", 8.8f, FontStyle.Regular))
        using (SolidBrush subBrush = new SolidBrush(Color.FromArgb(148, 163, 184)))
        {
            g.DrawString("Gerenciador de Certificados Digitais (.JKS / .PFX)", subFont, subBrush, 90, 84);
        }

        using (Font statusFont = new Font("Segoe UI", 9.2f, FontStyle.Regular))
        using (SolidBrush statusBrush = new SolidBrush(Color.FromArgb(203, 213, 225)))
        {
            g.DrawString(_statusText, statusFont, statusBrush, 32, 130);
        }

        int barX = 32;
        int barY = 156;
        int barW = this.Width - 64;
        int barH = 5;

        using (SolidBrush trackBrush = new SolidBrush(Color.FromArgb(22, 32, 50)))
        {
            g.FillRectangle(trackBrush, barX, barY, barW, barH);
        }

        Region oldClip = g.Clip;
        g.SetClip(new Rectangle(barX, barY, barW, barH));
        int pillWidth = 120;
        int pillX = barX + _animPos - pillWidth;
        using (LinearGradientBrush pillBrush = new LinearGradientBrush(
            new Rectangle(pillX, barY, pillWidth, barH),
            Color.FromArgb(2, 132, 199),
            Color.FromArgb(56, 189, 248),
            LinearGradientMode.Horizontal))
        {
            g.FillRectangle(pillBrush, pillX, barY, pillWidth, barH);
        }
        g.Clip = oldClip;
    }
}

class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        SplashForm splash = new SplashForm(args);
        splash.Show();
        splash.Update();
        splash.StartLaunchSequence();
        Application.Run(splash);
    }
}
