using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace NexAuthDesktop
{
    public static class MauiProgram
    {
        public static MauiApp CreateMauiApp()
        {
            var builder = MauiApp.CreateBuilder();
            builder
                .UseMauiApp<App>()
                .ConfigureFonts(fonts =>
                {
                    fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                    fonts.AddFont("Inter-VariableFont_opsz,wght.ttf", "Inter");
                    fonts.AddFont("JetBrainsMono-VariableFont_wght.ttf", "JetBrains Mono");
                });

            builder.Services.AddScoped<NexAuth.WalletSession>();
            builder.Services.AddMauiBlazorWebView();

#if DEBUG
    		builder.Services.AddBlazorWebViewDeveloperTools();
    		builder.Logging.AddDebug();

            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            {
                Debug.WriteLine($"UNHANDLED EXCEPTION: {e.ExceptionObject}");
            };

            TaskScheduler.UnobservedTaskException += (_, e) =>
            {
                Debug.WriteLine($"UNOBSERVED EXCEPTION: {e.Exception}");
            };
#endif

            return builder.Build();
        }
    }
}
