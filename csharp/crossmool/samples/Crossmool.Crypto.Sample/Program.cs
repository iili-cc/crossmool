namespace Crossmool.Crypto.Sample;

/// <summary>
/// Crossmool.Crypto 国密算法库 — 快速上手指南
/// 
/// 本项目依次运行 SM2、SM3、SM4 三个示例，展示国密算法的核心用法。
/// 运行方法：
///   1. 用 Visual Studio / Rider 打开 Crossmool.Crypto.sln
///   2. 将 Crossmool.Crypto.Sample 设为启动项目
///   3. 按 F5 运行
///   或使用命令行：dotnet run --project samples/Crossmool.Crypto.Sample
/// </summary>
class Program
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        Console.WriteLine();
        Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("║     Crossmool.Crypto — 国密算法 .NET 库 快速上手        ║");
        Console.WriteLine("║     SM2 (非对称) · SM3 (哈希) · SM4 (对称-GCM)          ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
        Console.WriteLine();

        // ---------- SM2 示例 ----------
        SM2Sample.Run();

        // ---------- SM3 示例 ----------
        SM3Sample.Run();

        // ---------- SM4 示例 ----------
        SM4Sample.Run();

        Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
        Console.WriteLine("║           所有 Sample 运行完毕，祝使用愉快！            ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
        Console.WriteLine();
    }
}
