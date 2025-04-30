// Author : rxndev
// github.com/rxndev
// velog.io/@rxndev

using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using System.Linq;
using System.Diagnostics;

namespace MYBS
{
    internal static class Program
    {
        private const uint ELF_MAGIC = 0x464C457F;

        private const string SYM_INITIALIZE_BOMB = "initialize_bomb";
        private const string SYM_SEND_MSG = "send_msg";

        private static unsafe ushort R16u(void* ptr) => *(ushort*)ptr;

        private static unsafe uint R32u(void* ptr) => *(uint*)ptr;

        private static unsafe int R32i(void* ptr) => *(int*)ptr;

        private static unsafe ulong R64u(void* ptr) => *(ulong*)ptr;

        private static unsafe ushort R16u(void* ptr, nint offset) => R16u((byte*)ptr + offset);

        private static unsafe uint R32u(void* ptr, nint offset) => R32u((byte*)ptr + offset);

        private static unsafe int R32i(void* ptr, nint offset) => R32i((byte*)ptr + offset);

        private static unsafe ulong R64u(void* ptr, nint offset) => R64u((byte*)ptr + offset);

        [STAThread]
        private static void Main()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;

            Console.WriteLine("[MYBS]");
            Console.WriteLine("Make Your Bomb Safe!");
            Console.WriteLine("by rxndev (github.com/rxndev)");

            Console.ForegroundColor = ConsoleColor.Gray;

            Console.WriteLine();

            Console.WriteLine("패치할 Bomb 파일을 선택하세요.");

            string bombPath = GetOpenFileName();

            Console.WriteLine();

            if (bombPath == null)
            {
                Console.WriteLine("파일이 입력되지 않았습니다.");
                Exit();
            }

            Console.WriteLine($"입력된 Bomb : {bombPath}");
            Console.WriteLine();

            byte[] bomb = File.ReadAllBytes(bombPath);

            if (BitConverter.ToUInt32(bomb, 0) != ELF_MAGIC)
            {
                Console.WriteLine("ELF 파일이 아닙니다.");
                Exit();
            }

            Console.WriteLine("올바른 ELF 파일입니다.");
            Console.WriteLine($"* Size : {bomb.Length:N0} Bytes");
            Console.WriteLine();

            unsafe
            {
                fixed (byte* pBomb = bomb)
                {
                    uint initializeBombOffset = FindSymbol(pBomb, SYM_INITIALIZE_BOMB);
                    uint sendMsgOffset = FindSymbol(pBomb, SYM_SEND_MSG);

                    Console.WriteLine($"Function \"{SYM_INITIALIZE_BOMB}\" at 0x{initializeBombOffset:X}");
                    Console.WriteLine($"Function \"{SYM_SEND_MSG}\" at 0x{sendMsgOffset:X}");
                    Console.WriteLine();

                    if (initializeBombOffset == 0 || sendMsgOffset == 0)
                    {
                        Console.WriteLine("함수 주소를 찾을 수 없습니다.");
                        Exit();
                    }

                    Console.WriteLine("타겟 call <REL32> 패치...");
                    Console.WriteLine();

                    Console.ForegroundColor = ConsoleColor.Green;

                    for (int i = 0; i < bomb.Length; i++)
                    {
                        if (pBomb[i] == 0xE8) // call rel32
                        {
                            bool isCalleeTarget = false;
                            string calleeTargetFunctionName = null;

                            int rel32 = R32i(pBomb, i + 1);
                            uint abs32 = (uint)(i + 0x05 + rel32);

                            if (abs32 == initializeBombOffset) // call initialize_bomb
                            {
                                isCalleeTarget = true;
                                calleeTargetFunctionName = SYM_INITIALIZE_BOMB;
                            }
                            else if (abs32 == sendMsgOffset) // call send_msg
                            {
                                isCalleeTarget = true;
                                calleeTargetFunctionName = SYM_SEND_MSG;
                            }

                            if (isCalleeTarget)
                            {
                                string instructionHex = GetHexString(pBomb + i, 5);

                                PadCall32WithNOPs(pBomb + i);
                                Console.WriteLine($"bomb+0x{i:X}\t{instructionHex}\t\tcall {calleeTargetFunctionName.PadRight(20, ' ')}\t--> 패치되었습니다.");
                            }
                        }
                    }

                    Console.ForegroundColor = ConsoleColor.Gray;

                    Console.WriteLine();

                    Console.WriteLine("문자열 패치...");

                    PatchCString(pBomb, bomb.Length, "Welcome to my fiendish little bomb. You have 6 phases with", "THIS BOMB IS SAFE (by Github : @rxndev)");
                    PatchCString(pBomb, bomb.Length, "which to blow yourself up. Have a nice day!", "HOST CHECK BYPASS, NO ATTEMPT LOG");
                    PatchCString(pBomb, bomb.Length, "Your instructor has been notified.", "BUT ^.^ NOBODY KNOWS EXPLODED");
                }
            }

            string newBombPath = $"{bombPath}_safe";
            File.WriteAllBytes(newBombPath, bomb);
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"Safe Bomb이 새로운 파일에 저장되었습니다. ({Path.GetFileName(newBombPath)})");

            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("생성된 Safe Bomb은:");
            Console.WriteLine(" - 호스트 인증이 제거되어 아무 리눅스 시스템에서나 실행할 수 있습니다.");
            Console.WriteLine(" - Explosion, Defusion 등 실패 성공 여부와 관계없이 아무런 로그를 남기지 않습니다.");
            Console.WriteLine();

            Console.WriteLine("주의:");
            Console.WriteLine(" - Safe Bomb은 Explode 되어도 감점되지 않지만, Defuse 되어도 기록이 남지 않습니다.");
            Console.WriteLine(" - Safe Bomb으로 로컬 리눅스 시스템에서 답 확인 후, 반드시 원본 Bomb으로 채점 서버에서 답을 제출하세요.");

            Console.ForegroundColor = ConsoleColor.Gray;

            Process.Start("explorer.exe", $"/select,\"{newBombPath}\"");

            Exit();

            return;
        }

        private static unsafe string GetHexString(byte* ptr, int size)
        {
            byte[] takenBytes = new byte[size];

            for (int i = 0; i < size; i++)
            {
                takenBytes[i] = ptr[i];
            }

            return string.Join(" ", takenBytes.Select(x => x.ToString("X2")));
        }

        private static unsafe void PadCall32WithNOPs(void* pCallInstruction)
        {
            byte* p = (byte*)pCallInstruction;

            for (int i = 0; i < 5; i++) // E8 ?? ?? ?? ?? (call rel32 : 5 bytes)
            {
                p[i] = 0x90;
            }
        }

        private static unsafe uint FindSymbol(byte* pElf, string symbolName)
        {
            ulong e_shoff = R64u(pElf, 0x28);
            ushort e_shentsize = R16u(pElf, 0x3A);
            ushort e_shnum = R16u(pElf, 0x3C);
            ushort e_shstrndx = R16u(pElf, 0x3E);

            byte* pShstrtabHeader = pElf + e_shoff + e_shentsize * e_shstrndx;
            uint shstrtabOffset = R32u(pShstrtabHeader, 0x18);

            nuint symtabOffset = 0;
            nuint symtabSize = 0;
            nuint strtabOffset = 0;

            for (int i = 0; i < e_shnum; i++)
            {
                byte* pSection = pElf + e_shoff + i * e_shentsize;

                uint sh_name = R32u(pSection);
                ulong sh_offset = R64u(pSection, 0x18);
                ulong sh_size = R64u(pSection, 0x20);

                string sectionName = ReadCString(pElf + shstrtabOffset + sh_name);

                if (sectionName == ".symtab")
                {
                    symtabOffset = (nuint)sh_offset;
                    symtabSize = (nuint)sh_size;
                }
                else if (sectionName == ".strtab")
                {
                    strtabOffset = (nuint)sh_offset;
                }
            }

            if (symtabOffset == 0 || strtabOffset == 0)
            {
                return 0;
            }

            int symbolCount = (int)(symtabSize / 0x18);

            for (int i = 0; i < symbolCount; i++)
            {
                byte* pSymbol = pElf + symtabOffset + i * 0x18;

                uint st_name = R32u(pSymbol, 0x00);
                ulong st_value = R64u(pSymbol, 0x08);

                string currentName = ReadCString(pElf + strtabOffset + st_name);

                if (currentName == symbolName)
                {
                    return (uint)st_value;
                }
            }

            return 0;
        }

        private static unsafe string ReadCString(byte* pStr)
        {
            int length = 0;

            while (pStr[length] != 0)
            {
                length++;
            }

            byte[] buffer = new byte[length];

            for (int i = 0; i < length; i++)
            {
                buffer[i] = pStr[i];
            }

            return Encoding.ASCII.GetString(buffer);
        }

        private static unsafe bool PatchCString(byte* pElf, int elfSize, string oldString, string newString)
        {
            byte[] oldBytes = Encoding.ASCII.GetBytes(oldString + '\0');
            byte[] newBytes = Encoding.ASCII.GetBytes(newString + '\0');

            if (newBytes.Length > oldBytes.Length)
            {
                return false;
            }

            for (int i = 0; i <= elfSize - oldBytes.Length; i++)
            {
                bool match = true;

                for (int j = 0; j < oldBytes.Length; j++)
                {
                    if (pElf[i + j] != oldBytes[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    for (int j = 0; j < newBytes.Length; j++)
                    {
                        pElf[i + j] = newBytes[j];
                    }

                    for (int j = newBytes.Length; j < oldBytes.Length; j++)
                    {
                        pElf[i + j] = 0x00;
                    }

                    return true;
                }
            }

            return false;
        }

        private static void Exit()
        {
            Console.WriteLine();
            Console.Write("계속하려면 아무 키나 누르십시오 . . . ");
            Console.ReadKey(true);
            Environment.Exit(0);
        }

        private static string GetOpenFileName()
        {
            using OpenFileDialog dialog = new();
            DialogResult result = dialog.ShowDialog();
            string fileName = dialog.FileName;

            if (result != DialogResult.OK)
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(fileName))
            {
                return null;
            }

            if (!File.Exists(fileName))
            {
                return null;
            }

            return fileName;
        }
    }
}
