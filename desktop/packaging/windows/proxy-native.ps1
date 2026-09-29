$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ClyntisWinInet {
    [StructLayout(LayoutKind.Sequential)] public struct Option { public int type; public IntPtr value; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct List {
        public int size; public IntPtr connection; public int count; public int error; public IntPtr options;
    }
    [DllImport("wininet.dll", SetLastError = true)] static extern bool InternetQueryOptionW(IntPtr h, int option, ref List data, ref int size);
    [DllImport("wininet.dll", SetLastError = true)] static extern bool InternetSetOptionW(IntPtr h, int option, IntPtr data, int size);
    public static int Flags() {
        var option = new Option { type = 1 };
        IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf<Option>());
        try {
            Marshal.StructureToPtr(option, p, false);
            var list = new List { size = Marshal.SizeOf<List>(), count = 1, options = p };
            int size = list.size;
            if (!InternetQueryOptionW(IntPtr.Zero, 75, ref list, ref size)) throw new System.ComponentModel.Win32Exception();
            return Marshal.PtrToStructure<Option>(p).value.ToInt32();
        } finally { Marshal.FreeHGlobal(p); }
    }
    public static void Flags(int flags) {
        IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf<Option>()), q = Marshal.AllocHGlobal(Marshal.SizeOf<List>());
        try {
            Marshal.StructureToPtr(new Option { type = 1, value = new IntPtr(flags) }, p, false);
            var list = new List { size = Marshal.SizeOf<List>(), count = 1, options = p };
            Marshal.StructureToPtr(list, q, false);
            if (!InternetSetOptionW(IntPtr.Zero, 75, q, list.size)) throw new System.ComponentModel.Win32Exception();
            InternetSetOptionW(IntPtr.Zero, 39, IntPtr.Zero, 0);
            InternetSetOptionW(IntPtr.Zero, 37, IntPtr.Zero, 0);
        } finally { Marshal.FreeHGlobal(p); Marshal.FreeHGlobal(q); }
    }
}
'@

