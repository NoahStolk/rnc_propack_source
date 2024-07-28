public class Vars
{
    public ushort EncKey;
    public ushort DictSize = 0x8000;
    public uint Method;
    public uint InputSize;
    public uint FileSize;
    public uint PackedSize;
    public uint ProcessedSize;
    public ushort BitCount;
    public ushort MatchCount;
    public ushort MatchOffset;
    public uint BitBuffer;
    public ushort UnpackedCrc;
    public ushort UnpackedCrcReal;
    public ushort PackedCrc;
    public byte[] Mem1;
    public IntPtr PackBlockStart;
    public byte[] Decoded;
    public IntPtr Window;
    public long ReadStartOffset;
    public byte[] Input;
    public byte[] Output;
    public long InputOffset;
    public long OutputOffset;
}

public enum ErrorCodes
{
    None = 0,
    CorruptedInputData = 4,
    CrcCheckFailed = 5,
    WrongRncHeader = 6,
    WrongRncHeader2 = 7,
    DecryptionKeyRequired = 10,
    NoRncArchivesWereFound = 11,
}

public static class RncUnpacker
{
    private static readonly ushort[] CrcTable = {
        0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
        0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
        0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
        0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
        0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
        0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
        0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
        0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
        0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
        0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
        0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
        0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
        0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
        0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
        0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
        0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
        0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
        0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
        0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
        0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
        0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
        0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
        0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
        0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
        0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
        0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
        0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
        0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
        0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
        0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
        0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
        0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
    };

    private static byte ReadByte(byte[] buf, ref long offset)
    {
        return buf[offset++];
    }

    private static ushort ReadWordBe(byte[] buf, ref long offset)
    {
        byte b1 = ReadByte(buf, ref offset);
        byte b2 = ReadByte(buf, ref offset);
        return (ushort)(b1 << 8 | b2);
    }

    private static uint ReadDwordBe(byte[] buf, ref long offset)
    {
        ushort w1 = ReadWordBe(buf, ref offset);
        ushort w2 = ReadWordBe(buf, ref offset);
        return (uint)(w1 << 16 | w2);
    }

    private static void ReadBuf(byte[] dest, byte[] source, ref long offset, int size)
    {
        Buffer.BlockCopy(source, (int)offset, dest, 0, size);
        offset += size;
    }

    private static void WriteBuf(byte[] dest, ref long offset, byte[] source, int size)
    {
        Buffer.BlockCopy(source, 0, dest, (int)offset, size);
        offset += size;
    }

    private static ushort CrcBlock(byte[] buf, long offset, int size)
    {
        ushort crc = 0;
        while (size-- > 0)
        {
            crc ^= ReadByte(buf, ref offset);
            crc = (ushort)(crc >> 8 ^ CrcTable[crc & 0xFF]);
        }
        return crc;
    }

    private static void RorW(ref ushort x)
    {
        x = (ushort)((x & 1) != 0 ? 0x8000 | x >> 1 : x >> 1);
    }

    private static Vars InitVars()
    {
        return new Vars
        {
            EncKey = 0,
            UnpackedCrcReal = 0,
            DictSize = 0x8000,
            ReadStartOffset = 0,
            InputOffset = 0,
            OutputOffset = 0,
        };
    }

    private static int _writtenDebug;

    private static byte ReadSourceByte(Vars v)
    {
        if (v.PackBlockStart.ToInt32() == 0xFFFD)
        {
            int leftSize = (int)(v.FileSize - v.InputOffset);
            int sizeToRead = Math.Min(leftSize, 0xFFFD);

            v.PackBlockStart = IntPtr.Zero;
            Array.Copy(v.Input, v.InputOffset, v.Mem1, 0, sizeToRead);
            v.InputOffset += sizeToRead;

            if (leftSize - sizeToRead > 2)
                leftSize = 2;
            else
                leftSize -= sizeToRead;

            Array.Copy(v.Input, v.InputOffset, v.Mem1, sizeToRead, leftSize);
            v.InputOffset -= leftSize;
        }

        byte result = v.Mem1[v.PackBlockStart.ToInt32()];
        v.PackBlockStart = (IntPtr)(v.PackBlockStart.ToInt32() + 1);

        if (_writtenDebug++ < 10)
            Console.WriteLine($"Read byte: {result:X2}");

        return result;
    }

    private static uint InputBitsM2(Vars v, short count)
    {
        uint bits = 0;
        while (count-- > 0)
        {
            if (v.BitCount == 0)
            {
                v.BitBuffer = ReadSourceByte(v);
                v.BitCount = 8;
            }

            bits <<= 1;
            
            if ((v.BitBuffer & 0x80) != 0)
                bits |= 1;
            
            v.BitBuffer <<= 1;
            v.BitCount--;
        }
        
        return bits;
    }

    private static void DecodeMatchCount(Vars v)
    {
        v.MatchCount = (ushort)(InputBitsM2(v, 1) + 4);
        if (InputBitsM2(v, 1) == 1)
        {
            v.MatchCount = (ushort)(((v.MatchCount - 1) << 1) + InputBitsM2(v, 1));
        }
    }

    private static void DecodeMatchOffset(Vars v)
    {
        v.MatchOffset = 0;
        if (InputBitsM2(v, 1) == 1)
        {
            v.MatchOffset = (ushort)InputBitsM2(v, 1);
            if (InputBitsM2(v, 1) == 1)
            {
                v.MatchOffset = (ushort)((v.MatchOffset << 1) | InputBitsM2(v, 1) | 4);
                if (InputBitsM2(v, 1) == 0)
                {
                    v.MatchOffset = (ushort)((v.MatchOffset << 1) | InputBitsM2(v, 1));
                }
            }
            else if (v.MatchOffset == 0)
            {
                v.MatchOffset = (ushort)(InputBitsM2(v, 1) + 2);
            }
        }
        v.MatchOffset = (ushort)((v.MatchOffset << 8) | ReadSourceByte(v) + 1);
    }

    private static void WriteDecodedByte(Vars v, byte b)
    {
        if (v.Window.ToInt32() == 0xFFFF)
        {
            WriteBuf(v.Output, ref v.OutputOffset, v.Decoded[v.DictSize..], 0xFFFF - v.DictSize);
            Array.Copy(v.Decoded, 0xFFFF - v.DictSize, v.Decoded, 0, v.DictSize);
            v.Window = (IntPtr)v.DictSize;
        }
        v.Decoded[v.Window.ToInt32()] = b;
        v.Window += 1;
        v.UnpackedCrcReal = (ushort)(CrcTable[(v.UnpackedCrcReal ^ b) & 0xFF] ^ (v.UnpackedCrcReal >> 8));
    }

    private static int UnpackDataM2(Vars v)
    {
        while (v.ProcessedSize < v.InputSize)
        {
            while (true)
            {
                if (InputBitsM2(v, 1) == 0)
                {
                    WriteDecodedByte(v, (byte)((v.EncKey ^ ReadSourceByte(v)) & 0xFF));
                    RorW(ref v.EncKey);
                    v.ProcessedSize++;
                }
                else
                {
                    if (InputBitsM2(v, 1) == 1)
                    {
                        if (InputBitsM2(v, 1) == 1)
                        {
                            if (InputBitsM2(v, 1) == 1)
                            {
                                v.MatchCount = (ushort)(ReadSourceByte(v) + 8);
                                if (v.MatchCount == 8)
                                {
                                    InputBitsM2(v, 1);
                                    break;
                                }
                            }
                            else
                            {
                                v.MatchCount = 3;
                            }
                            
                            DecodeMatchOffset(v);
                        }
                        else
                        {
                            v.MatchCount = 2;
                            v.MatchOffset = (ushort)(ReadSourceByte(v) + 1);
                        }
                        
                        v.ProcessedSize += v.MatchCount;
                        
                        while (v.MatchCount-- > 0)
                            WriteDecodedByte(v, v.Decoded[v.Window.ToInt32() - v.MatchOffset]);
                    }
                    else
                    {
                        DecodeMatchCount(v);
                        
                        if (v.MatchCount != 9)
                        {
                            DecodeMatchOffset(v);
                            v.ProcessedSize += v.MatchCount;
                            while (v.MatchCount-- > 0)
                                WriteDecodedByte(v, v.Decoded[v.Window.ToInt32() - v.MatchOffset]);
                        }
                        else
                        {
                            uint dataLength = (InputBitsM2(v, 4) << 2) + 12;
                            v.ProcessedSize += dataLength;

                            while (dataLength-- > 0)
                                WriteDecodedByte(v, (byte)((v.EncKey ^ ReadSourceByte(v)) & 0xFF));

                            RorW(ref v.EncKey);
                        }
                    }
                }
            }
        }

        WriteBuf(v.Output, ref v.OutputOffset, v.Decoded, v.Window.ToInt32() - v.DictSize);
        return 0;
    }

    private static ErrorCodes DoUnpackData(Vars v)
    {
        long startPos = v.InputOffset;
        uint sign = ReadDwordBe(v.Input, ref v.InputOffset);
        if (sign >> 8 != 0x524E43) // RNC
        {
            return ErrorCodes.WrongRncHeader;
        }
        v.Method = sign & 3;
        v.InputSize = ReadDwordBe(v.Input, ref v.InputOffset);
        v.PackedSize = ReadDwordBe(v.Input, ref v.InputOffset);
        if (v.FileSize < v.PackedSize)
        {
            return ErrorCodes.WrongRncHeader2;
        }
        v.UnpackedCrc = ReadWordBe(v.Input, ref v.InputOffset);
        v.PackedCrc = ReadWordBe(v.Input, ref v.InputOffset);
        ReadByte(v.Input, ref v.InputOffset);
        ReadByte(v.Input, ref v.InputOffset);
        if (CrcBlock(v.Input, v.InputOffset, (int)v.PackedSize) != v.PackedCrc)
        {
            return ErrorCodes.CorruptedInputData;
        }
        v.Mem1 = new byte[0xFFFF];
        v.Decoded = new byte[0xFFFF];
        v.PackBlockStart = 0xFFFD;
        v.Window = (IntPtr)v.DictSize;
        v.UnpackedCrcReal = 0;
        v.BitCount = 0;
        v.BitBuffer = 0;
        v.ProcessedSize = 0;
        ushort specifiedKey = v.EncKey;
        ErrorCodes errorCode = 0;
        InputBitsM2(v, 1);
        if (errorCode == 0)
        {
            if (InputBitsM2(v, 1) != 0 && v.EncKey == 0)
            {
                errorCode = ErrorCodes.DecryptionKeyRequired;
            }
        }
        if (errorCode == 0)
        {
            if (v.Method == 2)
            {
                errorCode = (ErrorCodes)UnpackDataM2(v);
            }
        }
        v.EncKey = specifiedKey;
        v.InputOffset = startPos + v.PackedSize + 0x12;
        if (errorCode != 0)
        {
            return errorCode;
        }
        if (v.UnpackedCrc != v.UnpackedCrcReal)
        {
            Console.WriteLine($"CRC check failed: {v.UnpackedCrc} != {v.UnpackedCrcReal}");
            return ErrorCodes.CrcCheckFailed;
        }
        return ErrorCodes.None;
    }

    public static ErrorCodes DoUnpack(Vars v)
    {
        v.PackedSize = v.FileSize;
        if (v.FileSize < 0x12)
        {
            return ErrorCodes.WrongRncHeader;
        }
        return DoUnpackData(v);
    }

    public static void Main(string[] args)
    {
        args = ["u", "E:\\repos-external\\rnc_propack_source\\CRATES.GSC", "E:\\repos-external\\rnc_propack_source\\CRATES_CS.NUS"];
        Vars v = InitVars();
        v.ReadStartOffset = 0;
        v.InputOffset = 0;
        v.OutputOffset = 0;

        using (FileStream inFile = new FileStream(args[1], FileMode.Open, FileAccess.Read))
        {
            v.FileSize = (uint)(inFile.Length - v.ReadStartOffset);
            v.Input = new byte[v.FileSize];
            inFile.Seek(v.ReadStartOffset, SeekOrigin.Begin);
            inFile.Read(v.Input, 0, (int)v.FileSize);
        }
        v.Output = new byte[0x1E00000];
        ErrorCodes errorCode = DoUnpack(v);
        switch (errorCode)
        {
            case ErrorCodes.None:
                using (FileStream outFile = new FileStream(args[2], FileMode.Create, FileAccess.Write))
                {
                    outFile.Write(v.Output, 0, (int)v.OutputOffset);
                }
                Console.WriteLine("File successfully unpacked!");
                Console.WriteLine($"Original/new size: {v.PackedSize + 0x12}/{v.OutputOffset} bytes");
                break;
            case ErrorCodes.CorruptedInputData:
                Console.WriteLine("Corrupted input data.");
                break;
            case ErrorCodes.CrcCheckFailed:
                Console.WriteLine("CRC check failed.");
                break;
            case ErrorCodes.WrongRncHeader:
            case ErrorCodes.WrongRncHeader2:
                Console.WriteLine("Wrong RNC header.");
                break;
            case ErrorCodes.DecryptionKeyRequired:
                Console.WriteLine("Decryption key required.");
                break;
            case ErrorCodes.NoRncArchivesWereFound:
                Console.WriteLine("No RNC archives were found.");
                break;
            default:
                Console.WriteLine($"Cannot process file. Error code: {errorCode}");
                break;
        }
    }
}
