using System.Buffers.Binary;
using System.ComponentModel;
using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ZipPoitto;

internal static class SafeZipExtractor
{
    internal const long MaxArchiveBytes = 2L * 1024 * 1024 * 1024;
    internal const int MaxEntryCount = 20_000;
    internal const long MaxCentralDirectoryBytes = 64L * 1024 * 1024;
    internal const long MaxEntryUncompressedBytes = 1L * 1024 * 1024 * 1024;
    internal const long MaxTotalUncompressedBytes = 4L * 1024 * 1024 * 1024;
    internal const long CompressionRatioCheckThreshold = 1L * 1024 * 1024;
    internal const long MaxCompressionRatio = 100;
    internal const ulong ReservedFreeBytes = 512UL * 1024 * 1024;

    private const int CopyBufferSize = 64 * 1024;
    private const uint EndOfCentralDirectorySignature = 0x06054b50;
    private const uint Zip64EndOfCentralDirectorySignature = 0x06064b50;
    private const uint Zip64EndOfCentralDirectoryLocatorSignature = 0x07064b50;
    private const uint CentralDirectoryHeaderSignature = 0x02014b50;
    private const uint LocalFileHeaderSignature = 0x04034b50;
    private const ushort Zip64ExtraFieldId = 0x0001;
    private const ushort Utf8Flag = 1 << 11;
    private const ushort EncryptedFlag = 1 << 0;
    private const ushort StrongEncryptedFlag = 1 << 6;
    private const ushort MaskedHeaderFlag = 1 << 13;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int MaxWindowsPathChars = 32_767;

    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);
    private static readonly Encoding Cp932 = CreateCp932Encoding();

    internal static string Extract(string zipPath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(zipPath);
        cancellationToken.ThrowIfCancellationRequested();

        var requestedZipPath = Path.GetFullPath(zipPath);
        if (IsUncPath(requestedZipPath))
        {
            throw UnsafeLocation("ネットワーク共有上のZIPは安全に解凍できません。");
        }

        using var zipStream = new FileStream(
            requestedZipPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            CopyBufferSize,
            FileOptions.RandomAccess);

        var fullZipPath = GetFinalLocalPath(zipStream.SafeFileHandle);
        ValidateLocalAclCapableVolume(fullZipPath);
        var parentDirectory = Path.GetDirectoryName(fullZipPath)
            ?? throw UnsafeLocation("ZIPファイルのローカル保存場所を特定できませんでした。");
        parentDirectory = Path.GetFullPath(parentDirectory);
        using var lockedSourceDirectories = LockDirectoryHierarchy(parentDirectory);
        var confirmedZipPath = GetFinalLocalPath(zipStream.SafeFileHandle);
        if (!string.Equals(fullZipPath, confirmedZipPath, StringComparison.OrdinalIgnoreCase))
        {
            throw UnsafeLocation("ZIPファイルの実体パスが安全確認中に変更されました。");
        }

        if (zipStream.Length > MaxArchiveBytes)
        {
            throw new TooLargeArchiveException(
                $"ZIPファイル本体が大きすぎます。安全のため、このアプリでは {FormatBytes(MaxArchiveBytes)} までに制限しています。");
        }

        var centralEntries = ReadAndValidateCentralDirectory(zipStream, cancellationToken);

        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read, leaveOpen: true, Cp932);
        var archiveEntries = archive.Entries.ToArray();
        ValidateMaterializedEntries(archiveEntries, centralEntries);

        var outputDirectory = GetUniqueOutputDirectory(parentDirectory, Path.GetFileNameWithoutExtension(fullZipPath));
        var tempDirectory = Path.Combine(parentDirectory, $".zippoit_tmp_{Guid.NewGuid():N}");
        var validatedEntries = ValidateEntryPaths(tempDirectory, centralEntries);

        var declaredTotal = centralEntries.Aggregate(0L, static (total, entry) => checked(total + entry.Length));
        EnsureFreeSpace(parentDirectory, checked((ulong)declaredTotal + ReservedFreeBytes));
        cancellationToken.ThrowIfCancellationRequested();

        var tempCreated = false;
        try
        {
            CreateNewDirectory(tempDirectory);
            tempCreated = true;
            using (var tempRootHandle = OpenTempRootWithoutDeleteSharing(tempDirectory))
            {
                VerifySecureDirectory(tempDirectory);
                if (Directory.EnumerateFileSystemEntries(tempDirectory).Any())
                {
                    throw new IOException("一時フォルダーが抽出開始前に空ではありません。");
                }

                ExtractValidatedEntries(
                    archiveEntries,
                    centralEntries,
                    validatedEntries,
                    parentDirectory,
                    cancellationToken);

                cancellationToken.ThrowIfCancellationRequested();
            }

            Directory.Move(tempDirectory, outputDirectory);
            tempCreated = false;
            return outputDirectory;
        }
        catch (Exception extractionError)
        {
            if (tempCreated)
            {
                try
                {
                    if (Directory.Exists(tempDirectory))
                    {
                        Directory.Delete(tempDirectory, recursive: true);
                    }
                }
                catch (Exception cleanupError)
                {
                    throw new ExtractionCleanupException(tempDirectory, extractionError, cleanupError);
                }
            }

            ExceptionDispatchInfo.Capture(extractionError).Throw();
            throw;
        }
    }

    private static IReadOnlyList<CentralEntry> ReadAndValidateCentralDirectory(
        FileStream stream,
        CancellationToken cancellationToken)
    {
        var eocd = FindEndOfCentralDirectory(stream);
        var directory = ReadDirectoryLocation(stream, eocd);

        if (directory.EntryCount > MaxEntryCount)
        {
            throw new TooLargeArchiveException(
                $"中に入っている項目数が多すぎます。安全のため、このアプリでは {MaxEntryCount:N0}個までに制限しています。");
        }

        if (directory.Size > MaxCentralDirectoryBytes)
        {
            throw new TooLargeArchiveException(
                $"ZIPの中央ディレクトリが大きすぎます。安全のため、このアプリでは {FormatBytes(MaxCentralDirectoryBytes)} までに制限しています。");
        }

        if (directory.Offset > (ulong)stream.Length || directory.Size > (ulong)stream.Length - directory.Offset)
        {
            throw InvalidZip("ZIPの中央ディレクトリ範囲がファイル外を指しています。");
        }

        var directoryEnd = checked(directory.Offset + directory.Size);
        if (directoryEnd > directory.BoundaryOffset)
        {
            throw InvalidZip("ZIPの中央ディレクトリ範囲が終端レコードと重なっています。");
        }

        stream.Position = checked((long)directory.Offset);
        var entries = new List<CentralEntry>((int)directory.EntryCount);
        var fixedHeaderBuffer = new byte[46];
        ulong consumed = 0;
        long totalUncompressed = 0;
        long totalCompressed = 0;

        while (consumed < directory.Size)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entries.Count >= MaxEntryCount)
            {
                throw new TooLargeArchiveException(
                    $"中に入っている実際の項目数が {MaxEntryCount:N0}個を超えています。");
            }

            if (directory.Size - consumed < 46)
            {
                throw InvalidZip("ZIPの中央ディレクトリヘッダーが途中で切れています。");
            }

            var fixedHeader = fixedHeaderBuffer.AsSpan();
            ReadExactly(stream, fixedHeader);
            if (BinaryPrimitives.ReadUInt32LittleEndian(fixedHeader) != CentralDirectoryHeaderSignature)
            {
                throw InvalidZip("ZIPの中央ディレクトリに不正なレコードがあります。");
            }

            var variableLength = checked(
                (ulong)BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader[28..]) +
                BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader[30..]) +
                BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader[32..]));
            if (variableLength > directory.Size - consumed - 46)
            {
                throw InvalidZip("ZIPの中央ディレクトリの可変長データが範囲外です。");
            }

            var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader[28..]);
            var extraLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader[30..]);
            var commentLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader[32..]);
            var nameBytes = new byte[nameLength];
            var extraBytes = new byte[extraLength];
            ReadExactly(stream, nameBytes);
            ReadExactly(stream, extraBytes);
            SkipExactly(stream, commentLength);

            var flags = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader[8..]);
            if ((flags & (EncryptedFlag | StrongEncryptedFlag | MaskedHeaderFlag)) != 0)
            {
                throw InvalidZip("パスワード付き・暗号化ZIPには対応していません。");
            }

            var compressionMethod = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader[10..]);
            if (compressionMethod is not 0 and not 8)
            {
                throw InvalidZip($"対応していない圧縮方式です（方式 {compressionMethod}）。");
            }

            var uncompressed32 = BinaryPrimitives.ReadUInt32LittleEndian(fixedHeader[24..]);
            var compressed32 = BinaryPrimitives.ReadUInt32LittleEndian(fixedHeader[20..]);
            var localOffset32 = BinaryPrimitives.ReadUInt32LittleEndian(fixedHeader[42..]);
            var diskStart16 = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader[34..]);
            var zip64 = ReadZip64Values(
                extraBytes,
                uncompressed32 == uint.MaxValue,
                compressed32 == uint.MaxValue,
                localOffset32 == uint.MaxValue,
                diskStart16 == ushort.MaxValue);

            var uncompressed = uncompressed32 == uint.MaxValue ? zip64.UncompressedSize : uncompressed32;
            var compressed = compressed32 == uint.MaxValue ? zip64.CompressedSize : compressed32;
            var localOffset = localOffset32 == uint.MaxValue ? zip64.LocalHeaderOffset : localOffset32;
            var diskStart = diskStart16 == ushort.MaxValue ? zip64.DiskStart : diskStart16;
            if (diskStart != 0)
            {
                throw InvalidZip("複数ディスクに分割されたZIPには対応していません。");
            }

            if (uncompressed > long.MaxValue || compressed > long.MaxValue || localOffset > long.MaxValue)
            {
                throw new TooLargeArchiveException("ZIP内のサイズ情報が安全に処理できる範囲を超えています。");
            }

            var name = DecodeEntryName(nameBytes, flags);
            var isDirectory = name.EndsWith('/') || name.EndsWith('\\');
            var entry = new CentralEntry(
                name,
                nameBytes,
                flags,
                compressionMethod,
                BinaryPrimitives.ReadUInt32LittleEndian(fixedHeader[16..]),
                checked((long)compressed),
                checked((long)uncompressed),
                BinaryPrimitives.ReadUInt32LittleEndian(fixedHeader[38..]),
                fixedHeader[5],
                checked((long)localOffset),
                isDirectory);

            ValidateEntryMetadata(entry);
            ValidateLocalHeader(stream, entry, directory.Offset);

            totalUncompressed = AddWithLimit(
                totalUncompressed,
                entry.Length,
                MaxTotalUncompressedBytes,
                "解凍後の合計サイズが安全上限を超えています。");
            totalCompressed = AddWithLimit(
                totalCompressed,
                entry.CompressedLength,
                long.MaxValue,
                "ZIP内の合計圧縮サイズを安全に計算できません。");
            entries.Add(entry);
            consumed = checked(consumed + 46 + variableLength);
        }

        if (consumed != directory.Size || (ulong)entries.Count != directory.EntryCount)
        {
            throw InvalidZip("ZIPの宣言項目数と実際の中央ディレクトリが一致しません。");
        }

        if (ExceedsCompressionRatio(totalUncompressed, totalCompressed))
        {
            throw new TooLargeArchiveException("ZIP全体の圧縮率が安全上限を超えています。");
        }

        return entries;
    }

    private static EndOfCentralDirectory FindEndOfCentralDirectory(FileStream stream)
    {
        const int minimumRecordSize = 22;
        const int maximumSearchSize = minimumRecordSize + ushort.MaxValue;
        if (stream.Length < minimumRecordSize)
        {
            throw InvalidZip("ZIPの終端レコードがありません。");
        }

        var searchLength = (int)Math.Min(stream.Length, maximumSearchSize);
        var buffer = new byte[searchLength];
        stream.Position = stream.Length - searchLength;
        ReadExactly(stream, buffer);

        for (var index = searchLength - minimumRecordSize; index >= 0; index--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(index)) != EndOfCentralDirectorySignature)
            {
                continue;
            }

            var commentLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(index + 20));
            if (index + minimumRecordSize + commentLength != searchLength)
            {
                continue;
            }

            return new EndOfCentralDirectory(
                stream.Length - searchLength + index,
                BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(index + 4)),
                BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(index + 6)),
                BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(index + 8)),
                BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(index + 10)),
                BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(index + 12)),
                BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(index + 16)));
        }

        throw InvalidZip("ZIPの終端レコードが見つかりません。");
    }

    private static DirectoryLocation ReadDirectoryLocation(FileStream stream, EndOfCentralDirectory eocd)
    {
        if (eocd.DiskNumber != 0 || eocd.DirectoryDiskNumber != 0 || eocd.EntriesOnDisk != eocd.TotalEntries)
        {
            throw InvalidZip("複数ディスクに分割されたZIPには対応していません。");
        }

        var needsZip64 = eocd.EntriesOnDisk == ushort.MaxValue ||
                         eocd.TotalEntries == ushort.MaxValue ||
                         eocd.DirectorySize == uint.MaxValue ||
                         eocd.DirectoryOffset == uint.MaxValue;
        if (!needsZip64)
        {
            return new DirectoryLocation(
                eocd.TotalEntries,
                eocd.DirectorySize,
                eocd.DirectoryOffset,
                checked((ulong)eocd.Offset));
        }

        if (eocd.Offset < 20)
        {
            throw InvalidZip("ZIP64終端ロケーターがありません。");
        }

        Span<byte> locator = stackalloc byte[20];
        stream.Position = eocd.Offset - locator.Length;
        ReadExactly(stream, locator);
        if (BinaryPrimitives.ReadUInt32LittleEndian(locator) != Zip64EndOfCentralDirectoryLocatorSignature)
        {
            throw InvalidZip("ZIP64終端ロケーターが見つかりません。");
        }

        var zip64Disk = BinaryPrimitives.ReadUInt32LittleEndian(locator[4..]);
        var zip64Offset = BinaryPrimitives.ReadUInt64LittleEndian(locator[8..]);
        var diskCount = BinaryPrimitives.ReadUInt32LittleEndian(locator[16..]);
        if (zip64Disk != 0 || diskCount != 1)
        {
            throw InvalidZip("複数ディスクに分割されたZIP64には対応していません。");
        }

        if (zip64Offset > (ulong)stream.Length - 12 || zip64Offset > (ulong)(eocd.Offset - 20))
        {
            throw InvalidZip("ZIP64終端レコードの位置が範囲外です。");
        }

        Span<byte> zip64Header = stackalloc byte[56];
        stream.Position = checked((long)zip64Offset);
        ReadExactly(stream, zip64Header);
        if (BinaryPrimitives.ReadUInt32LittleEndian(zip64Header) != Zip64EndOfCentralDirectorySignature)
        {
            throw InvalidZip("ZIP64終端レコードが見つかりません。");
        }

        var recordSize = BinaryPrimitives.ReadUInt64LittleEndian(zip64Header[4..]);
        if (recordSize < 44 || recordSize > (ulong)stream.Length - zip64Offset - 12)
        {
            throw InvalidZip("ZIP64終端レコードのサイズが不正です。");
        }

        var recordEnd = checked(zip64Offset + 12 + recordSize);
        if (recordEnd > (ulong)(eocd.Offset - 20))
        {
            throw InvalidZip("ZIP64終端レコードがロケーターと重なっています。");
        }

        var diskNumber = BinaryPrimitives.ReadUInt32LittleEndian(zip64Header[16..]);
        var directoryDisk = BinaryPrimitives.ReadUInt32LittleEndian(zip64Header[20..]);
        var entriesOnDisk = BinaryPrimitives.ReadUInt64LittleEndian(zip64Header[24..]);
        var totalEntries = BinaryPrimitives.ReadUInt64LittleEndian(zip64Header[32..]);
        if (diskNumber != 0 || directoryDisk != 0 || entriesOnDisk != totalEntries)
        {
            throw InvalidZip("複数ディスクに分割されたZIP64には対応していません。");
        }

        return new DirectoryLocation(
            totalEntries,
            BinaryPrimitives.ReadUInt64LittleEndian(zip64Header[40..]),
            BinaryPrimitives.ReadUInt64LittleEndian(zip64Header[48..]),
            zip64Offset);
    }

    private static Zip64Values ReadZip64Values(
        ReadOnlySpan<byte> extra,
        bool needsUncompressed,
        bool needsCompressed,
        bool needsOffset,
        bool needsDisk)
    {
        var position = 0;
        while (position < extra.Length)
        {
            if (extra.Length - position < 4)
            {
                throw InvalidZip("ZIPの拡張フィールドが途中で切れています。");
            }

            var id = BinaryPrimitives.ReadUInt16LittleEndian(extra[position..]);
            var length = BinaryPrimitives.ReadUInt16LittleEndian(extra[(position + 2)..]);
            position += 4;
            if (length > extra.Length - position)
            {
                throw InvalidZip("ZIPの拡張フィールド長が範囲外です。");
            }

            if (id == Zip64ExtraFieldId)
            {
                var data = extra.Slice(position, length);
                var dataPosition = 0;
                var uncompressed = needsUncompressed ? ReadZip64UInt64(data, ref dataPosition) : 0;
                var compressed = needsCompressed ? ReadZip64UInt64(data, ref dataPosition) : 0;
                var offset = needsOffset ? ReadZip64UInt64(data, ref dataPosition) : 0;
                var disk = needsDisk ? ReadZip64UInt32(data, ref dataPosition) : 0;
                return new Zip64Values(uncompressed, compressed, offset, disk);
            }

            position += length;
        }

        if (needsUncompressed || needsCompressed || needsOffset || needsDisk)
        {
            throw InvalidZip("ZIP64項目に必要な拡張サイズ情報がありません。");
        }

        return default;
    }

    private static ulong ReadZip64UInt64(ReadOnlySpan<byte> data, ref int position)
    {
        if (data.Length - position < sizeof(ulong))
        {
            throw InvalidZip("ZIP64拡張フィールドが途中で切れています。");
        }

        var result = BinaryPrimitives.ReadUInt64LittleEndian(data[position..]);
        position += sizeof(ulong);
        return result;
    }

    private static uint ReadZip64UInt32(ReadOnlySpan<byte> data, ref int position)
    {
        if (data.Length - position < sizeof(uint))
        {
            throw InvalidZip("ZIP64拡張フィールドが途中で切れています。");
        }

        var result = BinaryPrimitives.ReadUInt32LittleEndian(data[position..]);
        position += sizeof(uint);
        return result;
    }

    private static void ValidateEntryMetadata(CentralEntry entry)
    {
        if (entry.Length > MaxEntryUncompressedBytes)
        {
            throw new TooLargeArchiveException(
                $"ZIP内の1項目が大きすぎます（{entry.Name}）。1項目は {FormatBytes(MaxEntryUncompressedBytes)} までです。");
        }

        if (ExceedsCompressionRatio(entry.Length, entry.CompressedLength))
        {
            throw new TooLargeArchiveException(
                $"圧縮率が安全上限を超えている項目があります（{entry.Name}）。");
        }

        if (entry.CompressionMethod == 0 && entry.CompressedLength != entry.Length)
        {
            throw InvalidZip($"無圧縮項目のサイズ情報が一致しません（{entry.Name}）。");
        }

        if (entry.IsDirectory && (entry.Length != 0 || entry.CompressedLength != 0))
        {
            throw InvalidZip($"ディレクトリ項目にデータが含まれています（{entry.Name}）。");
        }

        var unixFileType = (entry.ExternalAttributes >> 16) & 0xF000;
        var isUnixSpecial = entry.HostSystem == 3 && unixFileType is not 0 and not 0x4000 and not 0x8000;
        var isUnixSymlink = entry.HostSystem == 3 && unixFileType == 0xA000;
        var hasReparseAttribute = (entry.ExternalAttributes & (uint)FileAttributes.ReparsePoint) != 0;
        if (isUnixSpecial || isUnixSymlink || hasReparseAttribute)
        {
            throw InvalidZip($"シンボリックリンクまたは特殊ファイルは解凍できません（{entry.Name}）。");
        }
    }

    private static void ValidateLocalHeader(FileStream stream, CentralEntry entry, ulong directoryOffset)
    {
        if ((ulong)entry.LocalHeaderOffset > (ulong)stream.Length ||
            (ulong)entry.LocalHeaderOffset > directoryOffset ||
            directoryOffset - (ulong)entry.LocalHeaderOffset < 30)
        {
            throw InvalidZip($"ローカルヘッダー位置が範囲外です（{entry.Name}）。");
        }

        var savedPosition = stream.Position;
        try
        {
            Span<byte> localHeader = stackalloc byte[30];
            stream.Position = entry.LocalHeaderOffset;
            ReadExactly(stream, localHeader);
            if (BinaryPrimitives.ReadUInt32LittleEndian(localHeader) != LocalFileHeaderSignature)
            {
                throw InvalidZip($"ローカルヘッダーが見つかりません（{entry.Name}）。");
            }

            var localFlags = BinaryPrimitives.ReadUInt16LittleEndian(localHeader[6..]);
            var localMethod = BinaryPrimitives.ReadUInt16LittleEndian(localHeader[8..]);
            if ((localFlags & (EncryptedFlag | StrongEncryptedFlag | MaskedHeaderFlag)) != 0 ||
                localMethod != entry.CompressionMethod ||
                (localFlags & Utf8Flag) != (entry.Flags & Utf8Flag))
            {
                throw InvalidZip($"中央ディレクトリとローカルヘッダーが一致しません（{entry.Name}）。");
            }

            var localNameLength = BinaryPrimitives.ReadUInt16LittleEndian(localHeader[26..]);
            var localExtraLength = BinaryPrimitives.ReadUInt16LittleEndian(localHeader[28..]);
            var dataOffset = checked((ulong)entry.LocalHeaderOffset + 30 + localNameLength + localExtraLength);
            if (dataOffset > directoryOffset || (ulong)entry.CompressedLength > directoryOffset - dataOffset)
            {
                throw InvalidZip($"圧縮データ範囲が中央ディレクトリと重なっています（{entry.Name}）。");
            }

            var localName = new byte[localNameLength];
            ReadExactly(stream, localName);
            if (!localName.AsSpan().SequenceEqual(entry.RawName))
            {
                throw InvalidZip($"中央ディレクトリとローカル項目名が一致しません（{entry.Name}）。");
            }
        }
        finally
        {
            stream.Position = savedPosition;
        }
    }

    private static void ValidateMaterializedEntries(
        IReadOnlyList<ZipArchiveEntry> archiveEntries,
        IReadOnlyList<CentralEntry> centralEntries)
    {
        if (archiveEntries.Count != centralEntries.Count || archiveEntries.Count > MaxEntryCount)
        {
            throw InvalidZip("ZIPの宣言項目数と読み取った項目数が一致しません。");
        }

        long totalUncompressed = 0;
        long totalCompressed = 0;
        for (var index = 0; index < archiveEntries.Count; index++)
        {
            var actual = archiveEntries[index];
            var expected = centralEntries[index];
            if (!string.Equals(actual.FullName, expected.Name, StringComparison.Ordinal) ||
                actual.Length != expected.Length ||
                actual.CompressedLength != expected.CompressedLength ||
                actual.Crc32 != expected.Crc32 ||
                actual.IsEncrypted)
            {
                throw InvalidZip("ZIPの中央ディレクトリ情報を一貫して読み取れませんでした。");
            }

            if (actual.Length > MaxEntryUncompressedBytes ||
                ExceedsCompressionRatio(actual.Length, actual.CompressedLength))
            {
                throw new TooLargeArchiveException($"ZIP内の項目が安全上限を超えています（{actual.FullName}）。");
            }

            totalUncompressed = AddWithLimit(
                totalUncompressed,
                actual.Length,
                MaxTotalUncompressedBytes,
                "解凍後の合計サイズが安全上限を超えています。");
            totalCompressed = AddWithLimit(
                totalCompressed,
                actual.CompressedLength,
                long.MaxValue,
                "ZIP内の合計圧縮サイズを安全に計算できません。");
        }

        if (ExceedsCompressionRatio(totalUncompressed, totalCompressed))
        {
            throw new TooLargeArchiveException("ZIP全体の圧縮率が安全上限を超えています。");
        }
    }

    private static IReadOnlyList<ValidatedEntry> ValidateEntryPaths(
        string tempDirectory,
        IReadOnlyList<CentralEntry> entries)
    {
        var root = EnsureTrailingSeparator(Path.GetFullPath(tempDirectory));
        var knownPaths = new Dictionary<string, PathKind>(StringComparer.OrdinalIgnoreCase);
        var validated = new List<ValidatedEntry>(entries.Count);

        foreach (var entry in entries)
        {
            var normalized = ValidateAndNormalizeEntryName(entry.Name, entry.IsDirectory);
            var components = normalized.Split(Path.DirectorySeparatorChar);
            var current = string.Empty;
            for (var index = 0; index < components.Length - 1; index++)
            {
                current = current.Length == 0
                    ? components[index]
                    : Path.Combine(current, components[index]);
                RegisterPath(knownPaths, current, PathKind.ImplicitDirectory, allowImplicitDirectoryUpgrade: false);
            }

            var kind = entry.IsDirectory ? PathKind.ExplicitDirectory : PathKind.File;
            RegisterPath(knownPaths, normalized, kind, allowImplicitDirectoryUpgrade: entry.IsDirectory);

            var destination = Path.GetFullPath(Path.Combine(tempDirectory, normalized));
            if (!destination.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                throw InvalidZip($"解凍先の外を指す項目名です（{entry.Name}）。");
            }

            validated.Add(new ValidatedEntry(destination, entry.IsDirectory));
        }

        return validated;
    }

    private static string ValidateAndNormalizeEntryName(string name, bool isDirectory)
    {
        if (string.IsNullOrEmpty(name) || name[0] is '/' or '\\')
        {
            throw InvalidZip("空または絶対パスの項目名は解凍できません。");
        }

        foreach (var character in name)
        {
            if (character == '\0' || char.IsControl(character) || character is '<' or '>' or '"' or '|' or '?' or '*' or ':')
            {
                throw InvalidZip($"Windowsで安全に扱えない文字を含む項目名です（{name}）。");
            }
        }

        var pathPart = isDirectory ? name[..^1] : name;
        if (pathPart.Length == 0)
        {
            throw InvalidZip("ルートだけを表すディレクトリ項目は解凍できません。");
        }

        var components = pathPart.Split(['/', '\\']);
        if (components.Any(static component => component.Length == 0))
        {
            throw InvalidZip($"空のパス要素を含む項目名です（{name}）。");
        }

        foreach (var component in components)
        {
            if (component is "." or "..")
            {
                throw InvalidZip($"相対移動を含む項目名です（{name}）。");
            }

            if (component.EndsWith(' ') || component.EndsWith('.'))
            {
                throw InvalidZip($"末尾が空白または点の項目名です（{name}）。");
            }

            var reservedBase = component.Split('.')[0];
            if (IsReservedWindowsName(reservedBase))
            {
                throw InvalidZip($"Windowsの予約名を含む項目名です（{name}）。");
            }
        }

        return string.Join(Path.DirectorySeparatorChar, components);
    }

    private static bool IsReservedWindowsName(string name)
    {
        if (name.Equals("CON", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("AUX", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("CONIN$", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("CONOUT$", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("CLOCK$", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return name.Length == 4 &&
               (name.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) &&
               (name[3] is >= '1' and <= '9' or '¹' or '²' or '³');
    }

    private static void RegisterPath(
        IDictionary<string, PathKind> knownPaths,
        string path,
        PathKind requestedKind,
        bool allowImplicitDirectoryUpgrade)
    {
        if (!knownPaths.TryGetValue(path, out var existingKind))
        {
            knownPaths.Add(path, requestedKind);
            return;
        }

        var existingSpelling = knownPaths.Keys.First(key => string.Equals(key, path, StringComparison.OrdinalIgnoreCase));
        if (!string.Equals(existingSpelling, path, StringComparison.Ordinal))
        {
            throw InvalidZip($"大文字と小文字だけが異なる項目名があります（{path}）。");
        }

        if (allowImplicitDirectoryUpgrade &&
            requestedKind == PathKind.ExplicitDirectory &&
            existingKind == PathKind.ImplicitDirectory)
        {
            knownPaths[path] = PathKind.ExplicitDirectory;
            return;
        }

        if (requestedKind == PathKind.ImplicitDirectory &&
            existingKind is PathKind.ImplicitDirectory or PathKind.ExplicitDirectory)
        {
            return;
        }

        throw InvalidZip($"同名項目またはファイルとディレクトリの衝突があります（{path}）。");
    }

    private static void ExtractValidatedEntries(
        IReadOnlyList<ZipArchiveEntry> archiveEntries,
        IReadOnlyList<CentralEntry> centralEntries,
        IReadOnlyList<ValidatedEntry> validatedEntries,
        string volumePath,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[CopyBufferSize];
        long actualTotal = 0;
        var totalCompressed = centralEntries.Aggregate(
            0L,
            static (total, entry) => AddWithLimit(
                total,
                entry.CompressedLength,
                long.MaxValue,
                "ZIP内の合計圧縮サイズを安全に計算できません。"));

        for (var index = 0; index < archiveEntries.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var archiveEntry = archiveEntries[index];
            var centralEntry = centralEntries[index];
            var validatedEntry = validatedEntries[index];
            if (validatedEntry.IsDirectory)
            {
                Directory.CreateDirectory(validatedEntry.DestinationPath);
                continue;
            }

            var parent = Path.GetDirectoryName(validatedEntry.DestinationPath)
                ?? throw new IOException("解凍先の親フォルダーを特定できませんでした。");
            Directory.CreateDirectory(parent);

            using var source = archiveEntry.Open();
            using var destination = new FileStream(
                validatedEntry.DestinationPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                CopyBufferSize,
                FileOptions.SequentialScan);

            var crc = Crc32Calculator.InitialValue;
            long entryWritten = 0;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var read = source.Read(buffer, 0, buffer.Length);
                if (read == 0)
                {
                    break;
                }

                var nextEntryWritten = AddWithLimit(
                    entryWritten,
                    read,
                    MaxEntryUncompressedBytes,
                    $"1項目の実際の解凍サイズが安全上限を超えました（{centralEntry.Name}）。");
                var nextTotal = AddWithLimit(
                    actualTotal,
                    read,
                    MaxTotalUncompressedBytes,
                    "実際の解凍合計サイズが安全上限を超えました。");
                if (ExceedsCompressionRatio(nextEntryWritten, centralEntry.CompressedLength))
                {
                    throw new TooLargeArchiveException(
                        $"実際の圧縮率が安全上限を超えました（{centralEntry.Name}）。");
                }

                if (ExceedsCompressionRatio(nextTotal, totalCompressed))
                {
                    throw new TooLargeArchiveException("実際のZIP全体の圧縮率が安全上限を超えました。");
                }

                EnsureFreeSpace(volumePath, checked(ReservedFreeBytes + (ulong)read));
                destination.Write(buffer, 0, read);
                crc = Crc32Calculator.Update(crc, buffer.AsSpan(0, read));
                entryWritten = nextEntryWritten;
                actualTotal = nextTotal;
                cancellationToken.ThrowIfCancellationRequested();
            }

            destination.Flush(flushToDisk: false);
            if (entryWritten != archiveEntry.Length || entryWritten != centralEntry.Length)
            {
                throw InvalidZip($"項目の実際のサイズがZIPの宣言値と一致しません（{centralEntry.Name}）。");
            }

            var finalCrc = Crc32Calculator.Finalize(crc);
            if (finalCrc != archiveEntry.Crc32 || finalCrc != centralEntry.Crc32)
            {
                throw InvalidZip($"項目のCRC32が一致しません。ZIPが壊れている可能性があります（{centralEntry.Name}）。");
            }

            destination.Dispose();
            File.SetLastWriteTime(validatedEntry.DestinationPath, archiveEntry.LastWriteTime.DateTime);
        }
    }

    private static bool ExceedsCompressionRatio(long uncompressed, long compressed)
    {
        if (uncompressed < CompressionRatioCheckThreshold)
        {
            return false;
        }

        if (compressed <= 0)
        {
            return true;
        }

        return compressed <= long.MaxValue / MaxCompressionRatio &&
               uncompressed > compressed * MaxCompressionRatio;
    }

    private static long AddWithLimit(long current, long addition, long limit, string message)
    {
        if (addition < 0 || current < 0 || addition > limit || current > limit - addition)
        {
            throw new TooLargeArchiveException(message);
        }

        return current + addition;
    }

    private static void EnsureFreeSpace(string path, ulong requiredAvailableBytes)
    {
        if (!GetDiskFreeSpaceEx(path, out var available, out _, out _))
        {
            throw new IOException(
                "保存先の空き容量を確認できませんでした。",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }

        if (available < requiredAvailableBytes)
        {
            throw new TooLargeArchiveException(
                $"保存先の空き容量が足りません。解凍後も {FormatBytes((long)ReservedFreeBytes)} の空きを残せる場所で実行してください。");
        }
    }

    private static void CreateNewDirectory(string path)
    {
        var currentUser = GetCurrentUserSid();
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(currentUser);
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.FullControl,
            InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        var descriptor = security.GetSecurityDescriptorBinaryForm();
        var pinnedDescriptor = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        try
        {
            var securityAttributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = pinnedDescriptor.AddrOfPinnedObject(),
                InheritHandle = false
            };
            if (CreateDirectory(path, ref securityAttributes))
            {
                return;
            }

            var error = Marshal.GetLastWin32Error();
            if (error == 183)
            {
                throw new IOException("安全な一時フォルダー名が既に使用されています。");
            }

            throw new IOException("保護された一時フォルダーを作成できませんでした。", new Win32Exception(error));
        }
        finally
        {
            pinnedDescriptor.Free();
        }
    }

    private static void VerifySecureDirectory(string path)
    {
        var currentUser = GetCurrentUserSid();
        var security = new DirectoryInfo(path).GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        if (!security.AreAccessRulesProtected)
        {
            throw new UnauthorizedAccessException("一時フォルダーのアクセス規則を継承から保護できませんでした。");
        }

        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !currentUser.Equals(owner))
        {
            throw new UnauthorizedAccessException("一時フォルダーの所有者が現在のWindowsユーザーではありません。");
        }

        var rules = security
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        var hasRequiredRule = false;
        foreach (var rule in rules)
        {
            if (rule.IsInherited ||
                rule.AccessControlType != AccessControlType.Allow ||
                !currentUser.Equals(rule.IdentityReference))
            {
                throw new UnauthorizedAccessException("一時フォルダーに想定外のアクセス規則があります。");
            }

            if ((rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl &&
                (rule.InheritanceFlags & (InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit)) ==
                (InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit))
            {
                hasRequiredRule = true;
            }
        }

        if (!hasRequiredRule)
        {
            throw new UnauthorizedAccessException("一時フォルダーに現ユーザー専用のアクセス規則を設定できませんでした。");
        }
    }

    private static SafeFileHandle OpenTempRootWithoutDeleteSharing(string path)
    {
        var handle = CreateFile(
            path,
            FileReadAttributes,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("一時フォルダーを安全に固定できませんでした。", new Win32Exception(error));
        }

        if (!GetFileInformationByHandleEx(
                handle,
                fileInformationClass: 0,
                out var information,
                (uint)Marshal.SizeOf<FileBasicInfo>()))
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("一時フォルダーの実体を確認できませんでした。", new Win32Exception(error));
        }

        if ((information.FileAttributes & (uint)FileAttributes.Directory) == 0 ||
            (information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
        {
            handle.Dispose();
            throw new IOException("一時フォルダーが別の場所を指す項目へ置き換えられました。");
        }

        return handle;
    }

    private static LockedDirectoryHandles LockDirectoryHierarchy(string parentDirectory)
    {
        var fullParent = Path.GetFullPath(parentDirectory);
        var root = Path.GetPathRoot(fullParent);
        if (string.IsNullOrEmpty(root) || IsUncPath(root))
        {
            throw UnsafeLocation("ZIP保存場所のローカルdirectory階層を特定できませんでした。");
        }

        var normalizedRoot = Path.GetFullPath(root);
        var paths = new List<string> { fullParent };
        var current = fullParent;
        while (!string.Equals(
                   NormalizeDirectoryPath(current),
                   NormalizeDirectoryPath(normalizedRoot),
                   StringComparison.OrdinalIgnoreCase))
        {
            var parent = Directory.GetParent(current)?.FullName;
            if (string.IsNullOrEmpty(parent))
            {
                throw UnsafeLocation("ZIP保存場所のdirectory階層を安全に列挙できませんでした。");
            }

            current = Path.GetFullPath(parent);
            paths.Add(current);
        }

        var handles = new List<SafeFileHandle>(paths.Count);
        try
        {
            foreach (var expectedPath in paths)
            {
                SafeFileHandle handle;
                try
                {
                    handle = OpenLockedSourceDirectory(expectedPath);
                }
                catch (UnsafeExtractionLocationException ex) when (
                    handles.Count > 0 && IsDirectorySharingConflict(ex))
                {
                    // WindowsやExplorerが祖先directoryをDELETE access付きで保持している場合、
                    // share-deleteなしhandleとは共存できない。ZIPの直接parentは必ず固定し、
                    // 祖先は競合が起きる直前まで固定する。
                    break;
                }

                handles.Add(handle);
                var actualPath = GetFinalLocalPath(handle);
                if (!string.Equals(
                        NormalizeDirectoryPath(expectedPath),
                        NormalizeDirectoryPath(actualPath),
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw UnsafeLocation($"ZIP保存場所のdirectory実体が一致しません（{expectedPath}）。");
                }
            }

            return new LockedDirectoryHandles(handles);
        }
        catch
        {
            for (var index = handles.Count - 1; index >= 0; index--)
            {
                handles[index].Dispose();
            }

            throw;
        }
    }

    private static bool IsDirectorySharingConflict(UnsafeExtractionLocationException exception)
    {
        return exception.InnerException is Win32Exception { NativeErrorCode: 5 or 32 };
    }

    private static SafeFileHandle OpenLockedSourceDirectory(string path)
    {
        var handle = CreateFile(
            path,
            FileReadAttributes,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw UnsafeLocation(
                $"ZIP保存場所のdirectoryを安全に固定できませんでした（{path}）。",
                new Win32Exception(error));
        }

        if (!GetFileInformationByHandleEx(
                handle,
                fileInformationClass: 0,
                out var information,
                (uint)Marshal.SizeOf<FileBasicInfo>()))
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw UnsafeLocation(
                $"ZIP保存場所のdirectory実体を確認できませんでした（{path}）。",
                new Win32Exception(error));
        }

        if ((information.FileAttributes & (uint)FileAttributes.Directory) == 0 ||
            (information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
        {
            handle.Dispose();
            throw UnsafeLocation($"ZIP保存場所の階層にreparse pointがあります（{path}）。");
        }

        return handle;
    }

    private static string NormalizeDirectoryPath(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath);
        return string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase)
            ? fullPath
            : Path.TrimEndingDirectorySeparator(fullPath);
    }

    private static SecurityIdentifier GetCurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User
            ?? throw new UnauthorizedAccessException("現在のWindowsユーザーを特定できませんでした。");
    }

    private static string GetFinalLocalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (capacity <= MaxWindowsPathChars)
        {
            var buffer = new char[capacity];
            var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, flags: 0);
            if (length == 0)
            {
                throw UnsafeLocation(
                    "ZIPファイルの実体パスを確認できませんでした。",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }

            if (length < buffer.Length)
            {
                var finalPath = new string(buffer, 0, checked((int)length));
                if (finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ||
                    IsUncPath(finalPath))
                {
                    throw UnsafeLocation("ネットワーク上のZIP実体は安全に解凍できません。");
                }

                if (finalPath.StartsWith(@"\\?\", StringComparison.Ordinal))
                {
                    finalPath = finalPath[4..];
                }

                if (finalPath.Length < 3 ||
                    !char.IsAsciiLetter(finalPath[0]) ||
                    finalPath[1] != ':' ||
                    finalPath[2] is not '\\' and not '/')
                {
                    throw UnsafeLocation("ZIPファイルのローカルDOSパスを確認できませんでした。");
                }

                return Path.GetFullPath(finalPath);
            }

            if (length > MaxWindowsPathChars)
            {
                break;
            }

            capacity = checked((int)length + 1);
        }

        throw UnsafeLocation("ZIPファイルの実体パスが安全に処理できる長さを超えています。");
    }

    private static void ValidateLocalAclCapableVolume(string fullPath)
    {
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root) || IsUncPath(root))
        {
            throw UnsafeLocation("ZIPファイルのローカルボリュームを特定できませんでした。");
        }

        try
        {
            var drive = new DriveInfo(root);
            if (drive.DriveType == DriveType.Network)
            {
                throw UnsafeLocation("ネットワークドライブ上のZIPは安全に解凍できません。");
            }

            if (!drive.IsReady ||
                (!drive.DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase) &&
                 !drive.DriveFormat.Equals("ReFS", StringComparison.OrdinalIgnoreCase)))
            {
                throw UnsafeLocation("ZIPの保存先ファイルシステムがNTFS/ReFSではありません。");
            }
        }
        catch (UnsafeExtractionLocationException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw UnsafeLocation("ZIPの保存先ボリュームを安全に確認できませんでした。", ex);
        }
    }

    private static bool IsUncPath(string path)
    {
        var normalized = path.Replace('/', '\\');
        if (normalized.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            return normalized.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase);
        }

        return normalized.StartsWith(@"\\", StringComparison.Ordinal);
    }

    private static UnsafeExtractionLocationException UnsafeLocation(string message, Exception? innerException = null)
    {
        return new UnsafeExtractionLocationException(
            $"{message} ローカルのNTFS/ReFS（デスクトップやダウンロードなど）へZIPをコピーして、もう一度試してください。",
            innerException);
    }

    private static string GetUniqueOutputDirectory(string parent, string baseName)
    {
        if (string.IsNullOrEmpty(baseName))
        {
            baseName = "解凍したファイル";
        }

        var candidate = Path.Combine(parent, baseName);
        if (!Directory.Exists(candidate) && !File.Exists(candidate))
        {
            return candidate;
        }

        for (var index = 2; index < 10_000; index++)
        {
            candidate = Path.Combine(parent, $"{baseName}_{index}");
            if (!Directory.Exists(candidate) && !File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException("解凍先フォルダー名を作れませんでした。");
    }

    private static string DecodeEntryName(byte[] bytes, ushort flags)
    {
        try
        {
            return ((flags & Utf8Flag) != 0 ? Utf8 : Cp932).GetString(bytes);
        }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidDataException("ZIP内の項目名をUTF-8またはCP932として正しく読み取れません。", ex);
        }
    }

    private static Encoding CreateCp932Encoding()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        return Encoding.GetEncoding(932, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
    }

    private static string EnsureTrailingSeparator(string path)
    {
        return Path.EndsInDirectorySeparator(path) ? path : path + Path.DirectorySeparatorChar;
    }

    private static string FormatBytes(long bytes)
    {
        var gibibytes = bytes / 1024d / 1024d / 1024d;
        return gibibytes >= 1
            ? $"{gibibytes:0.##} GiB"
            : $"{bytes / 1024d / 1024d:0.##} MiB";
    }

    private static InvalidDataException InvalidZip(string message) => new(message);

    private static void ReadExactly(Stream stream, Span<byte> buffer)
    {
        try
        {
            stream.ReadExactly(buffer);
        }
        catch (EndOfStreamException ex)
        {
            throw new InvalidDataException("ZIPデータが途中で切れています。", ex);
        }
    }

    private static void SkipExactly(Stream stream, int byteCount)
    {
        if (byteCount == 0)
        {
            return;
        }

        if (!stream.CanSeek || stream.Position > stream.Length - byteCount)
        {
            throw InvalidZip("ZIPデータが途中で切れています。");
        }

        stream.Position += byteCount;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetDiskFreeSpaceExW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceEx(
        string directoryName,
        out ulong freeBytesAvailable,
        out ulong totalNumberOfBytes,
        out ulong totalNumberOfFreeBytes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateDirectoryW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string path, ref SecurityAttributes securityAttributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        [Out] char[] filePath,
        uint filePathLength,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        int fileInformationClass,
        out FileBasicInfo fileInformation,
        uint bufferSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr SecurityDescriptor;

        [MarshalAs(UnmanagedType.Bool)]
        internal bool InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInfo
    {
        internal long CreationTime;
        internal long LastAccessTime;
        internal long LastWriteTime;
        internal long ChangeTime;
        internal uint FileAttributes;
    }

    private sealed record CentralEntry(
        string Name,
        byte[] RawName,
        ushort Flags,
        ushort CompressionMethod,
        uint Crc32,
        long CompressedLength,
        long Length,
        uint ExternalAttributes,
        byte HostSystem,
        long LocalHeaderOffset,
        bool IsDirectory);

    private sealed record ValidatedEntry(string DestinationPath, bool IsDirectory);

    private readonly record struct EndOfCentralDirectory(
        long Offset,
        ushort DiskNumber,
        ushort DirectoryDiskNumber,
        ushort EntriesOnDisk,
        ushort TotalEntries,
        uint DirectorySize,
        uint DirectoryOffset);

    private readonly record struct DirectoryLocation(
        ulong EntryCount,
        ulong Size,
        ulong Offset,
        ulong BoundaryOffset);

    private readonly record struct Zip64Values(
        ulong UncompressedSize,
        ulong CompressedSize,
        ulong LocalHeaderOffset,
        uint DiskStart);

    private enum PathKind
    {
        ImplicitDirectory,
        ExplicitDirectory,
        File
    }

    private sealed class LockedDirectoryHandles(List<SafeFileHandle> handles) : IDisposable
    {
        private List<SafeFileHandle>? ownedHandles = handles;

        public void Dispose()
        {
            var handlesToDispose = Interlocked.Exchange(ref ownedHandles, null);
            if (handlesToDispose is null)
            {
                return;
            }

            for (var index = handlesToDispose.Count - 1; index >= 0; index--)
            {
                handlesToDispose[index].Dispose();
            }
        }
    }
}

internal static class Crc32Calculator
{
    internal const uint InitialValue = 0xFFFFFFFF;
    private static readonly uint[] Table = CreateTable();

    internal static uint Compute(ReadOnlySpan<byte> data) => Finalize(Update(InitialValue, data));

    internal static uint Update(uint crc, ReadOnlySpan<byte> data)
    {
        foreach (var value in data)
        {
            crc = Table[(crc ^ value) & 0xFF] ^ (crc >> 8);
        }

        return crc;
    }

    internal static uint Finalize(uint crc) => ~crc;

    private static uint[] CreateTable()
    {
        var table = new uint[256];
        for (uint index = 0; index < table.Length; index++)
        {
            var value = index;
            for (var bit = 0; bit < 8; bit++)
            {
                value = (value & 1) != 0 ? 0xEDB88320U ^ (value >> 1) : value >> 1;
            }

            table[index] = value;
        }

        return table;
    }
}

internal sealed class TooLargeArchiveException(string message) : Exception(message);

internal sealed class UnsafeExtractionLocationException : IOException
{
    internal UnsafeExtractionLocationException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}

internal sealed class ExtractionCleanupException : IOException
{
    internal ExtractionCleanupException(string tempDirectoryPath, Exception extractionError, Exception cleanupError)
        : base(
            $"解凍に失敗し、一時フォルダーも削除できませんでした: {tempDirectoryPath}",
            new AggregateException(extractionError, cleanupError))
    {
        TempDirectoryPath = tempDirectoryPath;
    }

    internal string TempDirectoryPath { get; }
}
