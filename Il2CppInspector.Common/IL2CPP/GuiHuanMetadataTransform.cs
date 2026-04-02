using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;

namespace Il2CppInspector
{
    internal static class GuiHuanMetadataTransform
    {
        private const uint RawSanity = 0x214E4D46;
        private const uint StandardSanity = 0xFAB11BAF;
        private const uint MetadataVersion = 31;
        private const int ProbeDwordCount = 14;
        private const int AssemblyDefinitionSize = 0x40;
        private const int AssemblyPublicKeyIndexOffset = 24;
        private const int AssemblyFlagsOffset = 36;
        private const uint AssemblyNameFlagsPublicKey = 0x1;
        private const int FieldDefinitionSize = 0x0C;
        private const int TypeDefinitionFieldStartOffset = 0x20;
        private const int TypeDefinitionMethodStartOffset = 0x24;
        private const int TypeDefinitionMethodCountOffset = 0x40;
        private const int TypeDefinitionFieldCountOffset = 0x44;
        private const ulong StringTableVa = 0x187E48390;

        private static readonly uint[] ChaChaConstants = [0xA5202E99, 0xD7C2E4B2, 0x34C2418A, 0xF98AAB49];

        private static readonly byte[] HeaderKey =
        [
            0xF5, 0xEE, 0xE0, 0x3C, 0x40, 0x3E, 0xEE, 0x71, 0x86, 0xD9, 0x51, 0x27, 0x5A, 0x36, 0x2F, 0x5E,
            0x62, 0x43, 0x62, 0x5B, 0x79, 0xC2, 0x58, 0xE2, 0x2B, 0x99, 0x78, 0x7C, 0x40, 0x43, 0xD5, 0xAC
        ];

        private static readonly Regex ModuleNameRegex = new("[A-Za-z0-9_.]+\\.dll", RegexOptions.Compiled);
        private static readonly string[] RuntimeContentCatalogFieldFingerprint =
        [
            "ManagedStrings",
            "ArchiveLocations",
            "FileLocations",
            "ObjectLocations",
            "SceneLocations",
            "FileDependencies"
        ];

        private static readonly string[] RuntimeContentCatalogMethodFingerprint =
        [
            "LoadCatalogData",
            "AddArchiveLocations",
            "AddFileLocations",
            "AddObjectLocations",
            "AddSceneLocations",
            "TryGetArchiveLocation"
        ];

        private static readonly string[] RuntimeContentCatalogDataFieldFingerprint =
        [
            "Archives",
            "Files",
            "Objects",
            "Scenes",
            "Dependencies"
        ];

        public static bool TryTransform(byte[] metadataBytes, Stream binaryStream, EventHandler<string> statusCallback, out byte[] transformedBytes)
        {
            transformedBytes = null;
            if (!LooksLikeRawHeader(metadataBytes))
                return false;

            var binaryBytes = ReadAllBytes(binaryStream);
            var stringTable = LoadStringTable(binaryBytes);
            if (stringTable == null)
                return false;

            var data = metadataBytes.ToArray();
            statusCallback?.Invoke(null, "Applying built-in GuiHuan raw metadata transform");

            WriteUInt32(data, 0, StandardSanity);
            ApplyCustomChaCha(data, 8, 0x20, HeaderKey, 0);

            var headerWords = ReadHeaderDwords(data);
            if (!IsGuiHuanPermutedHeader(headerWords))
                return false;

            WriteHeaderDwords(data, NormalizeHeader(headerWords));
            DecryptMetadataStrings(data, stringTable);
            DecryptStringLiterals(data, stringTable);
            RepairTypeNames(data);
            RepairJobReflectionNames(data);
            RepairModuleNames(data, binaryBytes);
            ScrubInvalidPublicKeyFlags(data);

            transformedBytes = data;
            return true;
        }

        private static bool LooksLikeRawHeader(byte[] data) => data.Length >= 0x28 && ReadUInt32(data, 0) == RawSanity && ReadUInt32(data, 4) == MetadataVersion;

        private static uint[] ReadHeaderDwords(byte[] data)
        {
            var words = new uint[ProbeDwordCount];
            for (var i = 0; i < words.Length; i++)
                words[i] = ReadUInt32(data, i * 4);
            return words;
        }

        private static void WriteHeaderDwords(byte[] data, IReadOnlyList<uint> words)
        {
            for (var i = 0; i < ProbeDwordCount; i++)
                WriteUInt32(data, i * 4, words[i]);
        }

        private static bool IsGuiHuanPermutedHeader(IReadOnlyList<uint> words)
        {
            if (words.Count < ProbeDwordCount || words[0] != StandardSanity || words[1] != MetadataVersion)
                return false;

            var eventsOffset = words[2];
            var eventsSize = words[3];
            var stringLiteralDataSize = words[4];
            var stringLiteralOffset = words[5];
            var stringLiteralDataOffset = words[6];
            var stringOffset = words[7];
            var stringSize = words[8];
            var stringLiteralSize = words[9];
            var propertiesOffset = words[10];
            var propertiesSize = words[11];
            var methodsOffset = words[12];

            return stringLiteralOffset == 0x100
                   && stringLiteralOffset + stringLiteralSize == stringLiteralDataOffset
                   && stringLiteralDataOffset + stringLiteralDataSize == stringOffset
                   && stringOffset + stringSize == eventsOffset
                   && eventsOffset + eventsSize == propertiesOffset
                   && propertiesOffset + propertiesSize == methodsOffset;
        }

        private static uint[] NormalizeHeader(IReadOnlyList<uint> words)
        {
            var normalized = words.ToArray();
            normalized[2] = words[5];
            normalized[3] = words[9];
            normalized[4] = words[6];
            normalized[5] = words[4];
            normalized[6] = words[7];
            normalized[7] = words[8];
            normalized[8] = words[2];
            normalized[9] = words[3];
            return normalized;
        }

        private static void ApplyCustomChaCha(byte[] data, int offset, int count, byte[] keyData, ulong initialCounter)
        {
            Span<uint> state = stackalloc uint[16];
            for (var i = 0; i < ChaChaConstants.Length; i++)
                state[i] = ChaChaConstants[i];
            for (var i = 0; i < 8; i++)
                state[4 + i] = ReadUInt32(keyData, i * 4);

            state[14] = ReadUInt32(keyData, 0);
            state[15] = ReadUInt32(keyData, 4);

            Span<byte> block = stackalloc byte[64];
            ulong counter = initialCounter;
            for (var consumed = 0; consumed < count; consumed += 64, counter++)
            {
                state[12] = (uint)counter;
                state[13] = (uint)(counter >> 32);
                ChaChaBlock(state, block);
                var chunk = System.Math.Min(64, count - consumed);
                for (var i = 0; i < chunk; i++)
                    data[offset + consumed + i] ^= block[i];
            }
        }

        private static void ChaChaBlock(ReadOnlySpan<uint> state, Span<byte> output)
        {
            Span<uint> working = stackalloc uint[16];
            state.CopyTo(working);

            for (var i = 0; i < 10; i++)
            {
                QuarterRound(ref working[0], ref working[4], ref working[8], ref working[12]);
                QuarterRound(ref working[1], ref working[5], ref working[9], ref working[13]);
                QuarterRound(ref working[2], ref working[6], ref working[10], ref working[14]);
                QuarterRound(ref working[3], ref working[7], ref working[11], ref working[15]);
                QuarterRound(ref working[0], ref working[5], ref working[10], ref working[15]);
                QuarterRound(ref working[1], ref working[6], ref working[11], ref working[12]);
                QuarterRound(ref working[2], ref working[7], ref working[8], ref working[13]);
                QuarterRound(ref working[3], ref working[4], ref working[9], ref working[14]);
            }

            for (var i = 0; i < 16; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(i * 4, 4), unchecked(working[i] + state[i]));
        }

        private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d = RotateLeft(d ^ a, 16);
            c += d; b = RotateLeft(b ^ c, 12);
            a += b; d = RotateLeft(d ^ a, 8);
            c += d; b = RotateLeft(b ^ c, 7);
        }

        private static uint RotateLeft(uint value, int bits) => (value << bits) | (value >> (32 - bits));

        private static byte[] ReadAllBytes(Stream stream)
        {
            if (stream == null || !stream.CanSeek)
                return null;

            var originalPosition = stream.Position;
            try
            {
                stream.Position = 0;
                using var copy = new MemoryStream();
                stream.CopyTo(copy);
                return copy.ToArray();
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        private static byte[] LoadStringTable(byte[] binaryBytes)
        {
            if (binaryBytes == null || binaryBytes.Length < 0x100)
                return null;

            try
            {
                var peOffset = (int)ReadUInt32(binaryBytes, 0x3C);
                var optionalHeaderOffset = peOffset + 24;
                var optionalHeaderMagic = ReadUInt16(binaryBytes, optionalHeaderOffset);
                ulong imageBase = optionalHeaderMagic switch
                {
                    0x20B => BinaryPrimitives.ReadUInt64LittleEndian(binaryBytes.AsSpan(optionalHeaderOffset + 24, 8)),
                    0x10B => ReadUInt32(binaryBytes, optionalHeaderOffset + 28),
                    _ => 0
                };
                if (imageBase == 0 || StringTableVa < imageBase)
                    return null;

                var sectionCount = ReadUInt16(binaryBytes, peOffset + 6);
                var optionalHeaderSize = ReadUInt16(binaryBytes, peOffset + 20);
                var sectionOffset = peOffset + 24 + optionalHeaderSize;
                var rva = (int)(StringTableVa - imageBase);
                var fileOffset = RvaToFileOffset(binaryBytes, rva, sectionOffset, sectionCount);
                if (fileOffset < 0)
                    return null;

                for (var i = 0; i < sectionCount; i++)
                {
                    var current = sectionOffset + i * 40;
                    var rawSize = (int)ReadUInt32(binaryBytes, current + 16);
                    var rawOffset = (int)ReadUInt32(binaryBytes, current + 20);
                    if (rawOffset <= fileOffset && fileOffset < rawOffset + rawSize)
                        return binaryBytes.Skip(fileOffset).Take(rawOffset + rawSize - fileOffset).ToArray();
                }
            }
            catch
            {
                return null;
            }

            return null;
        }

        private static int RvaToFileOffset(byte[] peData, int rva, int sectionOffset, int sectionCount)
        {
            for (var i = 0; i < sectionCount; i++)
            {
                var current = sectionOffset + i * 40;
                var virtualSize = (int)ReadUInt32(peData, current + 8);
                var virtualAddress = (int)ReadUInt32(peData, current + 12);
                var rawSize = (int)ReadUInt32(peData, current + 16);
                var rawOffset = (int)ReadUInt32(peData, current + 20);
                var mappedSize = System.Math.Max(virtualSize, rawSize);
                if (virtualAddress <= rva && rva < virtualAddress + mappedSize)
                    return rawOffset + (rva - virtualAddress);
            }

            return -1;
        }

        private static void DecryptMetadataStrings(byte[] data, byte[] stringTable)
        {
            var source = data.ToArray();
            var stringOffset = (int)ReadUInt32(data, 0x18);
            var stringSize = (int)ReadUInt32(data, 0x1C);
            var starts = CollectConfirmedStringIndices(data);
            starts.Add(0);
            starts.Sort();

            for (var i = 0; i < starts.Count; i++)
            {
                var start = starts[i];
                var limit = i + 1 < starts.Count ? starts[i + 1] : stringSize;
                var current = start;
                while (current < limit)
                {
                    if (!DecryptMetadataStringAt(data, source, stringTable, stringOffset, stringSize, current, limit, out var next))
                    {
                        data[stringOffset + limit - 1] = 0;
                        break;
                    }

                    current = next;
                }
            }
        }

        private static bool DecryptMetadataStringAt(byte[] destination, byte[] source, byte[] stringTable, int stringOffset, int stringSize, int index, int limit, out int nextIndex)
        {
            nextIndex = index;
            if ((uint)index >= (uint)stringSize)
                return false;

            var absolute = stringOffset + index;
            if ((uint)absolute >= (uint)destination.Length)
                return false;

            var mixed = unchecked((uint)((index + stringOffset) * stringSize));
            var keyIndex = 0x10 * (int)((mixed % 0x11D53u) & 0xFu);
            for (var delta = 0; index + delta < limit && index + delta < stringSize; delta++)
            {
                var cursor = absolute + delta;
                if ((uint)cursor >= (uint)destination.Length || keyIndex + delta >= stringTable.Length)
                    break;

                var value = (byte)(source[cursor] ^ stringTable[keyIndex + delta]);
                destination[cursor] = value;
                if (value == 0)
                {
                    nextIndex = index + delta + 1;
                    return true;
                }
            }

            return false;
        }

        private static void DecryptStringLiterals(byte[] data, byte[] stringTable)
        {
            var source = data.ToArray();
            var stringLiteralOffset = (int)ReadUInt32(data, 0x08);
            var stringLiteralSize = (int)ReadUInt32(data, 0x0C);
            var stringLiteralDataOffset = (int)ReadUInt32(data, 0x10);
            var stringLiteralDataSize = (int)ReadUInt32(data, 0x14);

            for (var literalIndex = 0; literalIndex < stringLiteralSize / 8; literalIndex++)
            {
                var entryOffset = stringLiteralOffset + literalIndex * 8;
                var length = (int)ReadUInt32(data, entryOffset);
                var dataIndex = (int)ReadUInt32(data, entryOffset + 4);
                if (length <= 0 || dataIndex < 0 || dataIndex + length > stringLiteralDataSize)
                    continue;

                var keyIndex = 0x100 + 0x10 * ((literalIndex + length * dataIndex) & 0xF);
                for (var i = 0; i < length; i++)
                {
                    var sourceOffset = stringLiteralDataOffset + dataIndex + i;
                    if ((uint)sourceOffset >= (uint)data.Length || keyIndex + i >= stringTable.Length)
                        break;

                    data[sourceOffset] = (byte)(source[sourceOffset] ^ stringTable[keyIndex + i]);
                }
            }
        }

        private static List<int> CollectConfirmedStringIndices(byte[] data)
        {
            var indices = new HashSet<int>();
            var stringSize = (int)ReadUInt32(data, 0x1C);
            var imagesOffset = (int)ReadUInt32(data, 0xA8);
            var imagesSize = (int)ReadUInt32(data, 0xAC);
            var assembliesOffset = (int)ReadUInt32(data, 0xB0);
            var assembliesSize = (int)ReadUInt32(data, 0xB4);
            var typesOffset = (int)ReadUInt32(data, 0xA0);
            var typesSize = (int)ReadUInt32(data, 0xA4);
            var methodsOffset = (int)ReadUInt32(data, 0x30);
            var methodsSize = (int)ReadUInt32(data, 0x34);
            var parametersOffset = (int)ReadUInt32(data, 0x58);
            var parametersSize = (int)ReadUInt32(data, 0x5C);
            var fieldsOffset = (int)ReadUInt32(data, 0x60);
            var fieldsSize = (int)ReadUInt32(data, 0x64);
            var genericParametersOffset = (int)ReadUInt32(data, 0x68);
            var genericParametersSize = (int)ReadUInt32(data, 0x6C);
            var eventsOffset = (int)ReadUInt32(data, 0x20);
            var eventsSize = (int)ReadUInt32(data, 0x24);
            var propertiesOffset = (int)ReadUInt32(data, 0x28);
            var propertiesSize = (int)ReadUInt32(data, 0x2C);

            void AddIndex(uint value)
            {
                if (value < stringSize)
                    indices.Add((int)value);
            }

            for (var offset = imagesOffset; offset < imagesOffset + imagesSize; offset += 0x28)
                AddIndex(ReadUInt32(data, offset));

            for (var offset = assembliesOffset; offset < assembliesOffset + assembliesSize; offset += AssemblyDefinitionSize)
            {
                AddIndex(ReadUInt32(data, offset + 16));
                AddIndex(ReadUInt32(data, offset + 20));
                AddIndex(ReadUInt32(data, offset + 24));
            }

            for (var offset = typesOffset; offset < typesOffset + typesSize; offset += 0x58)
            {
                AddIndex(ReadUInt32(data, offset));
                AddIndex(ReadUInt32(data, offset + 4));
            }

            for (var offset = methodsOffset; offset < methodsOffset + methodsSize; offset += 0x24)
                AddIndex(ReadUInt32(data, offset));

            for (var offset = parametersOffset; offset < parametersOffset + parametersSize; offset += 0x0C)
                AddIndex(ReadUInt32(data, offset));

            for (var offset = fieldsOffset; offset < fieldsOffset + fieldsSize; offset += 0x0C)
                AddIndex(ReadUInt32(data, offset));

            for (var offset = genericParametersOffset; offset < genericParametersOffset + genericParametersSize; offset += 0x10)
                AddIndex(ReadUInt32(data, offset + 4));

            for (var offset = eventsOffset; offset < eventsOffset + eventsSize; offset += 0x18)
                AddIndex(ReadUInt32(data, offset));

            for (var offset = propertiesOffset; offset < propertiesOffset + propertiesSize; offset += 0x14)
                AddIndex(ReadUInt32(data, offset));

            return indices.OrderBy(x => x).ToList();
        }

        private static void RepairTypeNames(byte[] data)
        {
            var stringOffset = (int)ReadUInt32(data, 0x18);
            var stringSize = (int)ReadUInt32(data, 0x1C);
            var fieldsOffset = (int)ReadUInt32(data, 0x60);
            var fieldsSize = (int)ReadUInt32(data, 0x64);
            var typesOffset = (int)ReadUInt32(data, 0xA0);
            var typesSize = (int)ReadUInt32(data, 0xA4);
            var methodsOffset = (int)ReadUInt32(data, 0x30);
            var methodsSize = (int)ReadUInt32(data, 0x34);
            var heapStarts = IterHeapStringStarts(data, stringOffset, stringSize);
            var methodPrefixMap = BuildMethodPrefixMap(data, stringOffset, stringSize, heapStarts);

            for (var offset = typesOffset; offset < typesOffset + typesSize; offset += 0x58)
            {
                var nameIndex = (int)ReadUInt32(data, offset);
                var currentName = ReadHeapString(data, stringOffset, stringSize, nameIndex);
                if (!NeedsTypeNameRepair(currentName))
                    continue;

                if (TryRepairKnownRuntimeContentTypeName(data, stringOffset, stringSize, fieldsOffset, fieldsSize, methodsOffset, methodsSize, offset, out var fingerprintName))
                {
                    WriteHeapString(data, stringOffset, stringSize, heapStarts, nameIndex, fingerprintName);
                    continue;
                }

                var hint = ExtractIdentifierHint(currentName);
                if (hint.Length < 6)
                    continue;

                var methodStart = (int)ReadUInt32(data, offset + TypeDefinitionMethodStartOffset);
                var methodCount = ReadUInt16(data, offset + TypeDefinitionMethodCountOffset);
                if (methodCount == 0 || methodStart < 0 || methodsOffset + methodStart * 0x24 >= methodsOffset + methodsSize)
                    continue;

                var bestCandidate = string.Empty;
                var bestScore = int.MinValue;
                for (var methodIndex = methodStart; methodIndex < methodStart + methodCount; methodIndex++)
                {
                    var methodBase = methodsOffset + methodIndex * 0x24;
                    if (methodBase + 0x24 > methodsOffset + methodsSize)
                        break;

                    var methodNameIndex = (int)ReadUInt32(data, methodBase);
                    var methodName = ReadHeapString(data, stringOffset, stringSize, methodNameIndex);
                    if (!methodPrefixMap.TryGetValue(methodName, out var candidates))
                        continue;

                    foreach (var candidate in candidates)
                    {
                        foreach (var typeNameCandidate in EnumerateTypeNameCandidates(candidate))
                        {
                            var prefix = CommonPrefixLength(typeNameCandidate, hint);
                            if (prefix < System.Math.Max(6, hint.Length - 3))
                                continue;

                            var score = prefix * 100 - typeNameCandidate.Length;
                            if (score > bestScore)
                            {
                                bestScore = score;
                                bestCandidate = typeNameCandidate;
                            }
                        }
                    }
                }

                if (bestCandidate.Length == 0)
                    continue;

                WriteHeapString(data, stringOffset, stringSize, heapStarts, nameIndex, bestCandidate);
            }
        }

        private static bool TryRepairKnownRuntimeContentTypeName(byte[] data, int stringOffset, int stringSize, int fieldsOffset, int fieldsSize, int methodsOffset, int methodsSize, int typeOffset, out string repairedName)
        {
            repairedName = string.Empty;

            var fieldNames = ReadTypeFieldNames(data, stringOffset, stringSize, fieldsOffset, fieldsSize, typeOffset);
            if (ContainsAll(fieldNames, RuntimeContentCatalogDataFieldFingerprint))
            {
                repairedName = "RuntimeContentCatalogData";
                return true;
            }

            if (!ContainsAll(fieldNames, RuntimeContentCatalogFieldFingerprint))
                return false;

            var methodNames = ReadTypeMethodNames(data, stringOffset, stringSize, methodsOffset, methodsSize, typeOffset);
            if (!ContainsAll(methodNames, RuntimeContentCatalogMethodFingerprint))
                return false;

            repairedName = "RuntimeContentCatalog";
            return true;
        }

        private static IEnumerable<string> EnumerateTypeNameCandidates(string candidate)
        {
            yield return candidate;

            for (var i = 1; i < candidate.Length; i++)
            {
                if (candidate[i] is < 'A' or > 'Z')
                    continue;

                var suffix = candidate[i..];
                if (LooksLikeTypeName(suffix))
                    yield return suffix;
            }
        }

        private static Dictionary<string, HashSet<string>> BuildMethodPrefixMap(byte[] data, int stringOffset, int stringSize, IReadOnlyList<int> heapStarts)
        {
            var map = new Dictionary<string, HashSet<string>>(System.StringComparer.Ordinal);
            foreach (var start in heapStarts)
            {
                var value = ReadHeapString(data, stringOffset, stringSize, start);
                if (value.Length < 4 || value[^1] != '0')
                    continue;

                var separator = value.LastIndexOf('-');
                if (separator <= 0 || separator >= value.Length - 2)
                    continue;

                var prefix = value[..separator];
                if (!LooksLikeTypeName(prefix))
                    continue;

                var memberName = value.Substring(separator + 1, value.Length - separator - 2);
                if (memberName.Length == 0)
                    continue;

                if (!map.TryGetValue(memberName, out var prefixes))
                {
                    prefixes = new HashSet<string>(System.StringComparer.Ordinal);
                    map.Add(memberName, prefixes);
                }

                prefixes.Add(prefix);
            }

            return map;
        }

        private static HashSet<string> ReadTypeFieldNames(byte[] data, int stringOffset, int stringSize, int fieldsOffset, int fieldsSize, int typeOffset)
        {
            var names = new HashSet<string>(System.StringComparer.Ordinal);
            var fieldStart = (int)ReadUInt32(data, typeOffset + TypeDefinitionFieldStartOffset);
            var fieldCount = ReadUInt16(data, typeOffset + TypeDefinitionFieldCountOffset);
            for (var fieldIndex = fieldStart; fieldIndex < fieldStart + fieldCount; fieldIndex++)
            {
                var fieldBase = fieldsOffset + fieldIndex * FieldDefinitionSize;
                if (fieldIndex < 0 || fieldBase < fieldsOffset || fieldBase + FieldDefinitionSize > fieldsOffset + fieldsSize)
                    break;

                var nameIndex = (int)ReadUInt32(data, fieldBase);
                names.Add(ReadHeapString(data, stringOffset, stringSize, nameIndex));
            }

            return names;
        }

        private static HashSet<string> ReadTypeMethodNames(byte[] data, int stringOffset, int stringSize, int methodsOffset, int methodsSize, int typeOffset)
        {
            var names = new HashSet<string>(System.StringComparer.Ordinal);
            var methodStart = (int)ReadUInt32(data, typeOffset + TypeDefinitionMethodStartOffset);
            var methodCount = ReadUInt16(data, typeOffset + TypeDefinitionMethodCountOffset);
            for (var methodIndex = methodStart; methodIndex < methodStart + methodCount; methodIndex++)
            {
                var methodBase = methodsOffset + methodIndex * 0x24;
                if (methodIndex < 0 || methodBase < methodsOffset || methodBase + 0x24 > methodsOffset + methodsSize)
                    break;

                var nameIndex = (int)ReadUInt32(data, methodBase);
                names.Add(ReadHeapString(data, stringOffset, stringSize, nameIndex));
            }

            return names;
        }

        private static bool ContainsAll(HashSet<string> values, IEnumerable<string> required)
            => required.All(values.Contains);

        private static void RepairJobReflectionNames(byte[] data)
        {
            var stringOffset = (int)ReadUInt32(data, 0x18);
            var stringSize = (int)ReadUInt32(data, 0x1C);
            var fieldsOffset = (int)ReadUInt32(data, 0x60);
            var fieldsSize = (int)ReadUInt32(data, 0x64);
            var heapStarts = IterHeapStringStarts(data, stringOffset, stringSize);
            var suffixCounts = new Dictionary<string, int>(System.StringComparer.Ordinal);

            foreach (var start in heapStarts)
            {
                var value = ReadHeapString(data, stringOffset, stringSize, start);
                if (!TryParseJobReflectionName(value, out _, out var suffix))
                    continue;

                if (!LooksLikeCleanIdentifierWithSuffix(suffix))
                    continue;

                suffixCounts.TryGetValue(suffix, out var count);
                suffixCounts[suffix] = count + 1;
            }

            for (var offset = fieldsOffset; offset < fieldsOffset + fieldsSize; offset += 0x0C)
            {
                var nameIndex = (int)ReadUInt32(data, offset);
                var currentName = ReadHeapString(data, stringOffset, stringSize, nameIndex);
                if (!TryParseJobReflectionName(currentName, out var prefix, out var suffixHint))
                    continue;
                if (LooksLikeCleanIdentifierWithSuffix(suffixHint))
                    continue;

                var hint = ExtractIdentifierHint(suffixHint);
                if (hint.Length < 2)
                    continue;

                var bestSuffix = string.Empty;
                var bestScore = int.MinValue;
                foreach (var (candidateSuffix, frequency) in suffixCounts)
                {
                    if (!candidateSuffix.StartsWith(hint, System.StringComparison.Ordinal))
                        continue;

                    var score = frequency * 100 + CommonPrefixLength(candidateSuffix, hint) * 10 - candidateSuffix.Length;
                    if (score > bestScore)
                    {
                        bestScore = score;
                        bestSuffix = candidateSuffix;
                    }
                }

                if (bestSuffix.Length == 0)
                    continue;

                WriteHeapString(data, stringOffset, stringSize, heapStarts, nameIndex, $"{prefix}-{bestSuffix}");
            }
        }

        private static bool TryParseJobReflectionName(string value, out string prefix, out string suffix)
        {
            const string marker = "__JobReflectionRegistrationOutput__";
            prefix = string.Empty;
            suffix = string.Empty;

            if (!value.StartsWith(marker, System.StringComparison.Ordinal))
                return false;

            var separator = value.IndexOf('-', marker.Length);
            if (separator < 0 || separator + 1 >= value.Length)
                return false;

            prefix = value[..separator];
            suffix = value[(separator + 1)..];
            return true;
        }

        private static bool NeedsTypeNameRepair(string value)
        {
            if (value.Length == 0)
                return false;

            foreach (var c in value)
            {
                if ((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c is '_' or '`')
                    continue;

                return true;
            }

            return false;
        }

        private static bool LooksLikeTypeName(string value)
        {
            if (value.Length == 0)
                return false;

            foreach (var c in value)
            {
                if ((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c is '_' or '`')
                    continue;

                return false;
            }

            return true;
        }

        private static bool LooksLikeCleanIdentifierWithSuffix(string value)
        {
            if (value.Length < 2 || value[^1] != '0')
                return false;

            for (var i = 0; i < value.Length - 1; i++)
            {
                var c = value[i];
                if ((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '_')
                    continue;

                return false;
            }

            return true;
        }

        private static string ExtractIdentifierHint(string value)
        {
            var builder = new StringBuilder(value.Length);
            foreach (var c in value)
            {
                if ((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c is '_' or '`')
                {
                    builder.Append(c);
                    continue;
                }

                break;
            }

            return builder.ToString();
        }

        private static void RepairModuleNames(byte[] data, byte[] binaryBytes)
        {
            var moduleNames = ExtractModuleNames(binaryBytes);
            if (moduleNames.Count == 0)
                return;

            var stringOffset = (int)ReadUInt32(data, 0x18);
            var stringSize = (int)ReadUInt32(data, 0x1C);
            var imagesOffset = (int)ReadUInt32(data, 0xA8);
            var imagesSize = (int)ReadUInt32(data, 0xAC);
            var assembliesOffset = (int)ReadUInt32(data, 0xB0);
            var assembliesSize = (int)ReadUInt32(data, 0xB4);
            var heapStarts = IterHeapStringStarts(data, stringOffset, stringSize);
            var moduleNameSet = new HashSet<string>(moduleNames, System.StringComparer.Ordinal);

            var imageCount = System.Math.Min(imagesSize / 0x28, assembliesSize / AssemblyDefinitionSize);
            for (var i = 0; i < imageCount; i++)
            {
                var imageBase = imagesOffset + i * 0x28;
                var assemblyBase = assembliesOffset + i * AssemblyDefinitionSize;
                var imageNameIndex = (int)ReadUInt32(data, imageBase);
                var assemblyNameIndex = (int)ReadUInt32(data, assemblyBase + 16);
                var imageName = ReadHeapString(data, stringOffset, stringSize, imageNameIndex);
                var assemblyName = ReadHeapString(data, stringOffset, stringSize, assemblyNameIndex);

                if (moduleNameSet.Contains(imageName) && assemblyName == imageName[..^4])
                    continue;

                var probe = imageName.EndsWith(".dll", System.StringComparison.OrdinalIgnoreCase) ? imageName : assemblyName + ".dll";
                var bestName = string.Empty;
                var bestScore = 0.0;
                var bestPrefix = 0;

                foreach (var moduleName in moduleNames)
                {
                    var score = Similarity(probe, moduleName);
                    var prefix = CommonPrefixLength(probe, moduleName);
                    if (score > bestScore)
                    {
                        bestName = moduleName;
                        bestScore = score;
                        bestPrefix = prefix;
                    }
                }

                if (bestScore < 0.95 && !(bestScore >= 0.90 && bestPrefix >= 20))
                    continue;

                if (!WriteHeapString(data, stringOffset, stringSize, heapStarts, imageNameIndex, bestName))
                    continue;

                WriteHeapString(data, stringOffset, stringSize, heapStarts, assemblyNameIndex, bestName[..^4]);
            }
        }

        private static List<string> ExtractModuleNames(byte[] binaryBytes)
            => ModuleNameRegex.Matches(Encoding.ASCII.GetString(binaryBytes))
                .Cast<Match>()
                .Select(match => match.Value)
                .Where(value => value.Length >= 5)
                .Distinct(System.StringComparer.Ordinal)
                .OrderBy(value => value, System.StringComparer.Ordinal)
                .ToList();

        private static List<int> IterHeapStringStarts(byte[] data, int stringOffset, int stringSize)
        {
            var starts = new List<int> { 0 };
            var cursor = 0;
            var end = stringOffset + stringSize;
            while (cursor < stringSize)
            {
                var zero = System.Array.IndexOf(data, (byte)0, stringOffset + cursor, end - (stringOffset + cursor));
                if (zero < 0)
                    break;
                cursor = zero - stringOffset + 1;
                if (cursor < stringSize)
                    starts.Add(cursor);
            }

            return starts.Distinct().OrderBy(x => x).ToList();
        }

        private static string ReadHeapString(byte[] data, int stringOffset, int stringSize, int index)
        {
            var end = System.Array.IndexOf(data, (byte)0, stringOffset + index, stringSize - index);
            if (end < 0)
                end = stringOffset + stringSize;
            return Encoding.Latin1.GetString(data, stringOffset + index, end - (stringOffset + index));
        }

        private static bool WriteHeapString(byte[] data, int stringOffset, int stringSize, IReadOnlyList<int> starts, int index, string value)
        {
            var nextStart = stringSize;
            foreach (var start in starts)
            {
                if (start > index)
                {
                    nextStart = start;
                    break;
                }
            }

            var encoded = Encoding.ASCII.GetBytes(value + "\0");
            if (encoded.Length > nextStart - index)
                return false;

            Buffer.BlockCopy(encoded, 0, data, stringOffset + index, encoded.Length);
            return true;
        }

        private static void ScrubInvalidPublicKeyFlags(byte[] data)
        {
            var assembliesOffset = (int)ReadUInt32(data, 0xB0);
            var assembliesSize = (int)ReadUInt32(data, 0xB4);
            var stringOffset = (int)ReadUInt32(data, 0x18);
            var stringSize = (int)ReadUInt32(data, 0x1C);

            for (var offset = assembliesOffset; offset < assembliesOffset + assembliesSize; offset += AssemblyDefinitionSize)
            {
                var flagsOffset = offset + AssemblyFlagsOffset;
                var flags = ReadUInt32(data, flagsOffset);
                if ((flags & AssemblyNameFlagsPublicKey) == 0)
                    continue;

                var publicKeyIndex = (int)ReadUInt32(data, offset + AssemblyPublicKeyIndexOffset);
                var absoluteOffset = stringOffset + publicKeyIndex;
                if (publicKeyIndex < 0 || publicKeyIndex >= stringSize || absoluteOffset >= data.Length)
                {
                    WriteUInt32(data, flagsOffset, flags & ~AssemblyNameFlagsPublicKey);
                    continue;
                }

                if (!TryReadCompressedUInt(data, absoluteOffset, out var length, out var nextOffset)
                    || nextOffset + length > stringOffset + stringSize
                    || nextOffset + length > data.Length)
                {
                    WriteUInt32(data, flagsOffset, flags & ~AssemblyNameFlagsPublicKey);
                }
            }
        }

        private static bool TryReadCompressedUInt(byte[] data, int offset, out int value, out int nextOffset)
        {
            value = 0;
            nextOffset = offset;
            if (offset >= data.Length)
                return false;

            var first = data[offset];
            if ((first & 0b1000_0000) == 0)
            {
                value = first;
                nextOffset = offset + 1;
                return true;
            }

            if ((first & 0b1100_0000) == 0b1000_0000 && offset + 1 < data.Length)
            {
                value = ((first & ~0b1000_0000) << 8) | data[offset + 1];
                nextOffset = offset + 2;
                return true;
            }

            if ((first & 0b1110_0000) == 0b1100_0000 && offset + 3 < data.Length)
            {
                value = ((first & ~0b1100_0000) << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
                nextOffset = offset + 4;
                return true;
            }

            if (first == 0b1111_0000 && offset + 4 < data.Length)
            {
                value = (int)ReadUInt32(data, offset + 1);
                nextOffset = offset + 5;
                return true;
            }

            if (first == 0b1111_1110)
            {
                value = unchecked((int)0xFFFFFFFEu);
                nextOffset = offset + 1;
                return true;
            }

            if (first == 0b1111_1111)
            {
                value = unchecked((int)0xFFFFFFFFu);
                nextOffset = offset + 1;
                return true;
            }

            return false;
        }

        private static int CommonPrefixLength(string left, string right)
        {
            var length = 0;
            while (length < left.Length && length < right.Length && left[length] == right[length])
                length++;
            return length;
        }

        private static double Similarity(string left, string right)
        {
            if (left.Length == 0 && right.Length == 0)
                return 1.0;

            var distance = LevenshteinDistance(left, right);
            return 1.0 - (double)distance / System.Math.Max(left.Length, right.Length);
        }

        private static int LevenshteinDistance(string left, string right)
        {
            var costs = new int[right.Length + 1];
            for (var j = 0; j < costs.Length; j++)
                costs[j] = j;

            for (var i = 1; i <= left.Length; i++)
            {
                var diagonal = costs[0];
                costs[0] = i;
                for (var j = 1; j <= right.Length; j++)
                {
                    var previous = costs[j];
                    var substitution = left[i - 1] == right[j - 1] ? 0 : 1;
                    costs[j] = System.Math.Min(System.Math.Min(costs[j] + 1, costs[j - 1] + 1), diagonal + substitution);
                    diagonal = previous;
                }
            }

            return costs[right.Length];
        }

        private static ushort ReadUInt16(byte[] data, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2));
        private static uint ReadUInt32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
        private static void WriteUInt32(byte[] data, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset, 4), value);
    }
}
