import struct
import string
from PIL import Image

class XBE:
    m_file = None

    def __init__(self, file):
        self.m_file = open(file, 'rb').read()

        # Load XBE Header
        self.header = XBE_HEADER(self.m_file)
        self.cert   = XBE_CERT(self.m_file[self.header.dwCertificateAddr - self.header.dwBaseAddr:len(self.m_file)])

        # Load XBE Section Headers
        self.sections = []
        for x in range(0, self.header.dwSections):
            self.sections.append(XBE_SECTION(self.m_file[self.header.dwSectionHeadersAddr - self.header.dwBaseAddr + (x * 56):len(self.m_file)], self.m_file))

        # Load XBE Section Names
        for section in self.sections:
            section.name = struct.unpack('8s', self.m_file[section.dwSectionNameAddr - self.header.dwBaseAddr:
                                                           section.dwSectionNameAddr - self.header.dwBaseAddr + 8])[0].split("\x00")[0].rstrip()


    def get_logo(self):
        return 0

    def image_png(self):
        for section in self.sections:
            if section.name == '$$XTIMAG':
                data = section.data
                type = struct.unpack('4s', data[0:4])[0]

                newFile = open('C:\\Users\\Dustin\\Desktop\\XPR0.bin', "wb")
                # write to file
                newFile.write(data)
                newFile.close()

                if type == 'XPR0':
                    dwTotalSize  = struct.unpack('I', data[4:8])[0]
                    dwHeaderSize = struct.unpack('I', data[8:12])[0]

                    format_type = ord(data[25:26])

                    dwWidth  = 128
                    dwHeight = 128

                    # 6  RGBA8 0x06
                    if format_type == 0x06:
                        temp_data  = self.unswizzle(dwWidth, dwHeight, 4, dwHeaderSize, data)
                        image_data = [0] * dwWidth * dwHeight * 3

                        dwWidth  = 128
                        dwHeight = 128

                        for J in xrange(dwHeaderSize, len(data) - 1, 4):
                            x = (J / 4) % 128
                            y = (J / 4) / 128

                            r = temp_data[J]
                            g = temp_data[J+1]
                            b = temp_data[J+2]

                            image_data[(y * dwWidth) + x + 0] = r
                            image_data[(y * dwWidth) + x + 1] = g
                            image_data[(y * dwWidth) + x + 2] = b

                        string.join(image_data, '')
                    # 12 DXT1 0x0C
                    elif format_type == 0x0C:
                        image_data = self.decode_texture(dwWidth, dwHeight, data[dwHeaderSize:], self.texture_dxt1)
                    # 14 DXT3 0x0E
                    elif format_type == 0x0E:
                        raise Exception('Unimplemented format')
                    # 15 DXT5 0x0F
                    elif format_type == 0x0F:
                        image_data = self.decode_texture(dwWidth, dwHeight, data[dwHeaderSize:], self.texture_dxt5)
                    else:
                        raise Exception('Unknown format')
                elif type == 'DDS\x20':
                    dwSize   = struct.unpack('I', data[4:8])[0]   # Must be set to 124
                    dwHeight = struct.unpack('I', data[12:16])[0]
                    dwWidth  = struct.unpack('I', data[16:20])[0]

                    if dwSize != 124:
                        raise Exception('Invalid DDS dwSize != 124')

                    data = data[128:]
                    image_data = self.decode_texture(dwWidth, dwHeight, data, self.texture_dxt1)
                else:
                    raise 'Unknown XTIMAG format'

                if len(image_data):
                    image = Image.frombytes('RGB', (dwWidth, dwHeight), image_data)
                    image.save('C:\\Users\\Dustin\\Desktop\\image.bmp')
        print 'done';

    def unswizzle(self, width, height, depth, o, source):
        dest = [' '] * len(source)

        for y in xrange(0, height - 1):
            sy = 0
            if y < width:
                for bit in xrange(0, 15):
                    sy = sy or ((y >> bit) and 1) << (2 * bit)

                sy = sy << 1
            else:
                y_mask = y % width
                for bit in xrange(0, 15):
                    sy = sy or ((y_mask >> bit) and 1) << (2 * bit)

                sy = sy << 1
                sy = sy + (y / width) * width * width

            d = y * width * depth

            for x in xrange(0, width - 1):
                sx = 0
                if x < (height * 2):
                    for bit in xrange(0, 15):
                        sx = sx or ((x >> bit) and 1) << (2 * bit)
                else:
                    x_mask = x % (2 * height)
                    for bit in xrange(0, 15):
                        sx = sx or ((x_mask >> bit) and 1) << (2 * bit)

                    sx = sx + (x / (2 * height)) * 2 * height * height

                pSource = (sx + sy) * depth

                for i in xrange(0, depth - 1):
                    dest[d + i] = source[pSource + i + o:pSource + i + o + 1]
                    #print(d + i)
        return string.join(dest, '')

    def decode_texture(self, dwWidth, dwHeight, image, function):
        data = []
        linesize = (dwWidth + 3) / 4 * 8  # Number of data byte per row

        baseoffset = 0
        for yb in xrange(0, (dwHeight + 3) / 4):
            linedata = image[baseoffset:(baseoffset + linesize)]
            decoded = function(linedata)  # returns 4-tuple of RGB lines
            baseoffset += linesize
            for d in decoded:
                # Make sure that if we have a texture size that's not a
                # multiple of 4 that we correctly truncate the returned data
                data.append(d[:(dwWidth * 3)])

        return string.join(data[:dwHeight], '')

    def texture_dxt5(self, data):
        # input: one "row" of data (i.e. will produce 4*width pixels)
        blocks = len(data) / 16  # number of blocks in row
        out = ['', '', '', '']  # row accumulators
        a = [0 for i in xrange(8)]

        for xb in xrange(blocks):
            # Decode next 8-byte block.
            a[0],a[1],tab1,tab2, c0, c1, bits = struct.unpack('<BBHIHHI', data[xb*16:(xb+1)*16])

            atab = (tab2<<16) | tab1

            if a[0] > a[1]:
                for i in xrange(2,8):
                    a[i] = ((8-i)*a[0] + (i-1)*a[1])/7
            else:
                for i in xrange(2,6):
                    a[i] = ((6-i)*a[0] + (i-1)*a[1])/5
                a[6] = 0
                a[7] = 0xff

            a = [chr(v) for v in a]

            # color 0, packed 5-6-5
            b0 = (c0 & 0x1f) << 3
            g0 = ((c0 >> 5) & 0x3f) << 2
            r0 = ((c0 >> 11) & 0x1f) << 3

            # color 1, packed 5-6-5
            b1 = (c1 & 0x1f) << 3
            g1 = ((c1 >> 5) & 0x3f) << 2
            r1 = ((c1 >> 11) & 0x1f) << 3

            r0,b0,g0,r1,b1,g1 = ((int(v*1.2) if v*1.2 < 256 else 0xff) for v in (r0,b0,g0,r1,b1,g1))

            # Decode this block into 4x4 pixels
            # Accumulate the results onto our 4 row accumulators
            for yo in xrange(4):
                for xo in xrange(4):
                    # get next control op and generate a pixel

                    control = bits & 3
                    bits = bits >> 2
                    alpha_control = atab&7
                    atab >>= 3

                    if control == 0:
                        out[yo] += chr(r0) + chr(g0) + chr(b0) + a[alpha_control]
                    elif control == 1:
                        out[yo] += chr(r1) + chr(g1) + chr(b1) + a[alpha_control]
                    elif control == 2:
                        if 1:#c0 > c1:
                            out[yo] += chr((2 * r0 + r1 + 1) / 3) + chr((2 * g0 + g1 + 1) / 3) + chr((2 * b0 + b1 + 1) / 3) + a[alpha_control]
                        else:
                            out[yo] += chr((r0 + r1) / 2) + chr((g0 + g1) / 2) + chr((b0 + b1) / 2) + a[alpha_control]
                    elif control == 3:
                        if 1:#c0 > c1:
                            out[yo] += chr((2 * r1 + r0 + 1) / 3) + chr((2 * g1 + g0 + 1) / 3) + chr((2 * b1 + b0 + 1) / 3) + a[alpha_control]
                        else:
                            out[yo] += '\0\0\0\0'

        # All done.
        return tuple(out)

    def texture_dxt1(self, data):
        # input: one "row" of data (i.e. will produce 4*width pixels)
        blocks = len(data) / 8  # number of blocks in row
        out = ['', '', '', '']  # row accumulators

        for xb in xrange(blocks):
            # Decode next 8-byte block.
            c0, c1, bits = struct.unpack('<HHI', data[xb*8:xb*8+8])

            # color 0, packed 5-6-5
            b0 = (c0 & 0x1f) << 3
            g0 = ((c0 >> 5) & 0x3f) << 2
            r0 = ((c0 >> 11) & 0x1f) << 3

            # color 1, packed 5-6-5
            b1 = (c1 & 0x1f) << 3
            g1 = ((c1 >> 5) & 0x3f) << 2
            r1 = ((c1 >> 11) & 0x1f) << 3

            # Decode this block into 4x4 pixels
            # Accumulate the results onto our 4 row accumulators
            for yo in xrange(4):
                for xo in xrange(4):
                    # get next control op and generate a pixel

                    control = bits & 3
                    bits = bits >> 2
                    if control == 0:
                        out[yo] += chr(r0) + chr(g0) + chr(b0)
                    elif control == 1:
                        out[yo] += chr(r1) + chr(g1) + chr(b1)
                    elif control == 2:
                        if c0 > c1:
                            out[yo] += chr((2 * r0 + r1 + 1) / 3) + chr((2 * g0 + g1 + 1) / 3) + chr((2 * b0 + b1 + 1) / 3)
                        else:
                            out[yo] += chr((r0 + r1) / 2) + chr((g0 + g1) / 2) + chr((b0 + b1) / 2)
                    elif control == 3:
                        if c0 > c1:
                            out[yo] += chr((2 * r1 + r0 + 1) / 3) + chr((2 * g1 + g0 + 1) / 3) + chr((2 * b1 + b0 + 1) / 3)
                        else:
                            out[yo] += '\0\0\0'

        # All done.
        return tuple(out)

    def validate_xbe(self):
        failed = False

        if self.header.dwMagic == 'XBEH':
            print('Magic XBEH:\t Pass')
        else:
            print('Magic XBEH:\t Fail')
            failed = True

        if self.header.dwBaseAddr == 0x10000:
            print('Image Base Address:\t Pass')
        else:
            print('Image Base Address:\t Fail')
            failed = True

        if self.cert.dwSize == 0x1D0:
            print('Certificate Size:\t Pass')
        else:
            print('Certificate Size:\t Fail')
            failed = True

        return failed

class XBE_HEADER():
    def __init__(self, data):
        XOR_EP_DEBUG  = 0x94859D4B # Entry Point (Debug)
        XOR_EP_RETAIL = 0xA8FC57AB # Entry Point (Retail)
        XOR_KT_DEBUG  = 0xEFB1F152 # Kernel Thunk (Debug)
        XOR_KT_RETAIL = 0x5B6D40B6 # Kernel Thunk (Retail)

        self.dwMagic                       = struct.unpack('4s', data[0:4])[0]      # Magic number [should be "XBEH"]
        self.pbDigitalSignature            = struct.unpack('256B', data[4:260])    # Digital signature
        self.dwBaseAddr                    = struct.unpack('I', data[260:264])[0]  # Base address
        self.dwSizeofHeaders               = struct.unpack('I', data[264:268])[0]  # Size of headers
        self.dwSizeofImage                 = struct.unpack('I', data[268:272])[0]  # Size of image
        self.dwSizeofImageHeader           = struct.unpack('I', data[272:276])[0]  # Size of image header
        self.dwTimeDate                    = struct.unpack('I', data[276:280])[0]  # Timedate stamp
        self.dwCertificateAddr             = struct.unpack('I', data[280:284])[0]  # Certificate address
        self.dwSections                    = struct.unpack('I', data[284:288])[0]  # Number of sections
        self.dwSectionHeadersAddr          = struct.unpack('I', data[288:292])[0]  # Section headers address

        # Struct init_flags
        self.dwInitFlags                   = struct.unpack('I', data[292:296])[0]  # Mount utility drive flag
        self.init_flags_mount_utility_drive  = None # Mount utility drive flag
        self.init_flags_format_utility_drive = None # Format utility drive flag
        self.init_flags_limit_64mb           = None # Limit development kit run time memory to 64mb flag
        self.init_flags_dont_setup_harddisk  = None # Don't setup hard disk flag
        self.init_flags_unused               = None # Unused (or unknown)
        self.init_flags_unused_b1            = None # Unused (or unknown)
        self.init_flags_unused_b2            = None # Unused (or unknown)
        self.init_flags_unused_b3            = None # Unused (or unknown)

        self.dwEntryAddr                   = struct.unpack('I', data[296:300])[0]  # Entry point address
        self.dwTLSAddr                     = struct.unpack('I', data[300:304])[0]  # TLS directory address
        self.dwPeStackCommit               = struct.unpack('I', data[304:308])[0]  # Size of stack commit
        self.dwPeHeapReserve               = struct.unpack('I', data[308:312])[0]  # Size of heap reserve
        self.dwPeHeapCommit                = struct.unpack('I', data[312:316])[0]  # Size of heap commit
        self.dwPeBaseAddr                  = struct.unpack('I', data[316:320])[0]  # Original base address
        self.dwPeSizeofImage               = struct.unpack('I', data[320:324])[0]  # Size of original image
        self.dwPeChecksum                  = struct.unpack('I', data[324:328])[0]  # Original checksum
        self.dwPeTimeDate                  = struct.unpack('I', data[328:332])[0]  # Original timedate stamp
        self.dwDebugPathnameAddr           = struct.unpack('I', data[332:336])[0]  # Debug pathname address
        self.dwDebugFilenameAddr           = struct.unpack('I', data[336:340])[0]  # Debug filename address
        self.dwDebugUnicodeFilenameAddr    = struct.unpack('I', data[340:344])[0]  # Debug unicode filename address
        self.dwKernelImageThunkAddr        = struct.unpack('I', data[344:348])[0]  # Kernel image thunk address
        self.dwNonKernelImportDirAddr      = struct.unpack('I', data[348:352])[0]  # Non kernel import directory address
        self.dwLibraryVersions             = struct.unpack('I', data[352:356])[0]  # Number of library versions
        self.dwLibraryVersionsAddr         = struct.unpack('I', data[356:360])[0]  # Library versions address
        self.dwKernelLibraryVersionAddr    = struct.unpack('I', data[360:364])[0]  # Kernel library version address
        self.dwXAPILibraryVersionAddr      = struct.unpack('I', data[364:368])[0]  # XAPI library version address
        self.dwLogoBitmapAddr              = struct.unpack('I', data[368:372])[0]  # Logo bitmap address
        self.dwSizeofLogoBitmap            = struct.unpack('I', data[372:376])[0]  # Logo bitmap size

        self.dwEntryAddr_f                 = self.dwEntryAddr ^ XOR_EP_RETAIL      # Entry point address


class XBE_CERT():
    def __init__(self, data):
        self.dwSize                        = struct.unpack('I', data[0:4])[0]      # 0x0000 - size of certificate
        self.dwTimeDate                    = struct.unpack('I', data[4:8])[0]      # 0x0004 - timedate stamp
        self.dwTitleId                     = struct.unpack('I', data[8:12])[0]     # 0x0008 - title id
        self.wszTitleName                  = struct.unpack('40s', data[12:52])[0]  # 0x000C - title name (unicode)
        self.dwAlternateTitleId            = struct.unpack('16B', data[52:68])     # 0x005C - alternate title ids
        self.dwAllowedMedia                = struct.unpack('I', data[68:72])[0]    # 0x009C - allowed media types
        self.dwGameRegion                  = struct.unpack('I', data[72:76])[0]    # 0x00A0 - game region
        self.dwGameRatings                 = struct.unpack('I', data[80:84])[0]    # 0x00A4 - game ratings
        self.dwDiskNumber                  = struct.unpack('I', data[84:88])[0]    # 0x00A8 - disk number
        self.dwVersion                     = struct.unpack('I', data[92:96])[0]    # 0x00AC - version
        self.bzLanKey                      = struct.unpack('16B', data[100:116])   # 0x00B0 - lan key
        self.bzSignatureKey                = struct.unpack('16B', data[116:132])   # 0x00C0 - signature key
        self.bzTitleAlternateSignatureKey  = [                                     # 0x00D0 - alternate signature keys
            struct.unpack('16B', data[132:148]),
            struct.unpack('16B', data[148:164]),
            struct.unpack('16B', data[164:180]),
            struct.unpack('16B', data[180:196]),
            struct.unpack('16B', data[196:212]),
            struct.unpack('16B', data[212:228]),
            struct.unpack('16B', data[228:244]),
            struct.unpack('16B', data[244:260]),
            struct.unpack('16B', data[260:276]),
            struct.unpack('16B', data[276:292]),
            struct.unpack('16B', data[292:308]),
            struct.unpack('16B', data[308:324]),
            struct.unpack('16B', data[324:340]),
            struct.unpack('16B', data[340:356]),
            struct.unpack('16B', data[356:372]),
            struct.unpack('16B', data[372:388])
        ]

        # Title name cleanup
        self.wszTitleName = self.wszTitleName.decode('utf-16')


class XBE_SECTION(XBE):
    def __init__(self, data, data_file):
        self.name = None
        self.data = None

        # Header
        self.dwFlags                    = struct.unpack('I', data[0:4])[0]    # Virtual address
        self.flag_bWritable             = struct.unpack('I', data[0:4])[0]    # writable flag
        self.flag_bPreload              = struct.unpack('I', data[0:4])[0]    # preload flag
        self.flag_bExecutable           = struct.unpack('I', data[0:4])[0]    # executable flag
        self.flag_bInsertedFile         = struct.unpack('I', data[0:4])[0]    # inserted file flag
        self.flag_bHeadPageRO           = struct.unpack('I', data[0:4])[0]    # head page read only flag
        self.flag_bTailPageRO           = struct.unpack('I', data[0:4])[0]    # tail page read only flag
        self.flag_Unused_a1             = struct.unpack('I', data[0:4])[0]    # unused (or unknown)
        self.flag_Unused_a2             = struct.unpack('I', data[0:4])[0]    # unused (or unknown)
        self.flag_Unused_b1             = struct.unpack('I', data[0:4])[0]    # unused (or unknown)
        self.flag_Unused_b2             = struct.unpack('I', data[0:4])[0]    # unused (or unknown)
        self.flag_Unused_b3             = struct.unpack('I', data[0:4])[0]    # unused (or unknown)

        self.dwVirtualAddr              = struct.unpack('I', data[4:8])[0]    # Virtual address
        self.dwVirtualSize              = struct.unpack('I', data[8:12])[0]   # Virtual size
        self.dwRawAddr                  = struct.unpack('I', data[12:16])[0]  # File offset to raw data
        self.dwSizeofRaw                = struct.unpack('I', data[16:20])[0]  # Size of raw data
        self.dwSectionNameAddr          = struct.unpack('I', data[20:24])[0]  # Section name addr
        self.dwSectionRefCount          = struct.unpack('I', data[24:28])[0]  # Section reference count
        self.dwHeadSharedRefCountAddr   = struct.unpack('I', data[28:32])[0]  # Head shared page reference count address
        self.dwTailSharedRefCountAddr   = struct.unpack('I', data[32:36])[0]  # Tail shared page reference count address
        self.bzSectionDigest            = struct.unpack('20B', data[36:56])   # Section digest

        # Section Data
        self.data  = data_file[self.dwRawAddr:self.dwRawAddr + self.dwSizeofRaw]
        self.data += '\x00' * (self.dwVirtualSize - len(self.data))


class XBE_LIB(XBE):
    def __init__(self):
        print('wtf')


class XBE_TLS(XBE):
    def __init__(self):
        print('wtf')
