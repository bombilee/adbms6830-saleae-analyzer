# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
from typing import Union, Tuple, Optional, List

from saleae.analyzers import (
    HighLevelAnalyzer,
    AnalyzerFrame,
    StringSetting,
    NumberSetting,
    ChoicesSetting,
)

def parse_voltage(data: bytearray) -> str:
    return f"{(int.from_bytes(bytes(data), byteorder='little', signed=True) * 0.000150) + 1.5:.3f}V"


def print_bytes(data: bytearray) -> str:
    value = int.from_bytes(bytes(data), byteorder="little", signed=False)
    return f"0x{value:04X}"


REGISTER_MAP = {
    0x0260: {"name": "ADCV", "parse_fn": print_bytes},
    0x0168: {"name": "ADSV", "parse_fn": print_bytes},
    0x0200: {"name": "ADI1", "parse_fn": print_bytes},
    0x0108: {"name": "ADI2", "parse_fn": print_bytes},
    0x0240: {"name": "ADCIV", "parse_fn": print_bytes},
    0x0410: {"name": "ADAX", "parse_fn": print_bytes},
    0x0400: {"name": "ADAX2", "parse_fn": print_bytes},
    0x0028: {"name": "MUTE", "parse_fn": print_bytes},
    0x0029: {"name": "UNMUTE", "parse_fn": print_bytes},
    0x004C: {"name": "RDACALL", "parse_fn": print_bytes},
    0x0001: {"name": "WRCFGA", "parse_fn": print_bytes},
    0x0024: {"name": "WRCFGB", "parse_fn": print_bytes},
    0x0081: {"name": "WRCFGC", "parse_fn": print_bytes},
    0x00A4: {"name": "WRCFGD", "parse_fn": print_bytes},
    0x0073: {"name": "WRCFGE", "parse_fn": print_bytes},
    0x0075: {"name": "WRCFGF", "parse_fn": print_bytes},
    0x0077: {"name": "WRCFGG", "parse_fn": print_bytes},
    0x0079: {"name": "WRCFGH", "parse_fn": print_bytes},
    0x007B: {"name": "WRCFGI", "parse_fn": print_bytes},
    0x0002: {"name": "RDCFGA", "parse_fn": print_bytes},
    0x0026: {"name": "RDCFGB", "parse_fn": print_bytes},
    0x0082: {"name": "RDCFGC", "parse_fn": print_bytes},
    0x00A6: {"name": "RDCFGD", "parse_fn": print_bytes},
    0x0074: {"name": "RDCFGE", "parse_fn": print_bytes},
    0x0076: {"name": "RDCFGF", "parse_fn": print_bytes},
    0x0078: {"name": "RDCFGG", "parse_fn": print_bytes},
    0x007A: {"name": "RDCFGH", "parse_fn": print_bytes},
    0x007C: {"name": "RDCFGI", "parse_fn": print_bytes},
    # CADC Registers
    0x0004: {"name": "RDCVA", "parse_fn": parse_voltage, "offset": 0},
    0x0006: {"name": "RDCVB", "parse_fn": parse_voltage, "offset": 3},
    0x0008: {"name": "RDCVC", "parse_fn": parse_voltage, "offset": 6},
    0x000A: {"name": "RDCVD", "parse_fn": parse_voltage, "offset": 9},
    0x0009: {"name": "RDCVE", "parse_fn": parse_voltage, "offset": 12},
    0x000B: {"name": "RDCVF", "parse_fn": parse_voltage, "offset": 15},
    0x000C: {"name": "RDCVALL", "parse_fn": parse_voltage},
    0x0003: {"name": "RDSVA", "parse_fn": parse_voltage, "offset": 0},
    0x0005: {"name": "RDSVB", "parse_fn": parse_voltage, "offset": 3},
    0x0007: {"name": "RDSVC", "parse_fn": parse_voltage, "offset": 6},
    0x000D: {"name": "RDSVD", "parse_fn": parse_voltage, "offset": 9},
    0x000E: {"name": "RDSVE", "parse_fn": parse_voltage, "cell_offset": 12},
    0x000F: {"name": "RDSVF", "parse_fn": parse_voltage, "cell_offset": 15},
    0x0010: {"name": "RDSVALL", "parse_fn": parse_voltage},
    # CADC Filtered Registers
    0x0012: {"name": "RDFCA", "parse_fn": print_bytes},
    0x0013: {"name": "RDFCB", "parse_fn": print_bytes},
    0x0014: {"name": "RDFCC", "parse_fn": print_bytes},
    0x0015: {"name": "RDFCD", "parse_fn": print_bytes},
    0x0016: {"name": "RDFCE", "parse_fn": print_bytes},
    0x0017: {"name": "RDFCF", "parse_fn": print_bytes},
    0x0018: {"name": "RDFCALL", "parse_fn": print_bytes},
    # AUX Registers
    0x0019: {"name": "RDAUXA", "parse_fn": parse_voltage, "offset": 0},
    0x001A: {"name": "RDAUXB", "parse_fn": parse_voltage, "offset": 3},
    0x001B: {"name": "RDAUXC", "parse_fn": parse_voltage, "offset": 6},
    0x001F: {"name": "RDAUXD", "parse_fn": parse_voltage, "offset": 9},
    # AUX Registers
    0x001C: {"name": "RDRAXA", "parse_fn": parse_voltage, "offset": 0},
    0x001D: {"name": "RDRAXB", "parse_fn": parse_voltage, "offset": 3},
    0x001E: {"name": "RDRAXC", "parse_fn": parse_voltage, "offset": 6},
    0x0025: {"name": "RDRAXD", "parse_fn": parse_voltage, "offset": 9},
    # ID Register
    0x002C: {"name": "RDSID", "parse_fn": print_bytes},
    # Balance PWM Registers
    0x0020: {"name": "WRPWMA", "parse_fn": print_bytes},
    0x0022: {"name": "RDPWMA", "parse_fn": print_bytes},
    0x0021: {"name": "WRPWMB", "parse_fn": print_bytes},
    0x0023: {"name": "RDPWMB", "parse_fn": print_bytes},
}


def calculatePEC15(pDataBuf: Union[bytes, bytearray]) -> int:
    nRemainder = 16  # initialize the PEC
    for b in pDataBuf:
        nTableAddr = ((nRemainder >> 7) ^ (b & 0xFF)) & 0xFF
        nRemainder = ((nRemainder << 8) ^ Adbms6948_Crc15Table[nTableAddr]) & 0xFFFF
    # The CRC15 has a 0 in the LSB so the remainder must be multiplied by 2
    return (nRemainder * 2) & 0xFFFF


def calculatePEC10(pDataBuf: Union[bytes, bytearray], bIsRxCmd: bool, counter_byte: Optional[int] = None) -> int:
    nRemainder = 16  # PEC_SEED
    # x10 + x7 + x3 + x2 + x + 1 <- the CRC10 polynomial 100 1000 1111
    nPolynomial = 0x8F
    for b in pDataBuf:
        nTableAddr = ((nRemainder >> 2) ^ (b & 0xFF)) & 0xFF
        nRemainder = ((nRemainder << 8) ^ Adbms6948_Crc10Table[nTableAddr]) & 0xFFFF
    # If array is from received buffer add command counter to crc calculation
    if bIsRxCmd and (counter_byte is not None):
        nRemainder ^= ((counter_byte & 0xFC) << 2) & 0xFFFF
    # Perform modulo-2 division, a bit at a time
    for _ in range(6, 0, -1):
        # Try to divide the current data bit
        if (nRemainder & 0x200) > 0:
            nRemainder = ((nRemainder << 1) ^ nPolynomial) & 0xFFFF
        else:
            nRemainder = (nRemainder << 1) & 0xFFFF
    return nRemainder & 0x3FF


Adbms6948_Crc15Table: Tuple[int, ...] = (
    0x0000, 0xc599, 0xceab, 0x0b32, 0xd8cf, 0x1d56, 0x1664, 0xd3fd, 0xf407, 0x319e, 0x3aac,
    0xff35, 0x2cc8, 0xe951, 0xe263, 0x27fa, 0xad97, 0x680e, 0x633c, 0xa6a5, 0x7558, 0xb0c1,
    0xbbf3, 0x7e6a, 0x5990, 0x9c09, 0x973b, 0x52a2, 0x815f, 0x44c6, 0x4ff4, 0x8a6d, 0x5b2e,
    0x9eb7, 0x9585, 0x501c, 0x83e1, 0x4678, 0x4d4a, 0x88d3, 0xaf29, 0x6ab0, 0x6182, 0xa41b,
    0x77e6, 0xb27f, 0xb94d, 0x7cd4, 0xf6b9, 0x3320, 0x3812, 0xfd8b, 0x2e76, 0xebef, 0xe0dd,
    0x2544, 0x02be, 0xc727, 0xcc15, 0x098c, 0xda71, 0x1fe8, 0x14da, 0xd143, 0xf3c5, 0x365c,
    0x3d6e, 0xf8f7, 0x2b0a, 0xee93, 0xe5a1, 0x2038, 0x07c2, 0xc25b, 0xc969, 0x0cf0, 0xdf0d,
    0x1a94, 0x11a6, 0xd43f, 0x5e52, 0x9bcb, 0x90f9, 0x5560, 0x869d, 0x4304, 0x4836, 0x8daf,
    0xaa55, 0x6fcc, 0x64fe, 0xa167, 0x729a, 0xb703, 0xbc31, 0x79a8, 0xa8eb, 0x6d72, 0x6640,
    0xa3d9, 0x7024, 0xb5bd, 0xbe8f, 0x7b16, 0x5cec, 0x9975, 0x9247, 0x57de, 0x8423, 0x41ba,
    0x4a88, 0x8f11, 0x057c, 0xc0e5, 0xcbd7, 0x0e4e, 0xddb3, 0x182a, 0x1318, 0xd681, 0xf17b,
    0x34e2, 0x3fd0, 0xfa49, 0x29b4, 0xec2d, 0xe71f, 0x2286, 0xa213, 0x678a, 0x6cb8, 0xa921,
    0x7adc, 0xbf45, 0xb477, 0x71ee, 0x5614, 0x938d, 0x98bf, 0x5d26, 0x8edb, 0x4b42, 0x4070,
    0x85e9, 0x0f84, 0xca1d, 0xc12f, 0x04b6, 0xd74b, 0x12d2, 0x19e0, 0xdc79, 0xfb83, 0x3e1a, 0x3528,
    0xf0b1, 0x234c, 0xe6d5, 0xede7, 0x287e, 0xf93d, 0x3ca4, 0x3796, 0xf20f, 0x21f2, 0xe46b, 0xef59,
    0x2ac0, 0x0d3a, 0xc8a3, 0xc391, 0x0608, 0xd5f5, 0x106c, 0x1b5e, 0xdec7, 0x54aa, 0x9133, 0x9a01,
    0x5f98, 0x8c65, 0x49fc, 0x42ce, 0x8757, 0xa0ad, 0x6534, 0x6e06, 0xab9f, 0x7862, 0xbdfb, 0xb6c9,
    0x7350, 0x51d6, 0x944f, 0x9f7d, 0x5ae4, 0x8919, 0x4c80, 0x47b2, 0x822b, 0xa5d1, 0x6048, 0x6b7a,
    0xaee3, 0x7d1e, 0xb887, 0xb3b5, 0x762c, 0xfc41, 0x39d8, 0x32ea, 0xf773, 0x248e, 0xe117, 0xea25,
    0x2fbc, 0x0846, 0xcddf, 0xc6ed, 0x0374, 0xd089, 0x1510, 0x1e22, 0xdbbb, 0x0af8, 0xcf61, 0xC453,
    0x01ca, 0xd237, 0x17ae, 0x1c9c, 0xd905, 0xfeff, 0x3b66, 0x3054, 0xf5cd, 0x2630, 0xe3a9, 0xe89b,
    0x2d02, 0xa76f, 0x62f6, 0x69c4, 0xac5d, 0x7fa0, 0xba39, 0xb10b, 0x7492, 0x5368, 0x96f1, 0x9dc3,
    0x585a, 0x8ba7, 0x4e3e, 0x450c, 0x8095,
)

Adbms6948_Crc10Table: Tuple[int, ...] = (
    0x000, 0x08f, 0x11e, 0x191, 0x23c, 0x2b3, 0x322, 0x3ad, 0x0f7, 0x078, 0x1e9, 0x166, 0x2cb, 0x244, 0x3d5, 0x35a,
    0x1ee, 0x161, 0x0f0, 0x07f, 0x3d2, 0x35d, 0x2cc, 0x243, 0x119, 0x196, 0x007, 0x088, 0x325, 0x3aa, 0x23b, 0x2b4,
    0x3dc, 0x353, 0x2c2, 0x24d, 0x1e0, 0x16f, 0x0fe, 0x071, 0x32b, 0x3a4, 0x235, 0x2ba, 0x117, 0x198, 0x009, 0x086,
    0x232, 0x2bd, 0x32c, 0x3a3, 0x00e, 0x081, 0x110, 0x19f, 0x2c5, 0x24a, 0x3db, 0x354, 0x0f9, 0x076, 0x1e7, 0x168,
    0x337, 0x3b8, 0x229, 0x2a6, 0x10b, 0x184, 0x015, 0x09a, 0x3c0, 0x34f, 0x2de, 0x251, 0x1fc, 0x173, 0x0e2, 0x06d,
    0x2d9, 0x256, 0x3c7, 0x348, 0x0e5, 0x06a, 0x1fb, 0x174, 0x22e, 0x2a1, 0x330, 0x3bf, 0x012, 0x09d, 0x10c, 0x183,
    0x0eb, 0x064, 0x1f5, 0x17a, 0x2d7, 0x258, 0x3c9, 0x346, 0x01c, 0x093, 0x102, 0x18d, 0x220, 0x2af, 0x33e, 0x3b1,
    0x105, 0x18a, 0x01b, 0x094, 0x339, 0x3b6, 0x227, 0x2a8, 0x1f2, 0x17d, 0x0ec, 0x063, 0x3ce, 0x341, 0x2d0, 0x25f,
    0x2e1, 0x26e, 0x3ff, 0x370, 0x0dd, 0x052, 0x1c3, 0x14c, 0x216, 0x299, 0x308, 0x387, 0x02a, 0x0a5, 0x134, 0x1bb,
    0x30f, 0x380, 0x211, 0x29e, 0x133, 0x1bc, 0x02d, 0x0a2, 0x3f8, 0x377, 0x2e6, 0x269, 0x1c4, 0x14b, 0x0da, 0x055,
    0x13d, 0x1b2, 0x023, 0x0ac, 0x301, 0x38e, 0x21f, 0x290, 0x1ca, 0x145, 0x0d4, 0x05b, 0x3f6, 0x379, 0x2e8, 0x267,
    0x0d3, 0x05c, 0x1cd, 0x142, 0x2ef, 0x260, 0x3f1, 0x37e, 0x024, 0x0ab, 0x13a, 0x1b5, 0x218, 0x297, 0x306, 0x389,
    0x1d6, 0x159, 0x0c8, 0x047, 0x3ea, 0x365, 0x2f4, 0x27b, 0x121, 0x1ae, 0x03f, 0x0b0, 0x31d, 0x392, 0x203, 0x28c,
    0x038, 0x0b7, 0x126, 0x1a9, 0x204, 0x28b, 0x31a, 0x395, 0x0cf, 0x040, 0x1d1, 0x15e, 0x2f3, 0x27c, 0x3ed, 0x362,
    0x20a, 0x285, 0x314, 0x39b, 0x036, 0x0b9, 0x128, 0x1a7, 0x2fd, 0x272, 0x3e3, 0x36c, 0x0c1, 0x04e, 0x1df, 0x150,
    0x3e4, 0x36b, 0x2fa, 0x275, 0x1d8, 0x157, 0x0c6, 0x049, 0x313, 0x39c, 0x20d, 0x282, 0x12f, 0x1a0, 0x031, 0x0be,
)


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # TODO: enable raw output option
    # parse_output = ChoicesSetting(choices=("Parsed", "Raw"))

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        "Command": {"format": "{{data.command}}",},
        "PEC": {"format": "{{data.pec}}"},
        "Data": {"format": "{{data.data}}"},
    }

    def __init__(self):
        """
        Initialize HLA.

        Settings can be accessed using the same name used above.
        """

        self.frames = []
        self.word_start_time = None
        self.spi_enable = False
        self.error = False

    def handle_enable(self, frame: AnalyzerFrame):
        self.frames = []
        self.spi_enable = True
        self.error = False
        self.transaction_start_time = frame.start_time

    def reset(self):
        self.frames = []
        self.spi_enable = False
        self.error = False
        self.transaction_start_time = None

    def is_valid_transaction(self) -> bool:
        return (
            self.spi_enable
            and (not self.error)
            and (self.transaction_start_time is not None)
        )

    def handle_result(self, frame):
        if self.spi_enable:
            self.frames.append(frame)

    def get_frame_data(self) -> list:
        analyzer_frames: List[AnalyzerFrame] = []

        if len(self.frames) < 4:
            return []

        mosi_stream = bytearray()
        miso_stream = bytearray()
        for f in self.frames:
            mosi = f.data.get("mosi", 0)
            miso = f.data.get("miso", 0)
            if isinstance(mosi, (bytes, bytearray)):
                mosi_stream += mosi
            elif isinstance(mosi, int):
                mosi_stream.append(mosi & 0xFF)
            if isinstance(miso, (bytes, bytearray)):
                miso_stream += miso
            elif isinstance(miso, int):
                miso_stream.append(miso & 0xFF)

        # COMMAND
        command = bytes(mosi_stream[0:2])
        cmd_val = int.from_bytes(command, byteorder="big", signed=False)
        cmd_entry = REGISTER_MAP.get(cmd_val, {})
        if isinstance(cmd_entry, dict) and ("name" in cmd_entry):
            command_label = cmd_entry["name"]
        else:
            command_label = f"0x{cmd_val:04X}"

        analyzer_frames.append(
            AnalyzerFrame(
                "Command",
                self.frames[0].start_time,
                self.frames[1].end_time,
                {
                    "command": command_label,
                },
            )
        )

        # COMMAND PEC
        command_pec = bytes(mosi_stream[2:4])
        pec_val = int.from_bytes(command_pec, byteorder="big", signed=False)
        command_pec_label = f"0x{pec_val:04X}"
        command_pec_calc = calculatePEC15(command)
        pec_valid = command_pec_calc == pec_val

        analyzer_frames.append(
            AnalyzerFrame(
                "PEC",
                self.frames[2].start_time,
                self.frames[3].end_time,
                {
                    "pec": f"{command_pec_label} {'(VALID)' if pec_valid else '(INVALID)'}"
                },
            )
        )

        data_frames = []
        if len(self.frames) > 4:
            data_frames = self.frames[4:]

        if not data_frames or len(data_frames) % 8 != 0:
            return analyzer_frames

        # Split into lists of 8 frames per group
        self.data_frame_groups = [
            data_frames[i : i + 8] for i in range(0, len(data_frames), 8)
        ]
        parse_fn = cmd_entry.get("parse_fn") if isinstance(cmd_entry, dict) else None

        for asic_index, group in enumerate(self.data_frame_groups):
            if command_label.startswith("RD"):
                data_stream = miso_stream[4 + asic_index * 8 :]
            else:
                data_stream = mosi_stream[4 + asic_index * 8 :]
            for data_index in [1, 3, 5]:
                cell_index = (data_index - 1) // 2
                if callable(parse_fn):
                    parsed_data = parse_fn(data_stream[data_index - 1 : data_index + 1])
                else:
                    parsed_data = print_bytes(
                        data_stream[data_index - 1 : data_index + 1]
                    )

                analyzer_frames.append(
                    AnalyzerFrame(
                        "Data",
                        group[data_index - 1].start_time,
                        group[data_index].end_time,
                        {
                            "data": f"A{asic_index + 1}id{cmd_entry.get('offset', 0) + cell_index+1}: {parsed_data}"
                        },
                    )
                )

            data_pec_bytes = data_stream[6:8]
            # Show PEC as big-endian 16-bit for readability
            data_pec_be_str = f"0x{int.from_bytes(data_pec_bytes, byteorder='big', signed=False):04X}"
            # Extract counter and CRC10 from the two PEC bytes
            rx_counter_byte = data_pec_bytes[0]
            rx_crc10 = ((rx_counter_byte & 0x03) << 8) | data_pec_bytes[1]
            cc_value = (rx_counter_byte & 0xFC) >> 2
            # Compute expected CRC10 over the 6 data bytes + counter contribution
            data_pec_calc = calculatePEC10(data_stream[:6], bIsRxCmd=True, counter_byte=rx_counter_byte)
            data_pec_valid = (data_pec_calc == rx_crc10)

            analyzer_frames.append(
                AnalyzerFrame(
                    "PEC",
                    group[6].start_time,
                    group[7].end_time,
                    {
                        "pec": f"CC: {cc_value} PEC: 0x{rx_crc10:03X} {'(VALID)' if data_pec_valid else f'(INVALID) calc 0x{data_pec_calc:03X}'}"
                    },
                )
            )

        return analyzer_frames

    def handle_disable(self, frame):
        if self.is_valid_transaction():
            result = self.get_frame_data()
            # result = AnalyzerFrame(
            #     "SpiTransaction",
            #     self.transaction_start_time,
            #     frame.end_time,
            #     self.get_frame_data(),
            # )
        else:
            result = AnalyzerFrame(
                "SpiTransactionError",
                frame.start_time,
                frame.end_time,
                {
                    "error_info": "Invalid SPI transaction (spi_enable={}, error={}, transaction_start_time={})".format(
                        self.spi_enable,
                        self.error,
                        self.transaction_start_time,
                    )
                },
            )

        self.reset()
        return result

    def handle_error(self, frame):
        result = AnalyzerFrame(
            "SpiTransactionError",
            frame.start_time,
            frame.end_time,
            {
                "error_info": "The clock was in the wrong state when the enable signal transitioned to active"
            },
        )
        self.reset()
        return result

    def decode(self, frame: AnalyzerFrame):
        if frame.type == "enable":
            return self.handle_enable(frame)
        elif frame.type == "result":
            return self.handle_result(frame)
        elif frame.type == "disable":
            return self.handle_disable(frame)
        elif frame.type == "error":
            return self.handle_error(frame)
        else:
            return AnalyzerFrame(
                "SpiTransactionError",
                frame.start_time,
                frame.end_time,
                {
                    "error_info": "Unexpected frame type from input analyzer: {}".format(
                        frame.type
                    )
                },
            )
