#!/usr/bin/env python3

import struct
import collections
import json
import os

import ida_bytes
import ida_entry
import ida_ida
import ida_idp
import ida_loader
import ida_name
import ida_segment

# Based (mostly) on: https://github.com/espressif/esp-idf/blob/master/components/bootloader_support/include/esp_app_format.h

ESP_CHIP_ID_ESP32   = 0x0000 # chip ID: ESP32
ESP_CHIP_ID_ESP32S2 = 0x0002 # chip ID: ESP32-S2
ESP_CHIP_ID_ESP32C3 = 0x0005 # chip ID: ESP32-C3
ESP_CHIP_ID_ESP32S3 = 0x0009 # chip ID: ESP32-S3
ESP_CHIP_ID_ESP32S3_B2 = 0x0004 # chip ID: ESP32-S2 Beta 2
ESP_CHIP_ID_ESP32C2 = 0x000C # chip ID: ESP32-C2
ESP_CHIP_ID_ESP32H4_B1 = 0x000A # chip ID: ESP32-H4 Beta1
ESP_CHIP_ID_ESP32H4_B2 = 0x000E # chip ID: ESP32-H4 Beta2*/  // ESP32H4-TODO: IDF-3475
ESP_CHIP_ID_ESP32C6 = 0x000D # chip ID: ESP32-C6
ESP_CHIP_ID_INVALID = 0xFFFF # Invalid chip ID (we defined it to make sure the esp_chip_id_t is 2 bytes size)

ESP_IMAGE_KIND_NONE = None
ESP_IMAGE_KIND_8266 = "Esp8266RomImage"
ESP_IMAGE_KIND_8266_V2 = "Esp8266V2Image"
ESP_IMAGE_KIND_32 = "Esp32Image"
ESP_IMAGE_KIND_32S2 = "Esp32S2Image"
ESP_IMAGE_KIND_32S3 = "Esp32S3Image"
ESP_IMAGE_KIND_32S3_B2 = "Esp32S3Image (beta 2)"
ESP_IMAGE_KIND_32C2 = "Esp32C2Image"
ESP_IMAGE_KIND_32C3 = "Esp32C3Image"
ESP_IMAGE_KIND_32C6 = "Esp32C6Image"
ESP_IMAGE_KIND_32H4_B1 = "Esp32H4Image (beta 1)"
ESP_IMAGE_KIND_32H4_B2 = "Esp32H4Image (beta 2)"

ESP32_CHIP_ID_TO_IMAGE_KIND = {
    ESP_CHIP_ID_ESP32 : ESP_IMAGE_KIND_32,
    ESP_CHIP_ID_ESP32S2 : ESP_IMAGE_KIND_32S2,
    ESP_CHIP_ID_ESP32S3 : ESP_IMAGE_KIND_32S3,
    ESP_CHIP_ID_ESP32S3_B2 : ESP_IMAGE_KIND_32S3_B2,
    ESP_CHIP_ID_ESP32C2 : ESP_IMAGE_KIND_32C2,
    ESP_CHIP_ID_ESP32C3 : ESP_IMAGE_KIND_32C3,
    ESP_CHIP_ID_ESP32C6 : ESP_IMAGE_KIND_32C6,
    ESP_CHIP_ID_ESP32H4_B1 : ESP_IMAGE_KIND_32H4_B1,
    ESP_CHIP_ID_ESP32H4_B2 : ESP_IMAGE_KIND_32H4_B2,
}

ESP_IMAGE_KIND_XTENSA = [
    ESP_IMAGE_KIND_NONE,
    ESP_IMAGE_KIND_8266,
    ESP_IMAGE_KIND_8266_V2,
    ESP_IMAGE_KIND_32,
    ESP_IMAGE_KIND_32S2,
    ESP_IMAGE_KIND_32S3,
    ESP_IMAGE_KIND_32S3_B2,
    ESP_IMAGE_KIND_32H4_B1,
    ESP_IMAGE_KIND_32H4_B2,
]

def resolve_absolute_path(file):
    return os.path.join(os.path.dirname(__file__), "esp", file)

ESP_IMAGE_KIND_TO_ROM_FILE = {
    ESP_IMAGE_KIND_8266 : "8266.json",
    ESP_IMAGE_KIND_8266_V2 : "8266.json",
    ESP_IMAGE_KIND_32 : "32.json",
    ESP_IMAGE_KIND_32S2: "32s2.json",
    ESP_IMAGE_KIND_32S3: "32s3.json",
    ESP_IMAGE_KIND_32S3_B2: "32s3b2.json",
    ESP_IMAGE_KIND_32C2: "32c2.json",
    ESP_IMAGE_KIND_32C3: "32c3.json",
    ESP_IMAGE_KIND_32C6: "32c6.json",
}

def debug(msg):
    # print(msg)
    pass

class ReadError(Exception):
    pass

def read_struct(li, format):
    size = struct.calcsize(format)
    buffer = li.read(size)
    if len(buffer) < size:
        raise ReadError("Unexpected end of file!")
    return struct.unpack(format, buffer)

class esp_image_header_t(collections.namedtuple(
        "esp_image_header_t",
        (
            # prefix header
            "magic",
            "segment_count",
            "spi_mode",
            "spi_speed_and_size",
            "entry_addr",
            # extra header (16 bytes)
            "wp_spin",
            "spi_pin_drv_0",
            "spi_pin_drv_1",
            "spi_pin_drv_2",
            "chip_id",
            "min_chip_rev",
            "min_chip_rev_full",
            "max_chip_rev_full",
            "reserved_0",
            "reserved_1",
            "reserved_2",
            "reserved_3",
            "hash_appended"
        ))):

    @property
    def spi_speed(self):
        return self.spi_speed_and_size & 0xF

    @property
    def spi_size(self):
        return (self.spi_speed_and_size >> 4) & 0xF

    @property
    def esp8266v2_header(self):
        return self._esp8266v2_header

    @esp8266v2_header.setter
    def esp8266v2_header(self, h):
        self._esp8266v2_header = h

    def get_image_kind(self, strict=True):
        if self.magic not in [0xE9, 0xEA] \
           or self.spi_mode >= 6 \
           or self.spi_speed >= 0x10\
           or self.spi_size >= 0x9 \
           or self.hash_appended not in [0, 1]:
            return ESP_IMAGE_KIND_NONE

        if strict and (
                self.reserved_0 != 0 \
             or self.reserved_1 != 0 \
             or self.reserved_2 != 0 \
             or self.reserved_3 != 0):
            return ESP_IMAGE_KIND_NONE

        if self.magic == 0xEA:
            return ESP_IMAGE_KIND_8266_V2
        elif self.magic == 0xE9:
            return ESP32_CHIP_ID_TO_IMAGE_KIND.get(self.chip_id, ESP_IMAGE_KIND_8266)

    def get_processor(self):
        img_kind = self.get_image_kind()
        assert img_kind is not ESP_IMAGE_KIND_NONE
        return "xtensa" if img_kind in ESP_IMAGE_KIND_XTENSA else "riscv"

    def read_segment_header(self, li):
        seghdr_fmt = "<II"
        return read_struct(li, seghdr_fmt)

    def read_segment_data(self, li, data_len):
        file_off = li.tell()
        data = li.read(data_len) if data_len > 0 else b""
        if len(data) < data_len:
            raise ReadError("Unexpected end of file")
        return file_off, data

    def segments(self, li):
        prefix_header_len = 8
        extra_header_len = 16
        img_kind = self.get_image_kind()
        if img_kind is ESP_IMAGE_KIND_8266_V2:
            li.seek(prefix_header_len, 0)

            # 1) define `IROM` segment
            load_addr, data_len = self.read_segment_header(li)
            file_off, data = self.read_segment_data(li, data_len)

            # kludge: the addr in the image file is not the real
            # load address of the IROM segment
            IROM_MAP_START = 0x40200000
            flashing_addr = 0x1000
            dummy_header_size = 8
            load_addr = IROM_MAP_START + flashing_addr + dummy_header_size + 8
            yield file_off, load_addr, data

            # 2) skip v2 header
            li.seek(prefix_header_len, 1)

            # 3) then, iterate on other segments
            for segidx in range(self.esp8266v2_header.segment_count):
                load_addr, data_len = self.read_segment_header(li)
                file_off, data = self.read_segment_data(li, data_len)
                yield file_off, load_addr, data
        else:
            li.seek(prefix_header_len if img_kind is ESP_IMAGE_KIND_8266 else (prefix_header_len + extra_header_len), 0)
            for segidx in range(self.segment_count):
                load_addr, data_len = self.read_segment_header(li)
                file_off, data = self.read_segment_data(li, data_len)
                yield file_off, load_addr, data

    EMPTY_EXTRA_HEADER = (
        0, # "wp_spin",
        0, # "spi_pin_drv_0",
        0, # "spi_pin_drv_1",
        0, # "spi_pin_drv_2",
        ESP_CHIP_ID_INVALID, # "chip_id",
        0, # "min_chip_rev",
        0, # "min_chip_rev_full",
        0, # "max_chip_rev_full",
        0, # "reserved_0",
        0, # "reserved_1",
        0, # "reserved_2",
        0, # "reserved_3",
        0, # "hash_appended"
    )

    @staticmethod
    def _from_linput(li):
        prefix_fmt = "<4BI"
        prefix_tpl = read_struct(li, prefix_fmt)
        if prefix_tpl[0] not in [0xE9, 0xEA]:
            return
        esp8266_header_end_off = li.tell()
        try:
            extra_fmt = "<4BHBHH4B?"
            extra_tpl = read_struct(li, extra_fmt)
        except:
            extra_tpl = esp_image_header_t.EMPTY_EXTRA_HEADER

        candidate = esp_image_header_t._make(prefix_tpl + extra_tpl)
        candidate_img_kind = candidate.get_image_kind(strict=False)
        debug("candidate_img_kind: %s" % candidate_img_kind)
        debug(candidate)
        if candidate_img_kind is ESP_IMAGE_KIND_NONE:
            return
        elif candidate_img_kind is ESP_IMAGE_KIND_8266:
            return esp_image_header_t._make(prefix_tpl + esp_image_header_t.EMPTY_EXTRA_HEADER)
        elif candidate_img_kind is ESP_IMAGE_KIND_8266_V2:
            li.seek(esp8266_header_end_off, 0)
            # Skip IROM segment
            _, data_len = candidate.read_segment_header(li)
            li.seek(data_len, 1)

            # read v2 hdr
            v2_tpl = read_struct(li, prefix_fmt)
            if v2_tpl[0] != 0xE9:
                return
            v2_hdr = esp_image_header_t._make(v2_tpl + esp_image_header_t.EMPTY_EXTRA_HEADER)

            h = esp_image_header_t._make(prefix_tpl + esp_image_header_t.EMPTY_EXTRA_HEADER)
            h.esp8266v2_header = v2_hdr
            return h
        else:
            return esp_image_header_t._make(prefix_tpl + extra_tpl)


def accept_file(li, filename):
    """"""

    try:

        header = esp_image_header_t._from_linput(li)
        if not header:
            return 0

        img_kind = header.get_image_kind()
        if img_kind is not ESP_IMAGE_KIND_NONE:
            return {"format" : img_kind, "processor" : header.get_processor() }

        return 0

    except ReadError:
        return 0


def load_file(li, neflags, format):
    """"""

    def load_json(file):
        with open(resolve_absolute_path(file), "r") as f:
            return json.load(f)

    def read_binary_data(file, len, file_offs):
        with open(resolve_absolute_path(file), "rb") as f:
            if file_offs is not None:
                f.seek(file_offs)
            return f.read(len) if len is not None else f.read()

    def to_int(hex):
        if hex is None:
            return None
        return int(hex, 0)

    def file_exists(file):
        return os.path.isfile(resolve_absolute_path(file)) if file is not None else False

    header = esp_image_header_t._from_linput(li)
    img_kind = header.get_image_kind()
    rom_file = ESP_IMAGE_KIND_TO_ROM_FILE.get(img_kind, None)
    rom = load_json(rom_file) if rom_file is not None else {}

    ida_idp.set_processor_type(header.get_processor(), ida_idp.SETPROC_LOADER)
    ida_ida.inf_set_app_bitness(32);

    def get_segment_name(addr):
        for m in rom.get("memory_map", []):
            if addr >= to_int(m[0]) and addr < to_int(m[1]):
                return m[2]

    def get_segment_class(name):
        return {
            "DPORT": "DATA",
            "IRAM": "CODE",
            "DRAM": "DATA",
            "IROM": "CODE",
            "DROM": "CONST",
            "RTC_IRAM": "CODE",
            "RTC_DRAM": "DATA",
            "RTC_DATA": "DATA",
            "DIRAM_IRAM": "CODE",
            "DIRAM_DRAM": "DATA",
            "DIRAM": None,
            "EXTRAM_DATA": "DATA",
            "CACHE_APP": "CODE",
            "CACHE_PRO": "CODE",
            "IROM_MASK": "CODE",
            "DROM_MASK": "CONST",
        } [name]

    try:
        for file_off, load_addr, data in header.segments(li):
            seg_name = get_segment_name(load_addr)
            if seg_name == "PADDING":
                continue
            if seg_name is None:
                ida_loader.mem2base(data, load_addr, file_off)
                ida_segment.add_segm(0, load_addr, load_addr + len(data), None, None)
            else:
                ida_loader.mem2base(data, load_addr, file_off)
                ida_segment.add_segm(0, load_addr, load_addr + len(data), seg_name, get_segment_class(seg_name))

    except ReadError as e:
        import traceback
        traceback.print_exc()
        print("WARNING: Failed to load some segment(s): %s" % (e,));

    ida_entry.add_entry(0, header.entry_addr, "entry", 1)

    for segment in rom.get("segments", []):
        load_addr = to_int(segment["load_addr"])
        segment_name = get_segment_name(load_addr)
        data_file = segment["data"].get("file", None)
        data_len = to_int(segment["data"].get("len", None))
        if file_exists(data_file):
            file_offs = to_int(segment["data"].get("file_offs", None))
            data = read_binary_data(data_file, data_len, file_offs)
            if data_len is None:
                data_len = len(data)
            ida_loader.mem2base(data, load_addr, file_offs if file_offs is not None else 0)
            ida_segment.add_segm(0, load_addr, load_addr + data_len, segment_name, get_segment_class(segment_name))
        else:
            if data_file is not None:
                print("File '%s' is not found!" % data_file)
            ida_segment.add_segm(0, load_addr, load_addr + data_len, segment_name, "XTRN")

    for symbol in rom.get("symbols", []):
        addr = to_int(symbol[1])
        ida_name.force_name(addr, symbol[0])
        if not ida_bytes.is_loaded(addr):
            ida_bytes.create_byte(addr, 4)

    return 1
