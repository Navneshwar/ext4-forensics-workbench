from app.forensics.ext4_structs import (
    EXT4_MAGIC,
    parse_superblock,
    parse_inode,
)


def test_parse_minimal_superblock():
    data = bytearray(1024)
    data[0:4] = (100).to_bytes(4, "little")
    data[4:8] = (10000).to_bytes(4, "little")
    data[20:24] = (1).to_bytes(4, "little")
    data[24:28] = (2).to_bytes(4, "little")  # 4096-byte blocks
    data[32:36] = (32768).to_bytes(4, "little")
    data[40:44] = (8192).to_bytes(4, "little")
    data[56:58] = EXT4_MAGIC.to_bytes(2, "little")
    data[88:90] = (256).to_bytes(2, "little")
    sb = parse_superblock(bytes(data))
    assert sb.block_size == 4096
    assert sb.inode_size == 256
    assert sb.magic == EXT4_MAGIC


def test_deleted_inode_signal():
    data = bytearray(256)
    data[0:2] = (0x81A4).to_bytes(2, "little")       # regular file + mode
    data[4:8] = (1234).to_bytes(4, "little")
    data[20:24] = (100).to_bytes(4, "little")        # deletion time
    data[26:28] = (0).to_bytes(2, "little")          # links count
    inode = parse_inode(bytes(data), 123, 0, 4096)
    assert inode.is_deleted
    assert inode.file_type == "regular"
    assert inode.size == 1234
