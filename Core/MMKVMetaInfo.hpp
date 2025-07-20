/*
 * Tencent is pleased to support the open source community by making
 * MMKV available.
 *
 * Copyright (C) 2018 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Licensed under the BSD 3-Clause License (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *       https://opensource.org/licenses/BSD-3-Clause
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MMKV_MMKVMETAINFO_H
#define MMKV_MMKVMETAINFO_H
#ifdef __cplusplus

#include "aes/AESCrypt.h"
#include <cstdint>
#include <cstring>

namespace mmkv {

enum MMKVVersion : uint32_t {
    MMKVVersionDefault = 0,

    // record full write back count
    MMKVVersionSequence = 1,

    // store random iv for encryption
    MMKVVersionRandomIV = 2,

    // store actual size together with crc checksum, try to reduce file corruption
    MMKVVersionActualSize = 3,

    // store extra flags
    MMKVVersionFlag = 4,

    // preserved for next use
    MMKVVersionNext = 5,

    // always large than next, a placeholder for error check
    MMKVVersionHolder = MMKVVersionNext + 1,
};

constexpr uint32_t MMKV_BACKUP_MAGIC = 0x4D4D4B56; // 'MMKV' in hex

struct MMKVBackupInfo {
    uint32_t m_magic = 0;           // MMKV_BACKUP_MAGIC when backup is valid
    uint32_t m_restorePoint = 0;    // restore point in the file, where the backup data starts
    uint32_t m_backupDataSize = 0;  // size of backup data
    uint32_t m_restoredFileCRC = 0; // CRC of the complete file after restoration

    bool hasData() const {
        return m_magic == MMKV_BACKUP_MAGIC && m_backupDataSize > 0;
    }

    void clearData() {
        memset(this, 0, sizeof(MMKVBackupInfo));
    }

    void update(uint32_t restorePoint, uint32_t backupDataSize,  uint32_t restoredFileCRC) {
        m_magic = MMKV_BACKUP_MAGIC;
        m_restorePoint = restorePoint;
        m_backupDataSize = backupDataSize;
        m_restoredFileCRC = restoredFileCRC;
    }
};

struct MMKVMetaInfo {
    uint32_t m_crcDigest = 0;
    uint32_t m_version = MMKVVersionSequence;
    uint32_t m_sequence = 0; // full write-back count
    uint8_t m_vector[AES_KEY_LEN] = {};
    uint32_t m_actualSize = 0;

    // confirmed info: it's been synced to file
    struct {
        uint32_t lastActualSize = 0;
        uint32_t lastCRCDigest = 0;
        uint32_t _reserved[16] = {};
    } m_lastConfirmedMetaInfo;

    uint64_t m_flags = 0;

    MMKVBackupInfo m_backupInfo;

    // reserved for future use
    uint32_t m_reserved[16];

    enum MMKVMetaInfoFlag : uint64_t {
        EnableKeyExipre = 1 << 0,
    };
    bool hasFlag(MMKVMetaInfoFlag flag) { return (m_flags & flag) != 0; }
    void setFlag(MMKVMetaInfoFlag flag) { m_flags |= flag; }
    void unsetFlag(MMKVMetaInfoFlag flag) { m_flags &= ~flag; }

    void write(void *ptr) const {
        MMKV_ASSERT(ptr);
        memcpy(ptr, this, sizeof(MMKVMetaInfo));
    }

    void writeCRCAndActualSizeOnly(void *ptr) const {
        MMKV_ASSERT(ptr);
        auto other = (MMKVMetaInfo *) ptr;
        other->m_crcDigest = m_crcDigest;
        other->m_actualSize = m_actualSize;
    }

    void writeBackupInfoOnly(void *ptr) const{
        MMKV_ASSERT(ptr);
        auto other = (MMKVMetaInfo*)ptr;
        other->m_backupInfo = m_backupInfo;
    }

    void read(const void *ptr) {
        MMKV_ASSERT(ptr);
        memcpy(this, ptr, sizeof(MMKVMetaInfo));
    }
};

static_assert(sizeof(MMKVMetaInfo) <= (4 * 1024), "MMKVMetaInfo lager than one pagesize");

} // namespace mmkv

#endif
#endif //MMKV_MMKVMETAINFO_H
