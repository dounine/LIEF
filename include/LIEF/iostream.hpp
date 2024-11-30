/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIEF_OSTREAM_H
#define LIEF_OSTREAM_H

#include <limits>
#include <ios>
#include <cstdint>
#include <cstring>
#include <vector>
#include <array>

#include "LIEF/span.hpp"
#include "LIEF/endianness_support.hpp"

#define B0(a) (a & 0xFF)
#define B1(a) (a >> 8 & 0xFF)
#define B2(a) (a >> 16 & 0xFF)
#define B3(a) (a >> 24 & 0xFF)
namespace LIEF {

    class vector_iostream {
    public:
        static size_t uleb128_size(uint64_t value);

        static size_t sleb128_size(int64_t value);

        using pos_type = std::streampos;
        using off_type = std::streamoff;

        vector_iostream() = default;

        vector_iostream(bool endian_swap) :
                endian_swap_(endian_swap) {}

        void reserve(size_t size) {
            raw_.reserve(size);
        }

        std::string base64() {
            return encode_string(reinterpret_cast<const char *>(raw_.data()), raw_.size());
        }


        vector_iostream &put(uint8_t c);

        vector_iostream &write(const uint8_t *s, std::streamsize n);

        vector_iostream &write(span<const uint8_t> sp) {
            return write(sp.data(), sp.size());
        }

        vector_iostream &write(std::vector<uint8_t> s) {
            return write(s.data(), s.size());
        }

        vector_iostream &write(const std::string &s) {
            return write(reinterpret_cast<const uint8_t *>(s.c_str()), s.size() + 1);
        }

        vector_iostream &write(size_t count, uint8_t value) {
            raw_.insert(std::end(raw_), count, value);
            current_pos_ += count;
            return *this;
        }

        vector_iostream &write_sized_int(uint64_t value, size_t size) {
            const uint64_t stack_val = value;
            return write(reinterpret_cast<const uint8_t *>(&stack_val), size);
        }

        vector_iostream &write(const vector_iostream &other) {
            return write(other.raw());
        }

        template<class T, typename = typename std::enable_if<
                std::is_standard_layout<T>::value && std::is_trivial<T>::value>::type>
        vector_iostream &write(const T &t) {
            const auto pos = static_cast<size_t>(tellp());
            if (raw_.size() < (pos + sizeof(T))) {
                raw_.resize(pos + sizeof(T));
            }
            if (endian_swap_) {
                T tmp = t;
                swap_endian(&tmp);
                memcpy(raw_.data() + pos, &tmp, sizeof(T));
            } else {
                memcpy(raw_.data() + pos, &t, sizeof(T));
            }
            current_pos_ += sizeof(T);
            return *this;
        }

        vector_iostream &align(size_t alignment, uint8_t fill = 0);

        template<typename T, size_t size>
        vector_iostream &write(const std::array<T, size> &t) {
            static_assert(std::numeric_limits<T>::is_integer, "Requires integer type");
            for (T val: t) {
                write<T>(val);
            }
            return *this;
        }


        template<typename T>
        vector_iostream &write(const std::vector<T> &elements) {
            for (const T &e: elements) {
                write(e);
            }
            return *this;
        }

        vector_iostream &write_uleb128(uint64_t value);

        vector_iostream &write_sleb128(int64_t value);

        vector_iostream &get(std::vector<uint8_t> &c) {
            c = raw_;
            return *this;
        }

        vector_iostream &move(std::vector<uint8_t> &c) {
            c = std::move(raw_);
            return *this;
        }

        vector_iostream &flush() {
            return *this;
        }

        size_t size() const {
            return raw_.size();
        }

        // seeks:
        pos_type tellp() const {
            return current_pos_;
        }

        vector_iostream &seekp(pos_type p) {
            current_pos_ = p;
            return *this;
        }

        vector_iostream &seekp(vector_iostream::off_type p, std::ios_base::seekdir dir);

        const std::vector<uint8_t> &raw() const {
            return raw_;
        }

        std::vector<uint8_t> &raw() {
            return raw_;
        }

        void set_endian_swap(bool swap) {
            endian_swap_ = swap;
        }

    private:
        pos_type current_pos_ = 0;
        std::vector<uint8_t> raw_;
        bool endian_swap_ = false;


        char get_b64_char(int nIndex) {
            static const char szTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            if (nIndex >= 0 && nIndex < 64) {
                return szTable[nIndex];
            }
            return '=';
        }

        std::string encode_string(const char *szSrc, int nSrcLen) {
            std::vector<char *> m_arrEnc;
            if (0 == nSrcLen) {
                nSrcLen = (int) strlen(szSrc);
            }

            if (nSrcLen <= 0) {
                return "";
            }

            char *szEnc = new char[nSrcLen * 3 + 128];
            m_arrEnc.push_back(szEnc);

            int i = 0;
            auto *psrc = (unsigned char *) szSrc;
            char *p64 = szEnc;
            for (i = 0; i < nSrcLen - 3; i += 3) {
                unsigned long ulTmp = *(unsigned long *) psrc;
                int b0 = get_b64_char((B0(ulTmp) >> 2) & 0x3F);
                int b1 = get_b64_char((B0(ulTmp) << 6 >> 2 | B1(ulTmp) >> 4) & 0x3F);
                int b2 = get_b64_char((B1(ulTmp) << 4 >> 2 | B2(ulTmp) >> 6) & 0x3F);
                int b3 = get_b64_char((B2(ulTmp) << 2 >> 2) & 0x3F);
                *((unsigned long *) p64) = b0 | b1 << 8 | b2 << 16 | b3 << 24;
                p64 += 4;
                psrc += 3;
            }

            if (i < nSrcLen) {
                int rest = nSrcLen - i;
                unsigned long ulTmp = 0;
                for (int j = 0; j < rest; ++j) {
                    *(((unsigned char *) &ulTmp) + j) = *psrc++;
                }
                p64[0] = get_b64_char((B0(ulTmp) >> 2) & 0x3F);
                p64[1] = get_b64_char((B0(ulTmp) << 6 >> 2 | B1(ulTmp) >> 4) & 0x3F);
                p64[2] = rest > 1 ? get_b64_char((B1(ulTmp) << 4 >> 2 | B2(ulTmp) >> 6) & 0x3F) : '=';
                p64[3] = rest > 2 ? get_b64_char((B2(ulTmp) << 2 >> 2) & 0x3F) : '=';
                p64 += 4;
            }
            *p64 = '\0';
            return szEnc;
        }
    };


}
#endif
