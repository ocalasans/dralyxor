/* ============================================================================= *
 * Dralyxor - The Definitive C++ String Obfuscator ↓                             *
 * An advanced, header-only C++ library for compile-time string obfuscation.     *
 * ============================================================================= *
 *                                                                               *
 * Copyright (c) 2025, Calasans | All rights reserved.                           *
 *                                                                               *
 * Developed by: Calasans                                                        *
 * Repository: https://github.com/ocalasans/dralyxor                             *
 *                                                                               *
 * ============================================================================= *
 *                                                                               *
 * Licensed under the MIT License (MIT);                                         *
 * you may not use this file except in compliance with the License.              *
 * You may obtain a copy of the License at:                                      *
 *                                                                               *
 *     https://opensource.org/licenses/MIT                                       *
 *                                                                               *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    *
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      *
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   *
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        *
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, *
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN     *
 * THE SOFTWARE.                                                                 *
 *                                                                               *
 * ============================================================================= */

#pragma once

#include <cstdint>
#include <utility>
#include <type_traits>
//
#include "detection.hpp"
#include "env_traits.hpp"
#include "prng.hpp"
#include "algorithms.hpp"
#include "integrity_constants.hpp"
#include "anti_debug.hpp"
#include "secure_memory.hpp"

namespace Dralyxor {
    namespace Detail {
        template<typename CharT>

        _DRALYXOR_CONSTEXPR_FUNC static uint16_t Calculate_String_Content_Checksum(const CharT* data, size_t num_data_chars) {
            if (!data || num_data_chars == 0)
                return 0x0000;

            uint16_t checksum_val = 0x5A5A;

            for (size_t i = 0; i < num_data_chars; ++i) {
#if _DRALYXOR_CPP_VERSION >= 17
                _DRALYXOR_IF_CONSTEXPR (std::is_integral_v<CharT> || std::is_enum_v<CharT>) {
#else
                _DRALYXOR_IF_CONSTEXPR (std::is_integral<CharT>::value || std::is_enum<CharT>::value) {
#endif
                    using Unsigned_Equivalent = typename std::make_unsigned<CharT>::type;
                    Unsigned_Equivalent val_unsigned = static_cast<Unsigned_Equivalent>(data[i]);

                    for (size_t b = 0; b < sizeof(CharT); ++b) {
                        uint8_t current_byte = static_cast<uint8_t>((val_unsigned >> (b * 8)) & 0xFF);
                        checksum_val ^= static_cast<uint16_t>(current_byte);

                        if (b % 2 != 0)
                            checksum_val ^= (static_cast<uint16_t>(current_byte) << 8);
                            
                        checksum_val = (checksum_val << 1) | (checksum_val >> 15);
                    }
                }
                else {
                    const uint8_t* char_bytes = reinterpret_cast<const uint8_t*>(&data[i]);

                    for (size_t b = 0; b < sizeof(CharT); ++b) {
                        checksum_val ^= static_cast<uint16_t>(char_bytes[b]);

                        if (b % 2 != 0)
                            checksum_val ^= (static_cast<uint16_t>(char_bytes[b]) << 8);
                        
                        checksum_val = (checksum_val << 1) | (checksum_val >> 15);
                    }
                }
            }

            return checksum_val == 0 ? static_cast<uint16_t>(0xFFFF) : checksum_val;
        }

        _DRALYXOR_CONSTEXPR_FUNC static uint16_t Obfuscate_Deobfuscate_Short_Value(uint16_t val, uint64_t seed_for_key, uint8_t salt) {
            uint8_t key_byte1 = static_cast<uint8_t>(((seed_for_key >> 16) ^ salt) & 0xFF);
            uint8_t key_byte2 = static_cast<uint8_t>(((seed_for_key >> 32) ^ (salt * 3)) & 0xFF);
            uint16_t obf_key = static_cast<uint16_t>((key_byte1 << 8) | key_byte2);

            if (obf_key == 0)
                obf_key = 0xDA0D;
            
            return val ^ obf_key;
        }
    }

    template<typename Obfuscated_String_Type_Param> class Secure_Accessor;
    template<typename _CharT, size_t _N_Incl_Null, int Instance_Counter, uint64_t User_Seed = 0>

    class Obfuscated_String {
        public:
            using CharT = _CharT;
            static constexpr size_t storage_n = _N_Incl_Null;
            static_assert(storage_n > 0, "Obfuscated_String storage_n must be greater than 0 (must include null terminator).");

            friend class Secure_Accessor<Obfuscated_String<CharT, storage_n, Instance_Counter, User_Seed>>;
                
            _DRALYXOR_CONSTEVAL Obfuscated_String(const CharT* input_string);
            ~Obfuscated_String();

            Obfuscated_String(const Obfuscated_String&) = delete;
            Obfuscated_String& operator=(const Obfuscated_String&) = delete;
            Obfuscated_String(Obfuscated_String&& other) noexcept;
            Obfuscated_String& operator=(Obfuscated_String&& other) noexcept;

            uint64_t Decrypt() noexcept;
            uint64_t Encrypt() noexcept;

            bool is_decrypted() const volatile noexcept {
                return decrypted_;
            }

            _DRALYXOR_CONSTEXPR_FUNC bool Verify_Parent_Canaries() const {
                return Verify_Internal_Canaries();
            }

        private:
            void Clear_Internal_Data() noexcept;

            static constexpr uint64_t compile_time_seed = (User_Seed != 0) ? (User_Seed ^ ((uint64_t)Instance_Counter << 32) ^ storage_n) : (Detail::fnv1a_hash(__DATE__ __TIME__) ^ ((uint64_t)Instance_Counter << 32) ^ storage_n);
            static constexpr uint8_t content_checksum_obf_salt = 0xDA;

            CharT storage_[storage_n]{};
            Detail::Micro_Instruction micro_program_[Detail::max_micro_instructions > 0 ? Detail::max_micro_instructions : 1]{};
            size_t num_actual_instructions_in_program_;

            uint32_t _internal_integrity_canary1;
            uint32_t _internal_integrity_canary2;
            uint16_t _content_checksum_obfuscated;

            volatile bool decrypted_{false};
            bool moved_from_{false};
            
            _DRALYXOR_CONSTEXPR_FUNC void Initialize_Internal_Canaries() {
                _internal_integrity_canary1 = Detail::integrity_canary_value;
                _internal_integrity_canary2 = ~Detail::integrity_canary_value;
            }

            _DRALYXOR_CONSTEXPR_FUNC bool Verify_Internal_Canaries() const {
                return (_internal_integrity_canary1 == Detail::integrity_canary_value) && (_internal_integrity_canary2 == ~Detail::integrity_canary_value);
            }

            _DRALYXOR_CONSTEVAL void Generate_Micro_Program_Instructions(uint64_t prng_seed) {
                Detail::Constexpr_PRNG prng_generator(prng_seed);
                num_actual_instructions_in_program_ = 0;

                if constexpr (Detail::max_micro_instructions == 0 || storage_n <= 1)
                    return;

                size_t current_instr_idx = 0;

                while(current_instr_idx < Detail::max_micro_instructions) {
                    uint8_t instruction_type_choice = prng_generator.Key() % 100;
                    prng_generator = prng_generator.Next();

                    if (instruction_type_choice < 60) {
                        uint8_t op_choice_val = prng_generator.Key();
                        prng_generator = prng_generator.Next();

                        uint8_t operand_val = prng_generator.Key();
                        prng_generator = prng_generator.Next();

                        Detail::Micro_Operation_Code selected_code;

                        switch (op_choice_val % 6) {
                            case 0:
                                selected_code = Detail::Micro_Operation_Code::XOR;
                                break;
                            case 1:
                                selected_code = Detail::Micro_Operation_Code::ADD;
                                break;
                            case 2:
                                selected_code = Detail::Micro_Operation_Code::SUB;
                                break;
                            case 3:
                                selected_code = Detail::Micro_Operation_Code::ROTR;
                                break;
                            case 4:
                                selected_code = Detail::Micro_Operation_Code::ROTL;
                                break;
                            case 5:
                                selected_code = Detail::Micro_Operation_Code::SWAP_NIB;
                                break;
                            default:
                                selected_code = Detail::Micro_Operation_Code::NOP;
                                break;
                        }

                        if (selected_code == Detail::Micro_Operation_Code::SWAP_NIB)
                            operand_val = 0;
                        else if (selected_code == Detail::Micro_Operation_Code::ROTR || selected_code == Detail::Micro_Operation_Code::ROTL)
                            operand_val = (operand_val % 7) + 1;
                        
                        micro_program_[current_instr_idx++] = {selected_code, operand_val};
                    }
                    else if (instruction_type_choice < 80)
                        micro_program_[current_instr_idx++] = {Detail::Micro_Operation_Code::NOP, 0};
                    else {
                        if (current_instr_idx + 1 < Detail::max_micro_instructions) {
                            uint8_t logical_nop_type = prng_generator.Key() % 2;
                            prng_generator = prng_generator.Next();

                            uint8_t logical_nop_operand = prng_generator.Key();
                            prng_generator = prng_generator.Next();

                            if (logical_nop_type == 0) {
                                if (logical_nop_operand == 0)
                                    logical_nop_operand = 1;

                                micro_program_[current_instr_idx++] = {Detail::Micro_Operation_Code::ADD, logical_nop_operand};
                                micro_program_[current_instr_idx++] = {Detail::Micro_Operation_Code::SUB, logical_nop_operand};
                            }
                            else {
                                uint8_t rot_amount = (logical_nop_operand % 7) + 1;

                                micro_program_[current_instr_idx++] = {Detail::Micro_Operation_Code::ROTL, rot_amount};
                                micro_program_[current_instr_idx++] = {Detail::Micro_Operation_Code::ROTR, rot_amount};
                            }
                        }
                        else
                            micro_program_[current_instr_idx++] = {Detail::Micro_Operation_Code::NOP, 0};
                    }
                }
                num_actual_instructions_in_program_ = current_instr_idx;
                
                if (num_actual_instructions_in_program_ == 0 && Detail::max_micro_instructions > 0) {
                    if (Detail::max_micro_instructions >= 1) {
                        micro_program_[0] = {Detail::Micro_Operation_Code::XOR, prng_generator.Key()};
                        num_actual_instructions_in_program_ = 1;
                    }
                }
            }

            _DRALYXOR_CONSTEVAL void Obfuscate_Internal_Micro_Program() {
                if constexpr (Detail::max_micro_instructions > 0) {
                    if (num_actual_instructions_in_program_ > 0) {
                        uint8_t key = Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed);

                        for (size_t i = 0; i < num_actual_instructions_in_program_; ++i) {
                            if (i < Detail::max_micro_instructions)
                                micro_program_[i] = Detail::Obfuscate_Deobfuscate_Instruction(micro_program_[i], key);
                        }
                    }
                }
            }
    };

    template<typename C, size_t N_NULL, int CTR, uint64_t U_SEED>

    _DRALYXOR_CONSTEVAL Obfuscated_String<C, N_NULL, CTR, U_SEED>::Obfuscated_String(const CharT* input) : num_actual_instructions_in_program_(0), _content_checksum_obfuscated(0), decrypted_(false), moved_from_(false) {
        Initialize_Internal_Canaries();
        Generate_Micro_Program_Instructions(compile_time_seed ^ 0xDEADBEEFC0FFEEULL);

        for (size_t i = 0; i < storage_n; ++i)
            storage_[i] = input[i];

        if constexpr (storage_n > 1) {
            uint16_t plain_checksum = Detail::Calculate_String_Content_Checksum(input, storage_n - 1);
            _content_checksum_obfuscated = Detail::Obfuscate_Deobfuscate_Short_Value(plain_checksum, compile_time_seed, content_checksum_obf_salt);
        }
        else
            _content_checksum_obfuscated = Detail::Obfuscate_Deobfuscate_Short_Value(UINT16_C(0x0000), compile_time_seed, content_checksum_obf_salt);
        
        Obfuscate_Internal_Micro_Program();
                 
        if constexpr (storage_n > 1) {
            if (num_actual_instructions_in_program_ > 0)
                Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false);
        }
    }

    template<typename C, size_t N_NULL, int CTR, uint64_t U_SEED>

    Obfuscated_String<C, N_NULL, CTR, U_SEED>::~Obfuscated_String() {
        if (!moved_from_)
            Clear_Internal_Data();
    }
    
    template<typename C, size_t N_NULL, int CTR, uint64_t U_SEED>

    Obfuscated_String<C, N_NULL, CTR, U_SEED>::Obfuscated_String(Obfuscated_String&& other) noexcept : decrypted_(other.decrypted_), num_actual_instructions_in_program_(other.num_actual_instructions_in_program_), _internal_integrity_canary1(other._internal_integrity_canary1), 
        _internal_integrity_canary2(other._internal_integrity_canary2), _content_checksum_obfuscated(other._content_checksum_obfuscated), moved_from_(false) {
        
        for(size_t i = 0; i < storage_n; ++i)
            storage_[i] = other.storage_[i];
        
        if constexpr (Detail::max_micro_instructions > 0) {
            for(size_t i = 0; i < Detail::max_micro_instructions; ++i)
                micro_program_[i] = other.micro_program_[i];
        }

        other.moved_from_ = true;

        if (other.Verify_Internal_Canaries()) {
            Detail::Secure_Clear_Memory_Raw(other.storage_, sizeof(CharT) * storage_n);

            if constexpr (Detail::max_micro_instructions > 0)
                Detail::Secure_Clear_Memory_Raw(other.micro_program_, sizeof(other.micro_program_));

            other.num_actual_instructions_in_program_ = 0;
            other.decrypted_ = false;
            other._content_checksum_obfuscated = 0;
        }
    }
    
    template<typename C, size_t N_NULL, int CTR, uint64_t U_SEED>

    Obfuscated_String<C, N_NULL, CTR, U_SEED>& Obfuscated_String<C, N_NULL, CTR, U_SEED>::operator=(Obfuscated_String&& other) noexcept {
        if (this != &other) {
            if (!moved_from_)
                Clear_Internal_Data();

            decrypted_ = other.decrypted_;
            num_actual_instructions_in_program_ = other.num_actual_instructions_in_program_;
            _internal_integrity_canary1 = other._internal_integrity_canary1;
            _internal_integrity_canary2 = other._internal_integrity_canary2;
            _content_checksum_obfuscated = other._content_checksum_obfuscated;
            moved_from_ = false;

            for(size_t i = 0; i < storage_n; ++i)
                storage_[i] = other.storage_[i];
            
            if constexpr (Detail::max_micro_instructions > 0) {
                for(size_t i = 0; i < Detail::max_micro_instructions; ++i)
                    micro_program_[i] = other.micro_program_[i];
            }

            other.moved_from_ = true;

            if(other.Verify_Internal_Canaries()){
                Detail::Secure_Clear_Memory_Raw(other.storage_, sizeof(CharT) * storage_n);

                if constexpr (Detail::max_micro_instructions > 0)
                    Detail::Secure_Clear_Memory_Raw(other.micro_program_, sizeof(other.micro_program_));

                other.num_actual_instructions_in_program_ = 0;
                other.decrypted_ = false;
                other._content_checksum_obfuscated = 0;
            }
        }

        return *this;
    }
    
    template<typename C, size_t N_NULL, int CTR, uint64_t U_SEED>

    uint64_t Obfuscated_String<C, N_NULL, CTR, U_SEED>::Decrypt() noexcept {
        if (!Verify_Internal_Canaries()) {
            Clear_Internal_Data();
            decrypted_ = false;

            return Detail::integrity_compromised_magic;
        }

        if (!decrypted_) {
            uint64_t runtime_key_mod = Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2);

            if (runtime_key_mod == Detail::integrity_compromised_magic) {
                Clear_Internal_Data();
                decrypted_ = false;

                return Detail::integrity_compromised_magic;
            }

            if (!Verify_Internal_Canaries()) {
                Clear_Internal_Data();
                decrypted_ = false;

                return Detail::integrity_compromised_magic;
            }
            
            if constexpr (storage_n > 1) {
                if (num_actual_instructions_in_program_ > 0)
                    Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true);
            }
            
            uint16_t current_decrypted_checksum;

            if constexpr (storage_n > 1)
                current_decrypted_checksum = Detail::Calculate_String_Content_Checksum(storage_, storage_n - 1);
            else
                current_decrypted_checksum = Detail::Calculate_String_Content_Checksum<CharT>(nullptr, 0);

            uint16_t reference_checksum_deobfuscated = Detail::Obfuscate_Deobfuscate_Short_Value(_content_checksum_obfuscated, compile_time_seed, content_checksum_obf_salt);

            if (current_decrypted_checksum != reference_checksum_deobfuscated) {
                Clear_Internal_Data();
                decrypted_ = false;

                return Detail::integrity_compromised_magic;
            }

            decrypted_ = true;

            if (!Verify_Internal_Canaries()) {
                Clear_Internal_Data();
                decrypted_ = false;

                return Detail::integrity_compromised_magic;
            }
        }

        return 0;
    }

    template<typename C, size_t N_NULL, int CTR, uint64_t U_SEED>

    uint64_t Obfuscated_String<C, N_NULL, CTR, U_SEED>::Encrypt() noexcept {
        if (!Verify_Internal_Canaries()) {
            Clear_Internal_Data();
            decrypted_ = false;

            return Detail::integrity_compromised_magic;
        }

        if (decrypted_) {
            uint16_t current_plain_checksum;

            if constexpr (storage_n > 1)
                current_plain_checksum = Detail::Calculate_String_Content_Checksum(storage_, storage_n - 1);
            else
                current_plain_checksum = Detail::Calculate_String_Content_Checksum<CharT>(nullptr, 0);

            uint16_t expected_plain_checksum_deobfuscated = Detail::Obfuscate_Deobfuscate_Short_Value(_content_checksum_obfuscated, compile_time_seed, content_checksum_obf_salt);
            
            if (current_plain_checksum != expected_plain_checksum_deobfuscated) {
                Clear_Internal_Data();
                decrypted_ = false;

                return Detail::integrity_compromised_magic;
            }

            uint64_t runtime_key_mod = Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2);

            if (runtime_key_mod == Detail::integrity_compromised_magic) {
                Clear_Internal_Data();
                decrypted_ = false;

                return Detail::integrity_compromised_magic;
            }

            if (!Verify_Internal_Canaries()) {
                Clear_Internal_Data();
                decrypted_ = false;

                return Detail::integrity_compromised_magic;
            }

            if constexpr (storage_n > 1) {
                if (num_actual_instructions_in_program_ > 0)
                    Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, false);
            }
            
            decrypted_ = false;

            if (!Verify_Internal_Canaries())
                return (Clear_Internal_Data(), Detail::integrity_compromised_magic);
        }

        return 0;
    }
    
    template<typename C, size_t N_NULL, int CTR, uint64_t U_SEED>

    void Obfuscated_String<C, N_NULL, CTR, U_SEED>::Clear_Internal_Data() noexcept {
        Detail::Secure_Clear_Memory(storage_);
        
        if constexpr (Detail::max_micro_instructions > 0)
            Detail::Secure_Clear_Memory(micro_program_);

        num_actual_instructions_in_program_ = 0;
        decrypted_ = false;
    }
}