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
#include <type_traits> 
//
#include "prng.hpp"      
#include "detection.hpp" 

#ifndef _DRALYXOR_ROTR8
    #define _DRALYXOR_ROTR8(v, n) ( static_cast<uint8_t>(((v) >> (n)) | ((v) << (8 - (n)))) )
#endif

#ifndef _DRALYXOR_ROTL8
    #define _DRALYXOR_ROTL8(v, n) ( static_cast<uint8_t>(((v) << (n)) | ((v) >> (8 - (n)))) )
#endif

namespace Dralyxor {
    namespace Detail {
        enum class Micro_Operation_Code : uint8_t {
            NOP,
            XOR,
            ADD,
            SUB,
            ROTR,
            ROTL,
            SWAP_NIB,
            END_OF_PROGRAM
        };

        struct Micro_Instruction {
            Micro_Operation_Code op_code{};
            uint8_t operand{};
        };

        static constexpr size_t max_micro_instructions = 8;
        
        using Byte_Transform_Applier = uint8_t (*)(uint8_t, const Micro_Instruction&, bool, uint8_t);

        _DRALYXOR_CONSTEXPR_FUNC static uint8_t Get_Micro_Program_Obfuscation_Key(uint64_t base_seed) {
            return static_cast<uint8_t>((base_seed >> 24) ^ (base_seed >> 40));
        }

        _DRALYXOR_CONSTEXPR_FUNC static Micro_Instruction Obfuscate_Deobfuscate_Instruction(Micro_Instruction instr, uint8_t key) {
            instr.op_code = static_cast<Micro_Operation_Code>(static_cast<uint8_t>(instr.op_code) ^ key);
            instr.operand = instr.operand ^ key;

            return instr;
        }

        _DRALYXOR_CONSTEXPR_FUNC static uint8_t Apply_Single_Op(uint8_t byte_val, Micro_Operation_Code op_code, uint8_t op_val) {
            switch (op_code) {
                case Micro_Operation_Code::XOR:
                    return byte_val ^ op_val;
                case Micro_Operation_Code::ADD:
                    return static_cast<uint8_t>(byte_val + op_val);
                case Micro_Operation_Code::SUB:
                    return static_cast<uint8_t>(byte_val - op_val);
                case Micro_Operation_Code::ROTR:
                    return _DRALYXOR_ROTR8(byte_val, (op_val % 7) + 1);
                case Micro_Operation_Code::ROTL:
                    return _DRALYXOR_ROTL8(byte_val, (op_val % 7) + 1);
                case Micro_Operation_Code::SWAP_NIB:
                    return static_cast<uint8_t>(((byte_val & 0x0F) << 4) | ((byte_val & 0xF0) >> 4));
                case Micro_Operation_Code::NOP:
                case Micro_Operation_Code::END_OF_PROGRAM:
                default:
                    return byte_val;
            }
        }
    

        _DRALYXOR_CONSTEXPR_FUNC uint8_t Applier_Style_Direct(uint8_t val, const Micro_Instruction& instr_orig, bool is_decrypt_mode, uint8_t prng_key_for_operand_mod) {
            uint8_t modified_operand = static_cast<uint8_t>(instr_orig.operand ^ prng_key_for_operand_mod);
            Micro_Operation_Code op_to_apply = instr_orig.op_code;

            if (is_decrypt_mode) {
                switch (instr_orig.op_code) {
                    case Micro_Operation_Code::ADD:
                        op_to_apply = Micro_Operation_Code::SUB;
                        break;
                    case Micro_Operation_Code::SUB:
                        op_to_apply = Micro_Operation_Code::ADD;
                        break;
                    case Micro_Operation_Code::ROTR:
                        op_to_apply = Micro_Operation_Code::ROTL;
                        break;
                    case Micro_Operation_Code::ROTL:
                        op_to_apply = Micro_Operation_Code::ROTR;
                        break;
                    default:
                        break;
                }
            }

            if (op_to_apply == Micro_Operation_Code::NOP || op_to_apply == Micro_Operation_Code::END_OF_PROGRAM)
                return val;

            return Apply_Single_Op(val, op_to_apply, modified_operand);
        }

        _DRALYXOR_CONSTEXPR_FUNC uint8_t Applier_Style_DoubleLayer(uint8_t val, const Micro_Instruction& instr_orig, bool is_decrypt_mode, uint8_t prng_key_for_operand_mod) {
            if (instr_orig.op_code == Micro_Operation_Code::NOP || instr_orig.op_code == Micro_Operation_Code::END_OF_PROGRAM)
                return val;

            uint8_t mod_op1 = static_cast<uint8_t>(instr_orig.operand ^ prng_key_for_operand_mod);
            Micro_Operation_Code op1_orig = instr_orig.op_code;
            uint8_t mod_op2 = static_cast<uint8_t>(instr_orig.operand ^ (prng_key_for_operand_mod >> 2) ^ 0xAA);
            Micro_Operation_Code op2_orig = instr_orig.op_code;
            Micro_Operation_Code op1_eff = op1_orig;
            Micro_Operation_Code op2_eff = op2_orig;

            auto invert_op_type = [](Micro_Operation_Code code_in) -> Micro_Operation_Code {
                switch (code_in) {
                    case Micro_Operation_Code::ADD:
                        return Micro_Operation_Code::SUB;
                    case Micro_Operation_Code::SUB:
                        return Micro_Operation_Code::ADD;
                    case Micro_Operation_Code::ROTR:
                        return Micro_Operation_Code::ROTL;
                    case Micro_Operation_Code::ROTL:
                        return Micro_Operation_Code::ROTR;
                    default:
                        return code_in;
                }
            };

            if (is_decrypt_mode) {
                op1_eff = invert_op_type(op1_orig);
                op2_eff = invert_op_type(op2_orig);

                val = Apply_Single_Op(val, op2_eff, mod_op2);
                val = Apply_Single_Op(val, op1_eff, mod_op1);
            }
            else {
                val = Apply_Single_Op(val, op1_eff, mod_op1);
                val = Apply_Single_Op(val, op2_eff, mod_op2);
            }

            return val;
        }
        
        _DRALYXOR_CONSTEXPR_FUNC Byte_Transform_Applier Select_Applier(uint8_t prng_selector_value) {
            constexpr int num_applier_styles = 2;

            switch (prng_selector_value % num_applier_styles) {
                case 0:
                    return &Applier_Style_Direct;
                case 1:
                    return &Applier_Style_DoubleLayer;
                default:
                    return &Applier_Style_Direct;
            }
        }

        struct Micro_Program_Cipher {
            template<typename CharT>

            _DRALYXOR_CONSTEXPR_FUNC static void Transform_Compile_Time_Consistent(CharT* data, size_t N_data_elements_to_transform, const Micro_Instruction obfuscated_program_param[], size_t num_total_instructions_in_program_array, uint64_t base_seed, bool is_decrypt_transform) {
                if (N_data_elements_to_transform == 0 || data == nullptr)
                    return;
                
                Micro_Instruction local_plain_program[max_micro_instructions > 0 ? max_micro_instructions : 1];
                uint8_t program_obf_key = Get_Micro_Program_Obfuscation_Key(base_seed);
                size_t effective_instruction_count = 0;

                if constexpr (max_micro_instructions > 0) {
                    for (size_t i = 0; i < num_total_instructions_in_program_array; ++i) {
                        if (i < max_micro_instructions)
                            local_plain_program[i] = Obfuscate_Deobfuscate_Instruction(obfuscated_program_param[i], program_obf_key);
                    }
                }

                if (num_total_instructions_in_program_array == 0)
                    return;


                Constexpr_PRNG prng_operand_modifier(base_seed);
                Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL);

                for (size_t i_elem = 0; i_elem < N_data_elements_to_transform; ++i_elem) {
                    uint8_t prng_key_for_ops_in_elem = prng_operand_modifier.Key();
                    prng_operand_modifier = prng_operand_modifier.Next();

                    _DRALYXOR_IF_CONSTEXPR (sizeof(CharT) == 1) {
                        uint8_t val = static_cast<uint8_t>(data[i_elem]);
                        Byte_Transform_Applier current_applier = Select_Applier(prng_applier_selector.Key());
                        prng_applier_selector = prng_applier_selector.Next();

                        if (!is_decrypt_transform) {
                            for (size_t j = 0; j < num_total_instructions_in_program_array; ++j)
                                val = current_applier(val, local_plain_program[j], false, prng_key_for_ops_in_elem);
                        }
                        else {
                            for (size_t j_rev = 0; j_rev < num_total_instructions_in_program_array; ++j_rev) {
                                size_t j_idx = num_total_instructions_in_program_array - 1 - j_rev;
                                val = current_applier(val, local_plain_program[j_idx], true, prng_key_for_ops_in_elem);
                            }
                        }

                        data[i_elem] = static_cast<CharT>(val);
                    }
                    else {
                        _DRALYXOR_IF_CONSTEXPR (std::is_integral<CharT>::value) {
                            using UnsignedCharT = typename std::make_unsigned<CharT>::type;
                            UnsignedCharT key_val_unsigned = static_cast<UnsignedCharT>(prng_key_for_ops_in_elem);
                            UnsignedCharT key_mask_unsigned = 0;

                            _DRALYXOR_IF_CONSTEXPR (sizeof(CharT) == 2)
                                key_mask_unsigned = (key_val_unsigned << 8) | key_val_unsigned;
                            else _DRALYXOR_IF_CONSTEXPR (sizeof(CharT) == 4)
                                key_mask_unsigned = (key_val_unsigned << 24) | (key_val_unsigned << 16) | (key_val_unsigned << 8)  | key_val_unsigned;
                            else {
                                for(size_t b_idx = 0; b_idx < sizeof(CharT); ++b_idx)
                                    key_mask_unsigned |= (key_val_unsigned << (b_idx * 8));
                            }

                            data[i_elem] = static_cast<CharT>(static_cast<UnsignedCharT>(data[i_elem]) ^ key_mask_unsigned);
                        }
                        else
                            data[i_elem] ^= static_cast<CharT>(prng_key_for_ops_in_elem);
                    }
                }
            }
        };
    }
}