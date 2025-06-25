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

#include "obfuscated_string.hpp"   
#include "integrity_constants.hpp" 
#include "secure_memory.hpp"       

namespace Dralyxor {
    template<typename Obfuscated_String_Type>

    class Secure_Accessor {
        private:
            using Parent_Obfuscated_String = Obfuscated_String_Type;
            using CharT = typename Parent_Obfuscated_String::CharT;
            static constexpr size_t N_storage = Parent_Obfuscated_String::storage_n;
            static_assert(N_storage > 0, "Secure_Accessor requires Obfuscated_String with N_storage > 0.");
             
            static constexpr size_t fragment_count_val = (N_storage >= 4) ? 4 : N_storage;

            static constexpr size_t fragment_buffer_size_calc() {
                if constexpr (N_storage == 0)
                    return 1;

                if constexpr (fragment_count_val == 0)
                    return 1;

                size_t base = N_storage / fragment_count_val;
                size_t remainder = N_storage % fragment_count_val;

                return base + (remainder > 0 ? 1 : 0);
            }

            static constexpr size_t fragment_buffer_size = fragment_buffer_size_calc() > 0 ? fragment_buffer_size_calc() : 1;

            Obfuscated_String_Type& parent_ref_;
            CharT reconstructed_plain_buffer_[N_storage]{};
            CharT fragments_storage_[fragment_count_val][fragment_buffer_size]{};
            
            const CharT* current_access_ptr_;
            bool initialization_done_successfully_;

            uint32_t _accessor_integrity_canary1;
            uint32_t _accessor_integrity_canary2;

            size_t fragments_data_checksum_expected_;
            size_t fragments_data_checksum_reconstructed_;

            void Initialize_Internal_Accessor_Canaries() noexcept {
                _accessor_integrity_canary1 = Detail::accessor_integrity_canary_seed;
                _accessor_integrity_canary2 = ~Detail::accessor_integrity_canary_seed;
            }

            bool Verify_Internal_Accessor_Canaries() const noexcept {
                return (_accessor_integrity_canary1 == Detail::accessor_integrity_canary_seed) && (_accessor_integrity_canary2 == ~Detail::accessor_integrity_canary_seed);
            }
            
            size_t Calculate_Current_Fragments_Checksum() const noexcept {
                if constexpr (N_storage == 0 || fragment_count_val == 0 || fragment_buffer_size == 0)
                    return 0;
                
                size_t current_checksum = 0;
                size_t chars_processed_total = 0;

                for (size_t i = 0; i < fragment_count_val; ++i) {
                    size_t base_chars_in_frag = N_storage / fragment_count_val;
                    size_t chars_in_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);

                    for (size_t j = 0; j < chars_in_this_fragment; ++j) {
                        if (j < fragment_buffer_size) {
                            current_checksum = (current_checksum << 3) | (current_checksum >> (sizeof(size_t) * 8 - 3));
                            current_checksum ^= static_cast<size_t>(fragments_storage_[i][j]) + j;
                        }
                        else
                            break;
                    }

                    chars_processed_total += chars_in_this_fragment;

                    if(chars_processed_total >= N_storage -1)
                        break;
                }

                return current_checksum;
            }

            void Clear_All_Internal_Buffers() noexcept {
                Detail::Secure_Clear_Memory(reconstructed_plain_buffer_);

                if constexpr (fragment_count_val > 0 && fragment_buffer_size > 0) {
                    for (size_t i = 0; i < fragment_count_val; ++i)
                        Detail::Secure_Clear_Memory(fragments_storage_[i]);
                }

                current_access_ptr_ = nullptr;
                initialization_done_successfully_ = false;
                fragments_data_checksum_expected_ = 0xDEADBEEF;
                fragments_data_checksum_reconstructed_ = 0xBEEFDEAD;
            }
        public:
            explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), fragments_data_checksum_reconstructed_(1) {
                Initialize_Internal_Accessor_Canaries();

                if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                    Clear_All_Internal_Buffers();
                    _accessor_integrity_canary1 = 0;

                    return;
                }

                if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
                    Clear_All_Internal_Buffers();
                    _accessor_integrity_canary1 = 0;

                    return;
                }

                if constexpr (N_storage > 0) {
                    const CharT* plain_text_source = parent_ref_.storage_;
                    size_t source_idx = 0;

                    for (size_t i = 0; i < fragment_count_val; ++i) {
                        size_t base_chars_in_frag = N_storage / fragment_count_val;
                        size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                        
                        for (size_t j = 0; j < fragment_buffer_size; ++j) {
                            if (j < chars_for_this_fragment && source_idx < N_storage)
                                fragments_storage_[i][j] = plain_text_source[source_idx++];
                            else
                                fragments_storage_[i][j] = (CharT)0;
                        }

                        if(source_idx >= N_storage)
                            break;
                    }

                    fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum();
                }
                else
                    fragments_data_checksum_expected_ = 0;
                
                if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                    Clear_All_Internal_Buffers();
                    _accessor_integrity_canary1 = 0;

                    return;
                }

                initialization_done_successfully_ = true;
            }
                
            ~Secure_Accessor() {
                Clear_All_Internal_Buffers();
            }
            
            Secure_Accessor(const Secure_Accessor&) = delete;
            Secure_Accessor& operator=(const Secure_Accessor&) = delete;
            Secure_Accessor(Secure_Accessor&& other) noexcept = delete;
            Secure_Accessor& operator=(Secure_Accessor&& other) noexcept = delete;
            
            const CharT* Get() noexcept {
                if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries())
                    return (Clear_All_Internal_Buffers(), nullptr);

                if (!current_access_ptr_) {
                    if constexpr (N_storage == 0)
                         return reconstructed_plain_buffer_;
                    
                    if constexpr (N_storage > 0) {
                        size_t buffer_write_idx = 0;

                        for (size_t i = 0; i < fragment_count_val; ++i) {
                             size_t base_chars_in_frag = N_storage / fragment_count_val;
                             size_t chars_in_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);

                            for (size_t j = 0; j < chars_in_this_fragment; ++j) {
                                if (j < fragment_buffer_size && buffer_write_idx < N_storage)
                                    reconstructed_plain_buffer_[buffer_write_idx++] = fragments_storage_[i][j];
                                else
                                    break;
                            }

                            if (buffer_write_idx >= N_storage)
                                break;
                        }

                        if (buffer_write_idx < N_storage)
                            reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                        else if (N_storage > 0)
                            reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;

                        fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
                    }

                    if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                        Clear_All_Internal_Buffers();
                        _accessor_integrity_canary1 = 0;

                        return nullptr;
                    }

                    current_access_ptr_ = reconstructed_plain_buffer_;
                }
                
                if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                    Clear_All_Internal_Buffers();
                    _accessor_integrity_canary1 = 0;

                    return nullptr;
                }
                
                return current_access_ptr_;
            }

            operator const CharT*() noexcept {
                return Get();
            }

            const CharT* operator->() noexcept {
                return Get();
            }
    };
}