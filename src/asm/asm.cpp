/* Copyright 2022 - 2024 R. Thomas
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
#include "LIEF/asm/Instruction.hpp"
#include "LIEF/asm/Engine.hpp"
#include "LIEF/Abstract/Binary.hpp"

#include "internal_utils.hpp"
#include "messages.hpp"
#include "logging.hpp"

namespace LIEF {

// ----------------------------------------------------------------------------
// Abstract/Binary.hpp
// ----------------------------------------------------------------------------

Binary::instructions_it Binary::disassemble(uint64_t/*address*/, size_t/*size*/) const {
  LIEF_ERR(ASSEMBLY_NOT_SUPPORTED);
  return make_empty_iterator<assembly::Instruction>();
}

Binary::instructions_it Binary::disassemble(uint64_t/*address*/) const {
  LIEF_ERR(ASSEMBLY_NOT_SUPPORTED);
  return make_empty_iterator<assembly::Instruction>();
}

Binary::instructions_it Binary::disassemble(const std::string&/*function*/) const {
  LIEF_ERR(ASSEMBLY_NOT_SUPPORTED);
  return make_empty_iterator<assembly::Instruction>();
}

Binary::instructions_it Binary::disassemble(const uint8_t*, size_t, uint64_t) const {
  LIEF_ERR(ASSEMBLY_NOT_SUPPORTED);
  return make_empty_iterator<assembly::Instruction>();
}

assembly::Engine* Binary::get_engine(uint64_t) const {
  return nullptr;
}

namespace assembly {
namespace details {
class Instruction {};
class InstructionIt {};

class Engine {};
}

// ----------------------------------------------------------------------------
// asm/Instruction.hpp
// ----------------------------------------------------------------------------

Instruction::Iterator::Iterator(std::unique_ptr<details::InstructionIt>) :
  impl_(nullptr)
{}

Instruction::Iterator::Iterator(const Iterator&) :
  impl_(nullptr)
{}

Instruction::Iterator& Instruction::Iterator::operator=(const Iterator&) {
  return *this;
}

Instruction::Iterator::Iterator(Iterator&&) noexcept = default;
Instruction::Iterator& Instruction::Iterator::operator=(Iterator&&) noexcept = default;

Instruction::Iterator& Instruction::Iterator::operator++() {
  return *this;
}

std::unique_ptr<Instruction> Instruction::Iterator::operator*() const {
  return nullptr;
}

bool operator==(const Instruction::Iterator&, const Instruction::Iterator&) {
  return true;
}

Instruction::Iterator::~Iterator() = default;

Instruction::Instruction(std::unique_ptr<details::Instruction>) :
  impl_(nullptr)
{}

std::unique_ptr<Instruction> Instruction::create(std::unique_ptr<details::Instruction>) {
  return nullptr;
}

Instruction::~Instruction() = default;

uint64_t Instruction::address() const {
  return 0;
}

size_t Instruction::size() const {
  return 0;
}

const std::vector<uint8_t>& Instruction::raw() const {
  static std::vector<uint8_t> empty;
  return empty;
}

std::string Instruction::mnemonic() const {
  return "";
}

std::string Instruction::to_string() const {
  return "";
}

// ----------------------------------------------------------------------------
// asm/Engine.hpp
// ----------------------------------------------------------------------------
Engine::Engine(std::unique_ptr<details::Engine>) :
  impl_(nullptr)
{}

Engine::Engine(Engine&&) noexcept {

}

Engine& Engine::operator=(Engine&&) noexcept {
  return *this;
}

Engine::instructions_it Engine::disassemble(const uint8_t*, size_t, uint64_t) {
  return make_empty_iterator<assembly::Instruction>();
}

Engine::~Engine() = default;
}
}
