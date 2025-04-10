/*
    In UTF-16 code units in range 0xD800 to 0xDFFF have special meaning.

    In a vectorized algorithm we want to examine the most significant
    nibble in order to select a fast path. If none of highest nibbles
    are 0xD (13), than we are sure that UTF-16 chunk in a vector
    register is valid.

    Let us analyze what we need to check if the nibble is 0xD. The
    value of the preceding nibble determines what we have:

    0xd000 .. 0xd7ff - a valid word
    0xd800 .. 0xdbff - low surrogate
    0xdc00 .. 0xdfff - high surrogate

    Other constraints we have to consider:
    - there must not be two consecutive low surrogates (0xd800 .. 0xdbff)
    - there must not be two consecutive high surrogates (0xdc00 .. 0xdfff)
    - there must not be sole low surrogate nor high surrogate

    We're going to build three bitmasks based on the 3rd nibble:
    - V = valid word,
    - L = low surrogate (0xd800 .. 0xdbff)
    - H = high surrogate (0xdc00 .. 0xdfff)

      0   1   2   3   4   5   6   7    <--- word index
    [ V | L | H | L | H | V | V | L ]
      1   0   0   0   0   1   1   0     - V = valid masks
      0   1   0   1   0   0   0   1     - L = low surrogate
      0   0   1   0   1   0   0   0     - H high surrogate


      1   0   0   0   0   1   1   0   V = valid masks
      0   1   0   1   0   0   0   0   a = L & (H >> 1)
      0   0   1   0   1   0   0   0   b = a << 1
      1   1   1   1   1   1   1   0   c = V | a | b
                                  ^
                                  the last bit can be zero, we just consume 7
   code units and recheck this word in the next iteration
*/

/* Returns:
   - pointer to the last unprocessed character (a scalar fallback should check
   the rest);
   - nullptr if an error was detected.
*/
template <endianness big_endian>
const char16_t *lsx_validate_utf16(const char16_t *input, size_t size) {
  const char16_t *end = input + size;

  const auto v_d8 = simd8<uint8_t>::splat(0xd8);
  const auto v_f8 = simd8<uint8_t>::splat(0xf8);
  const auto v_fc = simd8<uint8_t>::splat(0xfc);
  const auto v_dc = simd8<uint8_t>::splat(0xdc);

  while (input + simd16<uint16_t>::SIZE * 2 < end) {
    // 0. Load data: since the validation takes into account only higher
    //    byte of each word, we compress the two vectors into one which
    //    consists only the higher bytes.
    auto in0 = simd16<uint16_t>(input);
    auto in1 =
        simd16<uint16_t>(input + simd16<uint16_t>::SIZE / sizeof(char16_t));
    if (big_endian) {
      in0 = in0.swap_bytes();
      in1 = in1.swap_bytes();
    }
    const auto in = simd8<uint8_t>(__lsx_vssrlni_bu_h(in1.value, in0.value, 8));

    // 1. Check whether we have any 0xD800..DFFF word (0b1101'1xxx'yyyy'yyyy).
    const auto surrogates_wordmask = (in & v_f8) == v_d8;
    const uint16_t surrogates_bitmask =
        static_cast<uint16_t>(surrogates_wordmask.to_bitmask());
    if (surrogates_bitmask == 0x0000) {
      input += 16;
    } else {
      // 2. We have some surrogates that have to be distinguished:
      //    - low  surrogates: 0b1101'10xx'yyyy'yyyy (0xD800..0xDBFF)
      //    - high surrogates: 0b1101'11xx'yyyy'yyyy (0xDC00..0xDFFF)
      //
      //    Fact: high surrogate has 11th bit set (3rd bit in the higher word)

      // V - non-surrogate code units
      //     V = not surrogates_wordmask
      const uint16_t V = static_cast<uint16_t>(~surrogates_bitmask);

      // H - word-mask for high surrogates: the six highest bits are 0b1101'11
      const auto vH = (in & v_fc) == v_dc;
      const uint16_t H = static_cast<uint16_t>(vH.to_bitmask());

      // L - word mask for low surrogates
      //     L = not H and surrogates_wordmask
      const uint16_t L = static_cast<uint16_t>(~H & surrogates_bitmask);

      const uint16_t a = static_cast<uint16_t>(
          L & (H >> 1)); // A low surrogate must be followed by high one.
                         // (A low surrogate placed in the 7th register's word
                         // is an exception we handle.)
      const uint16_t b = static_cast<uint16_t>(
          a << 1); // Just mark that the opinput - startite fact is hold,
                   // thanks to that we have only two masks for valid case.
      const uint16_t c = static_cast<uint16_t>(
          V | a | b); // Combine all the masks into the final one.

      if (c == 0xffff) {
        // The whole input register contains valid UTF-16, i.e.,
        // either single code units or proper surrogate pairs.
        input += 16;
      } else if (c == 0x7fff) {
        // The 15 lower code units of the input register contains valid UTF-16.
        // The 15th word may be either a low or high surrogate. It the next
        // iteration we 1) check if the low surrogate is followed by a high
        // one, 2) reject sole high surrogate.
        input += 15;
      } else {
        return nullptr;
      }
    }
  }

  return input;
}

template <endianness big_endian>
const result lsx_validate_utf16_with_errors(const char16_t *input,
                                            size_t size) {
  const char16_t *start = input;
  const char16_t *end = input + size;

  const auto v_d8 = simd8<uint8_t>::splat(0xd8);
  const auto v_f8 = simd8<uint8_t>::splat(0xf8);
  const auto v_fc = simd8<uint8_t>::splat(0xfc);
  const auto v_dc = simd8<uint8_t>::splat(0xdc);

  while (input + simd16<uint16_t>::SIZE * 2 < end) {
    // 0. Load data: since the validation takes into account only higher
    //    byte of each word, we compress the two vectors into one which
    //    consists only the higher bytes.
    auto in0 = simd16<uint16_t>(input);
    auto in1 =
        simd16<uint16_t>(input + simd16<uint16_t>::SIZE / sizeof(char16_t));

    if (big_endian) {
      in0 = in0.swap_bytes();
      in1 = in1.swap_bytes();
    }

    const auto in = simd8<uint8_t>(__lsx_vssrlni_bu_h(in1.value, in0.value, 8));

    // 1. Check whether we have any 0xD800..DFFF word (0b1101'1xxx'yyyy'yyyy).
    const auto surrogates_wordmask = (in & v_f8) == v_d8;
    const uint16_t surrogates_bitmask =
        static_cast<uint16_t>(surrogates_wordmask.to_bitmask());
    if (surrogates_bitmask == 0x0000) {
      input += 16;
    } else {
      // 2. We have some surrogates that have to be distinguished:
      //    - low  surrogates: 0b1101'10xx'yyyy'yyyy (0xD800..0xDBFF)
      //    - high surrogates: 0b1101'11xx'yyyy'yyyy (0xDC00..0xDFFF)
      //
      //    Fact: high surrogate has 11th bit set (3rd bit in the higher word)

      // V - non-surrogate code units
      //     V = not surrogates_wordmask
      const uint16_t V = static_cast<uint16_t>(~surrogates_bitmask);

      // H - word-mask for high surrogates: the six highest bits are 0b1101'11
      const auto vH = (in & v_fc) == v_dc;
      const uint16_t H = static_cast<uint16_t>(vH.to_bitmask());

      // L - word mask for low surrogates
      //     L = not H and surrogates_wordmask
      const uint16_t L = static_cast<uint16_t>(~H & surrogates_bitmask);

      const uint16_t a = static_cast<uint16_t>(
          L & (H >> 1)); // A low surrogate must be followed by high one.
                         // (A low surrogate placed in the 7th register's word
                         // is an exception we handle.)
      const uint16_t b = static_cast<uint16_t>(
          a << 1); // Just mark that the opinput - startite fact is hold,
                   // thanks to that we have only two masks for valid case.
      const uint16_t c = static_cast<uint16_t>(
          V | a | b); // Combine all the masks into the final one.

      if (c == 0xffff) {
        // The whole input register contains valid UTF-16, i.e.,
        // either single code units or proper surrogate pairs.
        input += 16;
      } else if (c == 0x7fff) {
        // The 15 lower code units of the input register contains valid UTF-16.
        // The 15th word may be either a low or high surrogate. It the next
        // iteration we 1) check if the low surrogate is followed by a high
        // one, 2) reject sole high surrogate.
        input += 15;
      } else {
        return result(error_code::SURROGATE, input - start);
      }
    }
  }

  return result(error_code::SUCCESS, input - start);
}
