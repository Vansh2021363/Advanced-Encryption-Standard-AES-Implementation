#include <iostream>
#include <unordered_map>
#include <bitset>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <array>
#include <future>

using namespace std;

// Declaration of two unordered_maps to store S-box and Inverse S-box mappings.
unordered_map<string, string> sBoxMap;
unordered_map<string, string> inverseSBoxMap;

// The AES S-box (Substitution Box), a 16x16 matrix that performs non-linear substitution of bytes.
// This is used during the SubBytes step of AES encryption.
string s_box[16][16] = {
    {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},
    {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},
    {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},
    {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
    {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
    {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
    {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
    {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
    {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
    {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
    {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
    {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
    {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
    {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
    {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
    {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}
};

// The AES Inverse S-box (used in decryption), a 16x16 matrix.
// This is used during the Inverse SubBytes step in AES decryption.
string inverseSBox[16][16] = {
    {"52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB"},
    {"7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB"},
    {"54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E"},
    {"08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25"},
    {"72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92"},
    {"6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84"},
    {"90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06"},
    {"D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B"},
    {"3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73"},
    {"96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E"},
    {"47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B"},
    {"FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4"},
    {"1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F"},
    {"60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF"},
    {"A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61"},
    {"17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"}
};


// Constructs the AES S-box map for encryption (SubBytes).
// Maps hexadecimal keys (e.g., "0A", "1F") to values in the S-box.
void construct_s_box () {
    string key;
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            key = "";
            if (i<10) {
                key+=('0' + i);
            }
            else {
                key+=('A' + i - 10);
            }
            if (j<10) {
                key+=('0' + j);
            }
            else {
                key+=('A' + j - 10);
            }
            sBoxMap[key] = s_box[i][j];
        }
    }    
}



// Constructs the inverse AES S-box map for decryption (InvSubBytes).
// Maps hexadecimal keys (e.g., "0A", "1F") to values in the inverse S-box.
void construct_inverse_s_box () {
    string key;
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            key = "";

            if (i<10) {
                key+=('0' + i);
            }
            else {
                key+=('A' + i - 10);
            }
            if (j<10) {
                key+=('0' + j);
            }
            else {
                key+=('A' + j - 10);
            }
            inverseSBoxMap[key] = (inverseSBox[i][j]);
        }
    } 
}


// Copies data from one 4x4 string matrix (matrix1) to another (matrix2).
void copy_data(string matrix1[4][4], string (&matrix2)[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            matrix2[i][j] = matrix1[i][j];
        }
    }
}


// Converts a hexadecimal string to its binary representation.
// Each hex digit (0-9, A-F) is mapped to a 4-bit binary string.
string hex_string_to_binary(string hex) {
    string binary_string = "";
    for (char hex_digit : hex) {
        switch (hex_digit) {
            case '0':
                binary_string += "0000";
                break;
            case '1':
                binary_string += "0001";
                break;
            case '2':
                binary_string += "0010";
                break;
            case '3':
                binary_string += "0011";
                break;
            case '4':
                binary_string += "0100";
                break;
            case '5':
                binary_string += "0101";
                break;
            case '6':
                binary_string += "0110";
                break;
            case '7':
                binary_string += "0111";
                break;
            case '8':
                binary_string += "1000";
                break;
            case '9':
                binary_string += "1001";
                break;
            case 'A':
                binary_string += "1010";
                break;
            case 'B':
                binary_string += "1011";
                break;
            case 'C':
                binary_string += "1100";
                break;
            case 'D':
                binary_string += "1101";
                break;
            case 'E':
                binary_string += "1110";
                break;
            case 'F':
                binary_string += "1111";
                break;
        }
    }
    return binary_string;
}


// Converts an 8-bit binary string to its hexadecimal representation.
// Splits the binary string into two 4-bit parts and maps each part to its corresponding hex value.
string binary_to_hex(string binary) {
    string result = "";
    string temp1 = binary.substr(0, 4); // First 4 bits
    string temp2 = binary.substr(4, 4); // Last 4 bits

    switch (stoi(temp1, nullptr, 2)) {
        case 0: result += "0"; break;
        case 1: result += "1"; break;
        case 2: result += "2"; break;
        case 3: result += "3"; break;
        case 4: result += "4"; break;
        case 5: result += "5"; break;
        case 6: result += "6"; break;
        case 7: result += "7"; break;
        case 8: result += "8"; break;
        case 9: result += "9"; break;
        case 10: result += "A"; break;
        case 11: result += "B"; break;
        case 12: result += "C"; break;
        case 13: result += "D"; break;
        case 14: result += "E"; break;
        case 15: result += "F"; break;
    }

    switch (stoi(temp2, nullptr, 2)) {
        case 0: result += "0"; break;
        case 1: result += "1"; break;
        case 2: result += "2"; break;
        case 3: result += "3"; break;
        case 4: result += "4"; break;
        case 5: result += "5"; break;
        case 6: result += "6"; break;
        case 7: result += "7"; break;
        case 8: result += "8"; break;
        case 9: result += "9"; break;
        case 10: result += "A"; break;
        case 11: result += "B"; break;
        case 12: result += "C"; break;
        case 13: result += "D"; break;
        case 14: result += "E"; break;
        case 15: result += "F"; break;
    }

    return result;
}


// Converts a 16-character string into a 4x4 key matrix.
// Each character in the input string is converted to a 2-digit hexadecimal value
// and placed into the matrix in a column-major order.
void stringToKey(const string& input, string key[4][4]) {
    for (int i = 0; i < 16; ++i) {
        stringstream ss;
        ss << hex << uppercase << setw(2) << setfill('0') << static_cast<int>(input[i]);
        key[i % 4][i / 4] = ss.str();
    }
}


// Performs an XOR operation on four binary strings and returns the result as a hexadecimal string.
// Each input string (s1, s2, s3, s4) is expected to be an 8-bit binary string.
// The XOR operation is applied bit by bit, and the result is converted to hexadecimal.
string xor_operation(string s1, string s2, string s3, string s4) {
    int temp1[8], temp2[8], temp3[8], temp4[8];
    for (int i = 0; i < 8; i++) {
        temp1[i] = s1[i] - '0';
        temp2[i] = s2[i] - '0';
        temp3[i] = s3[i] - '0';
        temp4[i] = s4[i] - '0';
    }

    string result = "";

    for (int i = 0; i < 8; i++) {
        result += to_string(temp1[i] ^ temp2[i] ^ temp3[i] ^ temp4[i]);
    }

    result = binary_to_hex(result);
    return result;
}


// Performs Galois Field (GF) multiplication of two hexadecimal strings (string_1 and string_2).
// The function converts hex strings to binary, applies multiplication in GF(2^8), and reduces the result modulo the AES irreducible polynomial (x^8 + x^4 + x^3 + x + 1).
string GF_multiplication(string string_1, string string_2) {
    string temp1 = hex_string_to_binary(string_1); // Convert hex to binary
    string temp2 = hex_string_to_binary(string_2); // Convert hex to binary
    int a[8], b[8];
    for (int i = 0; i < 8; i++) {
        a[i] = temp1[i] - '0';
        b[i] = temp2[i] - '0';
    }
    int c[15] = {0}; // Result of multiplication before modulo reduction
    int m[] = {1, 0, 0, 0, 1, 1, 0, 0, 1}; // Irreducible polynomial coefficients for GF(2^8)

    // Perform multiplication in GF(2)
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            if (a[7 - i] && b[7 - j]) {
                c[14 - i - j] += 1;
            }
        }
    }

    // Reduce modulo irreducible polynomial (x^8 + x^4 + x^3 + x + 1)
    for (int i = 0; i < 15; i++) {
        c[i] = c[i] % 2;
    }
    if (c[6]) {
        c[6] = 0;
        c[14] ^= 1;
        c[13] ^= 1;
        c[11] ^= 1;
        c[10] ^= 1;
    }
    if (c[5]) {
        c[5] = 0;
        c[13] ^= 1;
        c[12] ^= 1;
        c[10] ^= 1;
        c[9] ^= 1;
    }
    if (c[4]) {
        c[4] = 0;
        c[12] ^= 1;
        c[11] ^= 1;
        c[9] ^= 1;
        c[8] ^= 1;
    }
    if (c[3]) {
        c[3] = 0;
        c[11] ^= 1;
        c[10] ^= 1;
        c[8] ^= 1;
        c[7] ^= 1;
    }
    if (c[2]) {
        c[2] = 0;
        c[14] ^= 1;
        c[13] ^= 1;
        c[11] ^= 1;
        c[9] ^= 1;
        c[7] ^= 1;
    }
    if (c[1]) {
        c[1] = 0;
        c[14] ^= 1;
        c[12] ^= 1;
        c[11] ^= 1;
        c[8] ^= 1;
    }
    if (c[0]) {
        c[0] = 0;
        c[13] ^= 1;
        c[11] ^= 1;
        c[10] ^= 1;
        c[7] ^= 1;
    }

    // Convert the result back to binary string
    string result = "";
    for (int i = 7; i < 15; i++) {
        result += to_string(c[i]);
    }
    return result;
}


// Substitutes each byte in the 4x4 matrix using the AES S-box for the SubBytes step.
// Uses multithreading to perform substitutions row-wise in parallel.
void substitue_bytes(string (&matrix)[4][4]) {
    std::array<std::thread, 4> threads;

    // Create a thread for each row in the matrix
    for (int row = 0; row < 4; row++) {
        threads[row] = std::thread([&, row]() {
            for (int col = 0; col < 4; col++) {
                matrix[row][col] = sBoxMap[matrix[row][col]]; // Replace each byte using S-box
            }
        });
    }

    // Wait for all threads to complete
    for (auto &t : threads) {
        t.join();
    }
}


// Reverses the SubBytes step in AES by substituting each byte in the 4x4 matrix using the inverse S-box.
// Uses multithreading to perform substitutions row-wise in parallel.
void inverse_sub_bytes(string (&matrix)[4][4]) {
    std::array<std::thread, 4> threads;

    // Create a thread for each row in the matrix
    for (int row = 0; row < 4; row++) {
        threads[row] = std::thread([&, row]() {
            for (int col = 0; col < 4; col++) {
                matrix[row][col] = inverseSBoxMap[matrix[row][col]]; // Replace each byte using inverse S-box
            }
        });
    }

    // Wait for all threads to complete
    for (auto &t : threads) {
        t.join();
    }
}


// Performs the ShiftRows step of AES by cyclically shifting each row of the 4x4 matrix to the left.
// Each row is shifted by an offset equal to its row index (row 0: no shift, row 1: shift by 1, etc.).
// Uses multithreading to process rows in parallel for efficiency.
void shift_rows(string (&matrix)[4][4]) {
    auto shift_row = [](string (&row)[4], int shift) {
        // Cyclically shift a row by a specified number of positions
        string temp[4];
        for (int col = 0; col < 4; col++) {
            temp[col] = row[(col + shift) % 4];
        }
        for (int col = 0; col < 4; col++) {
            row[col] = temp[col];
        }
    };

    std::array<std::thread, 4> threads;

    // No shift for the first row
    threads[0] = std::thread([]() {});

    // Shift the second row by 1
    threads[1] = std::thread([&]() { shift_row(matrix[1], 1); });

    // Shift the third row by 2
    threads[2] = std::thread([&]() { shift_row(matrix[2], 2); });

    // Shift the fourth row by 3
    threads[3] = std::thread([&]() { shift_row(matrix[3], 3); });

    // Wait for all threads to complete
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
}


// Reverses the ShiftRows step of AES by cyclically shifting each row of the 4x4 matrix to the right.
// Each row is shifted by an offset equal to its row index (row 0: no shift, row 1: shift by 1, etc.).
// Uses multithreading to process rows in parallel for efficiency.
void inverse_shift_rows(string (&matrix)[4][4]) {
    auto shift_row_right = [](string (&row)[4], int shift) {
        // Cyclically shift a row to the right by a specified number of positions
        string temp[4];
        for (int col = 0; col < 4; col++) {
            temp[(col + shift) % 4] = row[col];
        }
        for (int col = 0; col < 4; col++) {
            row[col] = temp[col];
        }
    };

    std::array<std::thread, 4> threads;

    // No shift for the first row
    threads[0] = std::thread([]() {});

    // Shift the second row by 1 to the right
    threads[1] = std::thread([&]() { shift_row_right(matrix[1], 1); });

    // Shift the third row by 2 to the right
    threads[2] = std::thread([&]() { shift_row_right(matrix[2], 2); });

    // Shift the fourth row by 3 to the right
    threads[3] = std::thread([&]() { shift_row_right(matrix[3], 3); });

    // Wait for all threads to complete
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
}


// Performs the MixColumns step of AES, which mixes the data in each column of the matrix.
// The operation is based on Galois Field (GF) arithmetic and involves matrix multiplication
// with a fixed polynomial in GF(2^8). The result is stored in matrix2.
// Uses multithreading to process each column in parallel for better efficiency.
void Mix_Column(string matrix[4][4], string (&matrix2)[4][4]) {
    std::array<std::thread, 4> threads;

    for (int col = 0; col < 4; col++) {
        threads[col] = std::thread([&, col]() {
            // Compute each row of the column after the MixColumns transformation
            matrix2[0][col] = xor_operation(
                GF_multiplication("02", matrix[0][col]),
                GF_multiplication("03", matrix[1][col]),
                hex_string_to_binary(matrix[2][col]),
                hex_string_to_binary(matrix[3][col])
            );
            matrix2[1][col] = xor_operation(
                hex_string_to_binary(matrix[0][col]),
                GF_multiplication("02", matrix[1][col]),
                GF_multiplication("03", matrix[2][col]),
                hex_string_to_binary(matrix[3][col])
            );
            matrix2[2][col] = xor_operation(
                hex_string_to_binary(matrix[0][col]),
                hex_string_to_binary(matrix[1][col]),
                GF_multiplication("02", matrix[2][col]),
                GF_multiplication("03", matrix[3][col])
            );
            matrix2[3][col] = xor_operation(
                GF_multiplication("03", matrix[0][col]),
                hex_string_to_binary(matrix[1][col]),
                hex_string_to_binary(matrix[2][col]),
                GF_multiplication("02", matrix[3][col])
            );
        });
    }

    // Wait for all threads to complete
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
}


// Performs the Inverse MixColumns step of AES, which reverses the MixColumns transformation.
// The operation is based on matrix multiplication in Galois Field (GF) arithmetic using specific coefficients
// ("0E", "0B", "0D", "09") to ensure the transformation is reversible.
// The result is stored in matrix2, with multithreading used to process each column in parallel.
void Inverse_Mix_Column(string matrix[4][4], string (&matrix2)[4][4]) {
    std::array<std::thread, 4> threads;

    for (int col = 0; col < 4; col++) {
        threads[col] = std::thread([&, col]() {
            // Compute each row of the column after the Inverse MixColumns transformation
            matrix2[0][col] = xor_operation(
                GF_multiplication("0E", matrix[0][col]),
                GF_multiplication("0B", matrix[1][col]),
                GF_multiplication("0D", matrix[2][col]),
                GF_multiplication("09", matrix[3][col])
            );
            matrix2[1][col] = xor_operation(
                GF_multiplication("09", matrix[0][col]),
                GF_multiplication("0E", matrix[1][col]),
                GF_multiplication("0B", matrix[2][col]),
                GF_multiplication("0D", matrix[3][col])
            );
            matrix2[2][col] = xor_operation(
                GF_multiplication("0D", matrix[0][col]),
                GF_multiplication("09", matrix[1][col]),
                GF_multiplication("0E", matrix[2][col]),
                GF_multiplication("0B", matrix[3][col])
            );
            matrix2[3][col] = xor_operation(
                GF_multiplication("0B", matrix[0][col]),
                GF_multiplication("0D", matrix[1][col]),
                GF_multiplication("09", matrix[2][col]),
                GF_multiplication("0E", matrix[3][col])
            );
        });
    }

    // Wait for all threads to complete
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
}


// Performs the AddRoundKey step of AES, which XORs the state matrix with a round subkey.
// Each element in the state matrix is XORed with the corresponding element in the subkey matrix.
// Uses multithreading to process each row of the state matrix in parallel for efficiency.
void add_round_key(string (&state)[4][4], string subkey[4][4]) {
    std::array<std::thread, 4> threads;

    for (int row = 0; row < 4; row++) {
        threads[row] = std::thread([&, row]() {
            // XOR each element in the row with the corresponding subkey element
            for (int col = 0; col < 4; col++) {
                state[row][col] = xor_operation(
                    hex_string_to_binary(state[row][col]),
                    hex_string_to_binary(subkey[row][col]),
                    "00000000", "00000000" // Padding to maintain 4-input XOR
                );
            }
        });
    }

    // Wait for all threads to complete
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
}


// Calculates the round constant (RC) for the AES key schedule.
// The round constant is generated by multiplying "01" by 2 in Galois Field (GF) arithmetic
// for (round - 1) iterations. The result is returned as an 8-bit binary string.
string calculate_rc(int round) {
    string rc = "01"; // Initial round constant
    for (int i = 1; i < round; i++) {
        rc = binary_to_hex(GF_multiplication(rc, "02")); // Multiply by 2 in GF(2^8)
    }
    return hex_string_to_binary(rc); // Convert the final result to binary
}


// Implements the G-function used in the AES key schedule to transform a 4-byte word.
// The function rotates the word, applies the S-box substitution to each byte,
// and XORs the first byte with the round constant (RC) for the given round.
void g_function(string (&word)[4], int round) {
    // Rotate the word (left circular shift)
    swap(word[0], word[1]);
    swap(word[1], word[2]);
    swap(word[2], word[3]);

    // Substitute each byte using the S-box
    for (int i = 0; i < 4; i++) {
        word[i] = sBoxMap[word[i]];
    }

    // Calculate the round constant (RC) and XOR it with the first byte
    string RC = calculate_rc(round);
    word[0] = xor_operation(hex_string_to_binary(word[0]), RC, "00000000", "00000000");
}

// Generates a round subkey for AES by modifying the key matrix using the G-function and XOR operations.
void generate_sub_key(string (&key)[4][4], int round) {
    string word_3[4];
    for (int i = 0; i < 4; i++) {
        word_3[i] = key[i][3];
    }
    g_function(word_3, round);
    for (int i = 0; i < 4; i++) {
        key[i][0] = xor_operation(hex_string_to_binary(key[i][0]), hex_string_to_binary(word_3[i]), "00000000", "00000000");
    }

    for (int i = 1; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            key[j][i] = xor_operation(hex_string_to_binary(key[j][i - 1]), hex_string_to_binary(key[j][i]), "00000000", "00000000");
        }
    }
}


// Converts a 4x4 matrix into a single string in column-major order.
// Each element of the matrix is appended to the result string column by column.
string matrix_to_string(string matrix[4][4]) {
    string result = "";
    for (int i = 0; i < 4; i++) {        // Iterate over columns
        for (int j = 0; j < 4; j++) {    // Iterate over rows
            result += matrix[j][i];      // Append elements in column-major order
        }
    }
    return result;
}


// Converts a string into a 4x4 matrix in column-major order.
// Each 2-character substring of the input string is placed into the matrix.
void string_to_matrix(string text, string (&matrix)[4][4]) {
    int k = 0; // Index to track the position in the input string
    for (int i = 0; i < 4; i++) {        // Iterate over columns
        for (int j = 0; j < 4; j++) {    // Iterate over rows
            matrix[j][i] = text.substr(k * 2, 2); // Extract 2 characters and assign to matrix
            k++;
        }
    }
}


// Encrypts the plaintext using AES encryption for a specified number of rounds.
// Performs the standard AES operations: AddRoundKey, SubBytes, ShiftRows, and MixColumns (in all but the final round).
// Takes plaintext, the number of rounds, and the round subkeys as inputs, returning the encrypted ciphertext.
string AES_Encryption(string plaintext, int numOfRounds, string sub_key[][4][4]) {
    string ciphertext[4][4] = {""};
    string temp[4][4] = {""};

    string_to_matrix(plaintext, ciphertext);
    add_round_key(ciphertext, sub_key[0]);

    for (int i = 1; i < numOfRounds; i++) {
        substitue_bytes(ciphertext);
        shift_rows(ciphertext);
        copy_data(ciphertext, temp);
        Mix_Column(temp, ciphertext);
        add_round_key(ciphertext, sub_key[i]);
    }

    substitue_bytes(ciphertext);
    shift_rows(ciphertext);
    add_round_key(ciphertext, sub_key[numOfRounds]);

    return matrix_to_string(ciphertext);
}


// Decrypts the ciphertext using AES decryption for a specified number of rounds.
// Reverses the standard AES operations: AddRoundKey, InverseShiftRows, InverseSubBytes, and InverseMixColumns (in all but the final round).
// Takes ciphertext, the number of rounds, and the round subkeys as inputs, returning the decrypted plaintext.
string AES_Decryption(string ciphertext, int numOfRounds, string sub_key[][4][4]) {
    string plaintext[4][4] = {""};
    string temp[4][4] = {""};

    string_to_matrix(ciphertext, plaintext);
    string_to_matrix(ciphertext, temp);

    add_round_key(plaintext, sub_key[numOfRounds]);
    inverse_shift_rows(plaintext);
    inverse_sub_bytes(plaintext);

    for (int i = numOfRounds - 1; i > 0; i--) {
        add_round_key(plaintext, sub_key[i]);
        copy_data(plaintext, temp);
        Inverse_Mix_Column(temp, plaintext);
        inverse_shift_rows(plaintext);
        inverse_sub_bytes(plaintext);
    }

    add_round_key(plaintext, sub_key[0]);

    return matrix_to_string(plaintext);
}


// Converts the original text into a hexadecimal plaintext string by encoding each character as a two-digit hex value.
// Each character is first converted to an 8-bit binary string, which is then converted to its hexadecimal equivalent.
string generate_plaintext(string original_text) {
    string result = "";
    for (char c : original_text) {
        result += binary_to_hex(bitset<8>(int(c)).to_string());
    }
    return result;
}


// Converts a hexadecimal plaintext string back into the original text.
// Each 2-character hex substring is converted to an 8-bit binary string,
// which is then interpreted as an ASCII character.
string generate_originaltext(string plaintext) {
    string result = "";
    for (int i = 0; i < 16; i++) {
        result += static_cast<char>(
            stoi(hex_string_to_binary(plaintext.substr(i * 2, 2)), nullptr, 2)
        );
    }
    return result;
}




// Main function for AES encryption and decryption.
// Initializes S-box and inverse S-box asynchronously, takes user input for plaintext, key, and number of rounds,
// and performs encryption and decryption using the AES algorithm.
// Displays intermediate subkeys, encrypted ciphertext, and decrypted plaintext.
int main() {
    std::future<void> sboxFuture, inverseSboxFuture;

    // Initialize S-box and inverse S-box in parallel
    sboxFuture = std::async(std::launch::async, construct_s_box);
    inverseSboxFuture = std::async(std::launch::async, construct_inverse_s_box);

    string plaintext, strKey;
    int numOfRounds;

    // Input plaintext
    cout << "Enter Plaintext (32 digit hexadecimals): ";
    getline(cin, plaintext);

    if (plaintext.length() != 32) {
        cerr << "Error: Plaintext must be exactly 16 characters long." << endl;
        return 1;
    }

    // Input key
    cout << "Enter Key (32 digit hexadecimals): ";
    getline(cin, strKey);

    if (strKey.length() != 32) {
        cerr << "Error: Key must be exactly 16 characters long." << endl;
        return 1;
    }

    // Input number of rounds
    cout << "Enter Number of Rounds: ";
    cin >> numOfRounds;

    // Wait for S-box and inverse S-box initialization
    sboxFuture.get();
    inverseSboxFuture.get();

    // Display plaintext and key
    cout << endl;
    cout << "Plaintext(in hexadecimals): " << plaintext << endl << endl;
    cout << "Key(in hexadecimals): " << generate_plaintext(strKey) << endl << endl;

    // Generate subkeys
    string key[4][4];
    string_to_matrix(strKey, key);
    string sub_key[numOfRounds + 1][4][4] = {""};

    cout << "Sub Key 0" << endl;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            sub_key[0][i][j] = key[i][j];
            cout << sub_key[0][i][j] << " ";
        }
        cout << endl;
    }
    cout << endl;

    for (int i = 1; i <= numOfRounds; i++) {
        generate_sub_key(key, i);
        cout << "Sub Key " << i << endl;
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                sub_key[i][j][k] = key[j][k];
                cout << sub_key[i][j][k] << " ";
            }
            cout << endl;
        }
        cout << endl;
    }

    // Perform AES encryption
    cout << endl;
    cout << "------------Encryption Started----------" << endl << endl;
    string ciphertext = AES_Encryption(plaintext, numOfRounds, sub_key);

    // Perform AES decryption
    cout << "------------Decryption Started----------" << endl << endl;
    string decrypted_text = AES_Decryption(ciphertext, numOfRounds, sub_key);

    // Display results
    cout << "Encrypted Plaintext(in hexadecimals): " << ciphertext << endl << endl;
    cout << "Encrypted plaintext(in characters) with key (in hexadecimal) \"" 
         << strKey << "\" in " << numOfRounds << " rounds: " 
         << generate_originaltext(ciphertext) << endl;
    cout << endl;
    cout << "Decrypted Ciphertext(in hexadecimals): " << decrypted_text << endl << endl;
    cout << "Decrypted ciphertext(in characters) with key(in hexadecimals) \"" 
         << strKey << "\" in " << numOfRounds << " rounds: " 
         << generate_originaltext(decrypted_text) << endl;

    return 0;
}
