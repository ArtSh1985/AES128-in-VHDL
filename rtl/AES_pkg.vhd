----------------------------------------------------------------------------------
-- Artem Shlepchenko, as14836
-- Michael Mattioli, omm226
--
-- Company: 
-- Engineer: 
-- 
-- Create Date: 02/21/2022 04:06:45 PM
-- Design Name: 
-- Module Name: AES_pkg - Behavioral
-- Project Name: 
-- Target Devices: 
-- Tool Versions: 
-- Description: 
-- 
-- Dependencies: 
-- 
-- Revision:
-- Revision 0.01 - File Created
-- Additional Comments:
-- 
----------------------------------------------------------------------------------


library IEEE;
use IEEE.STD_LOGIC_1164.ALL;

-- Uncomment the following library declaration if using
-- arithmetic functions with Signed or Unsigned values
use IEEE.NUMERIC_STD.ALL;

-- Uncomment the following library declaration if instantiating
-- any Xilinx leaf cells in this code.
--library UNISIM;
--use UNISIM.VComponents.all;

package AES_pkg is

constant BYTE: integer := 8;

constant LENGTH_32_BIT: integer := 32;
constant LENGTH_64_BIT: integer := 64;
constant LENGTH_128_BIT: integer := 128;
constant LENGTH_256_BIT: integer := 256;

------------------------------------------------------------------------------------------------------
-- Array for storing keys during the decryption process
type INV_NEXT_KEY is array (0 to 10) of std_logic_vector(LENGTH_128_BIT-1 downto 0);
------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------
-- Round constants for key_generator function
type KEY_BOX_ARRAY is array (0 to 9) of std_logic_vector(BYTE-1 downto 0);
constant KEYBOX: KEY_BOX_ARRAY := (
    x"01", x"02", x"04", x"08", x"10", x"20", x"40", x"80", x"1b", x"36"
);
------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------
-- Constants for encryption, decryption and function mulby2()
type S_BOX_ARRAY is array (0 to 255) of std_logic_vector(BYTE-1 downto 0);

constant SBOX: S_BOX_ARRAY := (
    x"63", x"7c", x"77", x"7b", x"f2", x"6b", x"6f", x"c5", x"30", x"01", x"67", x"2b", x"fe", x"d7", x"ab", x"76",
    x"ca", x"82", x"c9", x"7d", x"fa", x"59", x"47", x"f0", x"ad", x"d4", x"a2", x"af", x"9c", x"a4", x"72", x"c0",
    x"b7", x"fd", x"93", x"26", x"36", x"3f", x"f7", x"cc", x"34", x"a5", x"e5", x"f1", x"71", x"d8", x"31", x"15",
    x"04", x"c7", x"23", x"c3", x"18", x"96", x"05", x"9a", x"07", x"12", x"80", x"e2", x"eb", x"27", x"b2", x"75",
    x"09", x"83", x"2c", x"1a", x"1b", x"6e", x"5a", x"a0", x"52", x"3b", x"d6", x"b3", x"29", x"e3", x"2f", x"84",
    x"53", x"d1", x"00", x"ed", x"20", x"fc", x"b1", x"5b", x"6a", x"cb", x"be", x"39", x"4a", x"4c", x"58", x"cf",
    x"d0", x"ef", x"aa", x"fb", x"43", x"4d", x"33", x"85", x"45", x"f9", x"02", x"7f", x"50", x"3c", x"9f", x"a8",
    x"51", x"a3", x"40", x"8f", x"92", x"9d", x"38", x"f5", x"bc", x"b6", x"da", x"21", x"10", x"ff", x"f3", x"d2",
    x"cd", x"0c", x"13", x"ec", x"5f", x"97", x"44", x"17", x"c4", x"a7", x"7e", x"3d", x"64", x"5d", x"19", x"73",
    x"60", x"81", x"4f", x"dc", x"22", x"2a", x"90", x"88", x"46", x"ee", x"b8", x"14", x"de", x"5e", x"0b", x"db",
    x"e0", x"32", x"3a", x"0a", x"49", x"06", x"24", x"5c", x"c2", x"d3", x"ac", x"62", x"91", x"95", x"e4", x"79",
    x"e7", x"c8", x"37", x"6d", x"8d", x"d5", x"4e", x"a9", x"6c", x"56", x"f4", x"ea", x"65", x"7a", x"ae", x"08",
    x"ba", x"78", x"25", x"2e", x"1c", x"a6", x"b4", x"c6", x"e8", x"dd", x"74", x"1f", x"4b", x"bd", x"8b", x"8a",
    x"70", x"3e", x"b5", x"66", x"48", x"03", x"f6", x"0e", x"61", x"35", x"57", x"b9", x"86", x"c1", x"1d", x"9e",
    x"e1", x"f8", x"98", x"11", x"69", x"d9", x"8e", x"94", x"9b", x"1e", x"87", x"e9", x"ce", x"55", x"28", x"df",
    x"8c", x"a1", x"89", x"0d", x"bf", x"e6", x"42", x"68", x"41", x"99", x"2d", x"0f", x"b0", x"54", x"bb", x"16"
);

constant INV_SBOX: S_BOX_ARRAY := (
    x"52", x"09", x"6a", x"d5", x"30", x"36", x"a5", x"38", x"bf", x"40", x"a3", x"9e", x"81", x"f3", x"d7", x"fb",
    x"7c", x"e3", x"39", x"82", x"9b", x"2f", x"ff", x"87", x"34", x"8e", x"43", x"44", x"c4", x"de", x"e9", x"cb",
    x"54", x"7b", x"94", x"32", x"a6", x"c2", x"23", x"3d", x"ee", x"4c", x"95", x"0b", x"42", x"fa", x"c3", x"4e",
    x"08", x"2e", x"a1", x"66", x"28", x"d9", x"24", x"b2", x"76", x"5b", x"a2", x"49", x"6d", x"8b", x"d1", x"25",
    x"72", x"f8", x"f6", x"64", x"86", x"68", x"98", x"16", x"d4", x"a4", x"5c", x"cc", x"5d", x"65", x"b6", x"92",
    x"6c", x"70", x"48", x"50", x"fd", x"ed", x"b9", x"da", x"5e", x"15", x"46", x"57", x"a7", x"8d", x"9d", x"84",
    x"90", x"d8", x"ab", x"00", x"8c", x"bc", x"d3", x"0a", x"f7", x"e4", x"58", x"05", x"b8", x"b3", x"45", x"06",
    x"d0", x"2c", x"1e", x"8f", x"ca", x"3f", x"0f", x"02", x"c1", x"af", x"bd", x"03", x"01", x"13", x"8a", x"6b",
    x"3a", x"91", x"11", x"41", x"4f", x"67", x"dc", x"ea", x"97", x"f2", x"cf", x"ce", x"f0", x"b4", x"e6", x"73",
    x"96", x"ac", x"74", x"22", x"e7", x"ad", x"35", x"85", x"e2", x"f9", x"37", x"e8", x"1c", x"75", x"df", x"6e",
    x"47", x"f1", x"1a", x"71", x"1d", x"29", x"c5", x"89", x"6f", x"b7", x"62", x"0e", x"aa", x"18", x"be", x"1b",
    x"fc", x"56", x"3e", x"4b", x"c6", x"d2", x"79", x"20", x"9a", x"db", x"c0", x"fe", x"78", x"cd", x"5a", x"f4",
    x"1f", x"dd", x"a8", x"33", x"88", x"07", x"c7", x"31", x"b1", x"12", x"10", x"59", x"27", x"80", x"ec", x"5f",
    x"60", x"51", x"7f", x"a9", x"19", x"b5", x"4a", x"0d", x"2d", x"e5", x"7a", x"9f", x"93", x"c9", x"9c", x"ef",
    x"a0", x"e0", x"3b", x"4d", x"ae", x"2a", x"f5", x"b0", x"c8", x"eb", x"bb", x"3c", x"83", x"53", x"99", x"61",
    x"17", x"2b", x"04", x"7e", x"ba", x"77", x"d6", x"26", x"e1", x"69", x"14", x"63", x"55", x"21", x"0c", x"7d"
);

constant MUL_BY_2_TABLE : S_BOX_ARRAY := (
    x"00",  x"02",  x"04",  x"06",  x"08",  x"0a",  x"0c",  x"0e",  x"10",  x"12",  x"14",  x"16",  x"18",  x"1a",  x"1c",  x"1e",  
    x"20",  x"22",  x"24",  x"26",  x"28",  x"2a",  x"2c",  x"2e",  x"30",  x"32",  x"34",  x"36",  x"38",  x"3a",  x"3c",  x"3e",  
    x"40",  x"42",  x"44",  x"46",  x"48",  x"4a",  x"4c",  x"4e",  x"50",  x"52",  x"54",  x"56",  x"58",  x"5a",  x"5c",  x"5e",  
    x"60",  x"62",  x"64",  x"66",  x"68",  x"6a",  x"6c",  x"6e",  x"70",  x"72",  x"74",  x"76",  x"78",  x"7a",  x"7c",  x"7e",  
    x"80",  x"82",  x"84",  x"86",  x"88",  x"8a",  x"8c",  x"8e",  x"90",  x"92",  x"94",  x"96",  x"98",  x"9a",  x"9c",  x"9e",  
    x"a0",  x"a2",  x"a4",  x"a6",  x"a8",  x"aa",  x"ac",  x"ae",  x"b0",  x"b2",  x"b4",  x"b6",  x"b8",  x"ba",  x"bc",  x"be",  
    x"c0",  x"c2",  x"c4",  x"c6",  x"c8",  x"ca",  x"cc",  x"ce",  x"d0",  x"d2",  x"d4",  x"d6",  x"d8",  x"da",  x"dc",  x"de",  
    x"e0",  x"e2",  x"e4",  x"e6",  x"e8",  x"ea",  x"ec",  x"ee",  x"f0",  x"f2",  x"f4",  x"f6",  x"f8",  x"fa",  x"fc",  x"fe",  
    x"1b",  x"19",  x"1f",  x"1d",  x"13",  x"11",  x"17",  x"15",  x"0b",  x"09",  x"0f",  x"0d",  x"03",  x"01",  x"07",  x"05",  
    x"3b",  x"39",  x"3f",  x"3d",  x"33",  x"31",  x"37",  x"35",  x"2b",  x"29",  x"2f",  x"2d",  x"23",  x"21",  x"27",  x"25",  
    x"5b",  x"59",  x"5f",  x"5d",  x"53",  x"51",  x"57",  x"55",  x"4b",  x"49",  x"4f",  x"4d",  x"43",  x"41",  x"47",  x"45",  
    x"7b",  x"79",  x"7f",  x"7d",  x"73",  x"71",  x"77",  x"75",  x"6b",  x"69",  x"6f",  x"6d",  x"63",  x"61",  x"67",  x"65",  
    x"9b",  x"99",  x"9f",  x"9d",  x"93",  x"91",  x"97",  x"95",  x"8b",  x"89",  x"8f",  x"8d",  x"83",  x"81",  x"87",  x"85",  
    x"bb",  x"b9",  x"bf",  x"bd",  x"b3",  x"b1",  x"b7",  x"b5",  x"ab",  x"a9",  x"af",  x"ad",  x"a3",  x"a1",  x"a7",  x"a5",  
    x"db",  x"d9",  x"df",  x"dd",  x"d3",  x"d1",  x"d7",  x"d5",  x"cb",  x"c9",  x"cf",  x"cd",  x"c3",  x"c1",  x"c7",  x"c5",  
    x"fb",  x"f9",  x"ff",  x"fd",  x"f3",  x"f1",  x"f7",  x"f5",  x"eb",  x"e9",  x"ef",  x"ed",  x"e3",  x"e1",  x"e7",  x"e5"
);
------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------
-- General function
function mulby2(input: std_logic_vector(7 downto 0)) return std_logic_vector;

function key_expansion(input: std_logic_vector(LENGTH_128_BIT-1 downto 0);
                       rcon: std_logic_vector(BYTE-1 downto 0)) return std_logic_vector;

------------------------------------------------------------------------------------------------------
-- Encryption process functions
function sub_bytes(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector;

function s_box_init(input: std_logic_vector(BYTE-1 downto 0)) return std_logic_vector;

function shift_row(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector;

function mix_columns(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector;

function mix_column_calc(input: std_logic_vector(LENGTH_32_BIT-1 downto 0)) return std_logic_vector;
------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------
-- Encryption process functions
function inv_sub_bytes(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector;

function inv_s_box_init(input: std_logic_vector(BYTE-1 downto 0)) return std_logic_vector;

function inv_shift_row(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector;

function inv_mix_columns(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector;

function inv_mix_column_calc(input: std_logic_vector(LENGTH_32_BIT-1 downto 0)) return std_logic_vector;
------------------------------------------------------------------------------------------------------

end AES_pkg;

package body AES_pkg is
------------------------------------------------------------------------------------------------------
-- General function
function key_expansion(input: std_logic_vector(LENGTH_128_BIT-1 downto 0);
                       rcon: std_logic_vector(BYTE-1 downto 0)) return std_logic_vector is

    variable output: std_logic_vector(LENGTH_128_BIT-1 downto 0);
    variable w0, w1, w2, w3, w4, w5, w6, w7: STD_LOGIC_VECTOR (31 downto 0);
    variable w3_rot, w3_sbox, w3_con, temp, w3_init: STD_LOGIC_VECTOR (31 downto 0);
    
    begin
        w0 := input(BYTE*16-1 downto BYTE*12);
        w1 := input(BYTE*12-1 downto BYTE*8);
        w2 := input(BYTE*8-1 downto BYTE*4);
        w3 := input(BYTE*4-1 downto BYTE*0);
        w3_rot := input(BYTE*3-1 downto BYTE*0) & input(BYTE*4-1 downto BYTE*3);
        w3_sbox(BYTE*4-1 downto BYTE*3) := s_box_init(w3_rot(BYTE*4-1 downto BYTE*3));
        w3_sbox(BYTE*3-1 downto BYTE*2) := s_box_init(w3_rot(BYTE*3-1 downto BYTE*2));
        w3_sbox(BYTE*2-1 downto BYTE*1) := s_box_init(w3_rot(BYTE*2-1 downto BYTE*1));
        w3_sbox(BYTE*1-1 downto BYTE*0) := s_box_init(w3_rot(BYTE*1-1 downto BYTE*0));
        w3_con := (w3_sbox(BYTE*4-1 downto BYTE*3) XOR rcon) & w3_sbox(BYTE*3-1 downto BYTE*0);
        w4 := w0 XOR w3_con;
        w5 := w4 XOR w1;
        w6 := w5 XOR w2;
        w7 := w6 XOR w3;
        
        output := w4 & w5 & w6 & w7;
        
        return output;
end key_expansion;

function mulby2(input: std_logic_vector(7 downto 0)) return std_logic_vector is
    variable output: std_logic_vector(7 downto 0);
    begin
        output := std_logic_vector(MUL_BY_2_TABLE(to_integer(unsigned(input))));
  
        return output;
end mulby2;
------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------
-- Encryption process functions
function sub_bytes(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector is

    variable output: std_logic_vector(LENGTH_128_BIT-1 downto 0);

    begin
        for i in 0 to 15 loop
            output((i+1)*BYTE-1 downto i*BYTE) := s_box_init(input((i+1)*BYTE-1 downto i*BYTE));
        end loop;
            
        return output;
end sub_bytes;

function s_box_init(input: std_logic_vector(BYTE-1 downto 0)) return std_logic_vector is
    
    variable output: std_logic_vector(BYTE-1 downto 0);
    
    begin
    
        output := std_logic_vector(SBOX(to_integer(unsigned(input))));
        
        return output;
end s_box_init;

------------------------------------------------------------------------------------------------------
-- shift_row() function
--  ---------------------------      ---------------------------
-- | a0,0 | a0,1 | a0,2 | a0,3 |    | a0,0 | a0,1 | a0,2 | a0,3 |
-- |---------------------------|    |---------------------------|
-- | a1,0 | a1,1 | a1,2 | a1,3 |    | a1,1 | a1,2 | a1,3 | a1,0 |
-- |---------------------------| => |---------------------------|
-- | a2,0 | a2,1 | a2,2 | a2,3 |    | a2,2 | a2,3 | a2,0 | a2,1 |
-- |---------------------------|    |---------------------------|
-- | a3,0 | a3,1 | a3,2 | a3,3 |    | a3,3 | a3,0 | a3,1 | a3,2 |
--  ---------------------------      ---------------------------
------------------------------------------------------------------------------------------------------
function shift_row(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector is
    
    variable output: std_logic_vector(LENGTH_128_BIT-1 downto 0);

    begin
        output(BYTE*16-1 downto BYTE*15) := input(BYTE*16-1 downto BYTE*15);
        output(BYTE*15-1 downto BYTE*14) := input(BYTE*11-1 downto BYTE*10);
        output(BYTE*14-1 downto BYTE*13) := input(BYTE*6-1  downto BYTE*5);
        output(BYTE*13-1 downto BYTE*12) := input(BYTE*1-1  downto BYTE*0);
        output(BYTE*12-1 downto BYTE*11) := input(BYTE*12-1 downto BYTE*11);
        output(BYTE*11-1 downto BYTE*10) := input(BYTE*7-1  downto BYTE*6);
        output(BYTE*10-1 downto BYTE*9) := input(BYTE*2-1  downto BYTE*1);
        output(BYTE*9-1  downto BYTE*8) := input(BYTE*13-1 downto BYTE*12);
        output(BYTE*8-1  downto BYTE*7) := input(BYTE*8-1  downto BYTE*7);
        output(BYTE*7-1  downto BYTE*6) := input(BYTE*3-1  downto BYTE*2);
        output(BYTE*6-1  downto BYTE*5) := input(BYTE*14-1 downto BYTE*13);
        output(BYTE*5-1  downto BYTE*4) := input(BYTE*9-1  downto BYTE*8);
        output(BYTE*4-1  downto BYTE*3) := input(BYTE*4-1  downto BYTE*3);
        output(BYTE*3-1  downto BYTE*2) := input(BYTE*15-1 downto BYTE*14);
        output(BYTE*2-1  downto BYTE*1) := input(BYTE*10-1 downto BYTE*9);
        output(BYTE*1-1  downto BYTE*0) := input(BYTE*5-1  downto BYTE*4);
    
        return output;
end shift_row;

------------------------------------------------------------------------------------------------------
-- mix_columns() function
--  ---------------------------     ---------------     ---------------------------
-- | a0,0 | a0,1 | a0,2 | a0,3 |   | 2 | 3 | 1 | 1 |   | b0,0 | b0,1 | b0,2 | b0,3 |
-- |---------------------------|   |---------------|   |---------------------------|
-- | a1,0 | a1,1 | a1,2 | a1,3 |   | 1 | 2 | 3 | 1 |   | b1,0 | b1,1 | b1,2 | b1,3 |
-- |---------------------------| × |---------------| = |---------------------------|
-- | a2,0 | a2,1 | a2,2 | a2,3 |   | 1 | 1 | 2 | 3 |   | b2,0 | b2,1 | b2,2 | b2,3 |
-- |---------------------------|   |---------------|   |---------------------------|
-- | a3,0 | a3,1 | a3,2 | a3,3 |   | 3 | 1 | 1 | 2 |   | b3,0 | b3,1 | b3,2 | b3,3 |
--  ---------------------------     ---------------     ---------------------------
-- Multiplication by 3 is implemented with using (x*2) with "exclusive-or"
-- x×3 = (x×2)+x 
------------------------------------------------------------------------------------------------------
function mix_columns(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector is
    variable output: std_logic_vector(LENGTH_128_BIT-1 downto 0);
    variable column_1, column_2, column_3, column_4: std_logic_vector(LENGTH_32_BIT-1 downto 0);
    variable new_column_1, new_column_2, new_column_3, new_column_4: std_logic_vector(LENGTH_32_BIT-1 downto 0);

    begin
        column_1 := input(BYTE*16-1 downto BYTE*12);
        column_2 := input(BYTE*12-1 downto BYTE*8);
        column_3 := input(BYTE*8-1 downto BYTE*4);
        column_4 := input(BYTE*4-1 downto BYTE*0);
        
        new_column_1 := mix_column_calc(column_1);
        new_column_2 := mix_column_calc(column_2);
        new_column_3 := mix_column_calc(column_3);
        new_column_4 := mix_column_calc(column_4);   
                        
        output := new_column_1 & new_column_2 & new_column_3 & new_column_4;
        return output;
end mix_columns;

function mix_column_calc(input: std_logic_vector(LENGTH_32_BIT-1 downto 0)) return std_logic_vector is
    
    variable output: std_logic_vector(LENGTH_32_BIT-1 downto 0);
    variable temp: std_logic_vector(LENGTH_32_BIT-1 downto 0);
    begin
        temp(BYTE*4-1 downto BYTE*3) := 
            mulby2(input(BYTE*4-1 downto BYTE*3)) XOR
            (mulby2(input(BYTE*3-1 downto BYTE*2)) XOR input(BYTE*3-1 downto BYTE*2)) XOR
            input(BYTE*2-1 downto BYTE*1) XOR
            input(BYTE*1-1 downto 0);
        temp(BYTE*3-1 downto BYTE*2) := 
            input(BYTE*4-1 downto BYTE*3) XOR
            mulby2(input(BYTE*3-1 downto BYTE*2)) XOR
            (mulby2(input(BYTE*2-1 downto BYTE*1)) XOR input(BYTE*2-1 downto BYTE*1)) XOR
            input(BYTE*1-1 downto 0);
        temp(BYTE*2-1 downto BYTE*1) := 
            input(BYTE*4-1 downto BYTE*3) XOR
            input(BYTE*3-1 downto BYTE*2) XOR
            mulby2(input(BYTE*2-1 downto BYTE*1)) XOR
            (mulby2(input(BYTE*1-1 downto 0)) XOR input(BYTE*1-1 downto 0));
        temp(BYTE*1-1 downto BYTE*0) := 
            (mulby2(input(BYTE*4-1 downto BYTE*3)) XOR input(BYTE*4-1 downto BYTE*3)) XOR
            input(BYTE*3-1 downto BYTE*2) XOR
            input(BYTE*2-1 downto BYTE*1) XOR
            mulby2(input(BYTE*1-1 downto 0));
    
        output := temp;
    
        return output;
end mix_column_calc;
------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------------
-- Decryption process functions
function inv_sub_bytes(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector is

    variable output: std_logic_vector(LENGTH_128_BIT-1 downto 0);

    begin
        for i in 0 to 15 loop
            output((i+1)*BYTE-1 downto i*BYTE) := inv_s_box_init(input((i+1)*BYTE-1 downto i*BYTE));
        end loop;
            
        return output;
end inv_sub_bytes;

function inv_s_box_init(input: std_logic_vector(BYTE-1 downto 0)) return std_logic_vector is
    
    variable output: std_logic_vector(BYTE-1 downto 0);
    
    begin
    
        output := std_logic_vector(INV_SBOX(to_integer(unsigned(input))));
        
        return output;
end inv_s_box_init;

function inv_shift_row(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector is
    
    variable output: std_logic_vector(LENGTH_128_BIT-1 downto 0);

    begin
        output(BYTE*16-1 downto BYTE*15) := input(BYTE*16-1 downto BYTE*15);
        output(BYTE*15-1 downto BYTE*14) := input(BYTE*3-1 downto BYTE*2);
        output(BYTE*14-1 downto BYTE*13) := input(BYTE*6-1  downto BYTE*5);
        output(BYTE*13-1 downto BYTE*12) := input(BYTE*9-1  downto BYTE*8);
        output(BYTE*12-1 downto BYTE*11) := input(BYTE*12-1 downto BYTE*11);
        output(BYTE*11-1 downto BYTE*10) := input(BYTE*15-1  downto BYTE*14);
        output(BYTE*10-1 downto BYTE*9) := input(BYTE*2-1  downto BYTE*1);
        output(BYTE*9-1  downto BYTE*8) := input(BYTE*5-1 downto BYTE*4);
        output(BYTE*8-1  downto BYTE*7) := input(BYTE*8-1  downto BYTE*7);
        output(BYTE*7-1  downto BYTE*6) := input(BYTE*11-1  downto BYTE*10);
        output(BYTE*6-1  downto BYTE*5) := input(BYTE*14-1 downto BYTE*13);
        output(BYTE*5-1  downto BYTE*4) := input(BYTE*1-1  downto BYTE*0);
        output(BYTE*4-1  downto BYTE*3) := input(BYTE*4-1  downto BYTE*3);
        output(BYTE*3-1  downto BYTE*2) := input(BYTE*7-1 downto BYTE*6);
        output(BYTE*2-1  downto BYTE*1) := input(BYTE*10-1 downto BYTE*9);
        output(BYTE*1-1  downto BYTE*0) := input(BYTE*13-1  downto BYTE*12);
    
        return output;
end inv_shift_row;

------------------------------------------------------------------------------------------------------
-- inv_mix_columns() function
--  ---------------------------     -------------------     ---------------------------
-- | a0,0 | a0,1 | a0,2 | a0,3 |   | 14 | 11 | 13 | 9  |   | b0,0 | b0,1 | b0,2 | b0,3 |
-- |---------------------------|   |-------------------|   |---------------------------|
-- | a1,0 | a1,1 | a1,2 | a1,3 |   | 9  | 14 | 11 | 13 |   | b1,0 | b1,1 | b1,2 | b1,3 |
-- |---------------------------| × |-------------------| = |---------------------------|
-- | a2,0 | a2,1 | a2,2 | a2,3 |   | 13 | 9  | 14 | 11 |   | b2,0 | b2,1 | b2,2 | b2,3 |
-- |---------------------------|   |-------------------|   |---------------------------|
-- | a3,0 | a3,1 | a3,2 | a3,3 |   | 11 | 13 | 9  | 14 |   | b3,0 | b3,1 | b3,2 | b3,3 |
--  ---------------------------     -------------------     ---------------------------
-- Multiplication by 9, 11, 13, 14 is implemented with using (x*2) several times with "exclusive-or"
-- x×9  = (((x×2)×2)×2)+x 
-- x×11 = ((((x×2)×2)+x)×2)+x
-- x×13 = ((((x×2)+x)×2)×2)+x
-- x×14 = ((((x×2)+x)×2)+x)×2
------------------------------------------------------------------------------------------------------
function inv_mix_columns(input: std_logic_vector(LENGTH_128_BIT-1 downto 0)) return std_logic_vector is
    variable output: std_logic_vector(LENGTH_128_BIT-1 downto 0);
    variable column_1, column_2, column_3, column_4: std_logic_vector(LENGTH_32_BIT-1 downto 0);
    variable new_column_1, new_column_2, new_column_3, new_column_4: std_logic_vector(LENGTH_32_BIT-1 downto 0);

    begin
        column_1 := input(BYTE*16-1 downto BYTE*12);
        column_2 := input(BYTE*12-1 downto BYTE*8);
        column_3 := input(BYTE*8-1 downto BYTE*4);
        column_4 := input(BYTE*4-1 downto BYTE*0);
        
        new_column_1 := inv_mix_column_calc(column_1);
        new_column_2 := inv_mix_column_calc(column_2);
        new_column_3 := inv_mix_column_calc(column_3);
        new_column_4 := inv_mix_column_calc(column_4);   
                        
        output := new_column_1 & new_column_2 & new_column_3 & new_column_4;
        return output;
end inv_mix_columns;

function inv_mix_column_calc(input: std_logic_vector(LENGTH_32_BIT-1 downto 0)) return std_logic_vector is
    
    variable output: std_logic_vector(LENGTH_32_BIT-1 downto 0);
    variable temp: std_logic_vector(LENGTH_32_BIT-1 downto 0);
    begin
        temp(BYTE*4-1 downto BYTE*3) := 
            (mulby2(mulby2(mulby2(input(BYTE*4-1 downto BYTE*3)) XOR input(BYTE*4-1 downto BYTE*3)) XOR input(BYTE*4-1 downto BYTE*3))) XOR
            (mulby2(mulby2(mulby2(input(BYTE*3-1 downto BYTE*2))) XOR input(BYTE*3-1 downto BYTE*2)) XOR input(BYTE*3-1 downto BYTE*2)) XOR
            (mulby2(mulby2((mulby2(input(BYTE*2-1 downto BYTE*1)) XOR input(BYTE*2-1 downto BYTE*1)))) XOR input(BYTE*2-1 downto BYTE*1)) XOR
            (mulby2(mulby2(mulby2(input(BYTE*1-1 downto 0)))) XOR input(BYTE*1-1 downto 0));
        temp(BYTE*3-1 downto BYTE*2) := 
            (mulby2(mulby2(mulby2(input(BYTE*4-1 downto BYTE*3)))) XOR input(BYTE*4-1 downto BYTE*3)) XOR
            (mulby2(mulby2(mulby2(input(BYTE*3-1 downto BYTE*2)) XOR input(BYTE*3-1 downto BYTE*2)) XOR input(BYTE*3-1 downto BYTE*2))) XOR
            (mulby2(mulby2(mulby2(input(BYTE*2-1 downto BYTE*1))) XOR input(BYTE*2-1 downto BYTE*1)) XOR input(BYTE*2-1 downto BYTE*1)) XOR
            (mulby2(mulby2((mulby2(input(BYTE*1-1 downto 0)) XOR input(BYTE*1-1 downto 0)))) XOR input(BYTE*1-1 downto 0));
        temp(BYTE*2-1 downto BYTE*1) := 
            (mulby2(mulby2((mulby2(input(BYTE*4-1 downto BYTE*3)) XOR input(BYTE*4-1 downto BYTE*3)))) XOR input(BYTE*4-1 downto BYTE*3)) XOR
            (mulby2(mulby2(mulby2(input(BYTE*3-1 downto BYTE*2)))) XOR input(BYTE*3-1 downto BYTE*2)) XOR
            (mulby2(mulby2(mulby2(input(BYTE*2-1 downto BYTE*1)) XOR input(BYTE*2-1 downto BYTE*1)) XOR input(BYTE*2-1 downto BYTE*1))) XOR
            (mulby2(mulby2(mulby2(input(BYTE*1-1 downto 0))) XOR input(BYTE*1-1 downto 0)) XOR input(BYTE*1-1 downto 0));
        temp(BYTE*1-1 downto BYTE*0) := 
            (mulby2(mulby2(mulby2(input(BYTE*4-1 downto BYTE*3))) XOR input(BYTE*4-1 downto BYTE*3)) XOR input(BYTE*4-1 downto BYTE*3)) XOR
            (mulby2(mulby2((mulby2(input(BYTE*3-1 downto BYTE*2)) XOR input(BYTE*3-1 downto BYTE*2)))) XOR input(BYTE*3-1 downto BYTE*2)) XOR
            (mulby2(mulby2(mulby2(input(BYTE*2-1 downto BYTE*1)))) XOR input(BYTE*2-1 downto BYTE*1)) XOR
            (mulby2(mulby2(mulby2(input(BYTE*1-1 downto BYTE*0)) XOR input(BYTE*1-1 downto BYTE*0)) XOR input(BYTE*1-1 downto BYTE*0)));
    
        output := temp;
    
        return output;
end inv_mix_column_calc;
------------------------------------------------------------------------------------------------------

end AES_pkg;
