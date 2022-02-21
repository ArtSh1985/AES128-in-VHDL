----------------------------------------------------------------------------------
-- Company: 
-- Engineer: 
-- 
-- Create Date: 02/14/2022 07:27:26 PM
-- Design Name: 
-- Module Name: TB_AES_Encryption - Behavioral
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
use STD.TEXTIO.ALL;
use IEEE.STD_LOGIC_TEXTIO.ALL;
use work.AES_pkg.ALL;

-- Uncomment the following library declaration if using
-- arithmetic functions with Signed or Unsigned values
use IEEE.NUMERIC_STD.ALL;

-- Uncomment the following library declaration if instantiating
-- any Xilinx leaf cells in this code.
--library UNISIM;
--use UNISIM.VComponents.all;

entity TB_AES_Encryption is
--  Port ( );
end TB_AES_Encryption;

architecture Behavioral of TB_AES_Encryption is

    component AES port (
        clk_AES: in std_logic;
        
        AES_start_enc: in std_logic;
        AES_start_dec: in std_logic;
        AES_dir: in std_logic
        );
    end component;
    
    component Encryption port (
        clk: in std_logic;
        enc_vld: in std_logic;
    
        plaintext : in  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0); --x"00112233445566778899aabbccddeeff"
        ciphertext : out  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0); --x"69c4e0d86a7b0430d8cdb78070b4c55a";
    
        key_in : in  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0) --x"000102030405060708090a0b0c0d0e0f"
        );
    end component;
    
    file file_pointer: text;
    
    signal tb_clk_AES: std_logic;
    
    signal tb_input_AES: std_logic_vector(LENGTH_128_BIT-1 downto 0); --:= x"69c4e0d86a7b0430d8cdb78070b4c55a";--x"00112233445566778899aabbccddeeff";
    signal tb_output_AES: std_logic_vector(LENGTH_128_BIT-1 downto 0);
    signal tb_user_key: std_logic_vector(LENGTH_128_BIT-1 downto 0); --:= x"000102030405060708090a0b0c0d0e0f";
    
    signal tb_AES_start_enc: std_logic := '1';
    signal tb_AES_start_dec: std_logic := '0';
    signal tb_AES_dir: std_logic := '0';
    signal counter: integer;
    
begin
    
    dut: entity work.AES port map(
        clk_AES => tb_clk_AES,
        AES_start_enc => tb_AES_start_enc,
        AES_start_dec => tb_AES_start_dec,
        AES_dir => tb_AES_dir
    );
    
    uut: entity work.Encryption port map (
        clk => tb_clk_AES,
        enc_vld => tb_AES_start_enc,
        plaintext => tb_input_AES,
        ciphertext => tb_output_AES,
        key_in => tb_user_key
    );
    CLK_GEN: process begin
        tb_clk_AES <= '0';
        wait for 0.2ns;
        tb_clk_AES <= '1';
        wait for 0.2ns;
    end process;
    
    
    TEST: process
                
        variable file_line: line;
        variable plaintext: std_logic_vector(LENGTH_128_BIT-1 downto 0);
        variable key: std_logic_vector(LENGTH_128_BIT-1 downto 0);
        variable ciphertext: std_logic_vector(LENGTH_128_BIT-1 downto 0);
        variable file_space: character;
        
    begin
        
        wait for 0.1ns;
        file_open(file_pointer, "ECBvarTxt128e.txt", read_mode);
        counter <= 1;
        while not endfile(file_pointer) loop
            readline(file_pointer, file_line);
            hread(file_line, plaintext);
            read(file_line, file_space);
            hread(file_line, key);
            read(file_line, file_space);
            hread(file_line, ciphertext);
            
            wait for 0.3ns;

            tb_input_AES <= plaintext;
            tb_user_key <= key;
             
            wait for 9ns;
            assert(tb_output_AES = ciphertext) report"The test case didn't match what was expected. Test case (line #): " &integer'image(counter) severity FAILURE;
            counter <= counter + 1;
        end loop;
        file_close(file_pointer);
        report"All tests passed successfully!";
        std.env.stop;
    
    end process;
    
end Behavioral;
