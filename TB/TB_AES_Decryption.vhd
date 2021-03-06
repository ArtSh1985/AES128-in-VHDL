----------------------------------------------------------------------------------
-- Artem Shlepchenko, as14836
-- Michael Mattioli, omm226
--
-- Company: 
-- Engineer: 
-- 
-- Create Date: 02/21/2022 04:10:24 PM
-- Design Name: 
-- Module Name: TB_AES_Decryption - Behavioral
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

entity TB_AES_Decryption is
--  Port ( );
end TB_AES_Decryption;

architecture Behavioral of TB_AES_Decryption is
    
    component AES port (
        clk_AES: in std_logic;
        rstn_AES: in std_logic;
        enable_AES: in std_logic;
        AES_dir: in std_logic;
        AES_ready: in std_logic
        );
    end component;
    
    component Decryption port (
        clk: in std_logic;
        rstn: in std_logic;
        dec_vld: in std_logic;
        ciphertext : in  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0); --x"69c4e0d86a7b0430d8cdb78070b4c55a";
        plaintext : out  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0); --x"00112233445566778899aabbccddeeff"
        key_in : in  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0) --x"000102030405060708090a0b0c0d0e0f"
        );
    end component;
    
    file file_pointer: text;
    
    signal tb_clk_AES: std_logic;
    signal tb_rstn_AES: std_logic := '0';
    signal tb_input_AES: std_logic_vector(LENGTH_128_BIT-1 downto 0); --:= x"69c4e0d86a7b0430d8cdb78070b4c55a";--x"00112233445566778899aabbccddeeff";
    signal tb_output_AES: std_logic_vector(LENGTH_128_BIT-1 downto 0);
    signal tb_user_key: std_logic_vector(LENGTH_128_BIT-1 downto 0); --:= x"000102030405060708090a0b0c0d0e0f";
    
    signal tb_AES_enable: std_logic := '1';
    signal tb_AES_dir: std_logic := '1';
    signal counter: integer;
    
begin
    
    dut: entity work.AES port map(
        clk_AES => tb_clk_AES,
        rstn_AES => tb_rstn_AES,
        enable_AES => tb_AES_enable,
        AES_dir => tb_AES_dir,
        AES_ready => tb_AES_dir
    );
    
    uut: entity work.Decryption port map (
        clk => tb_clk_AES,
        rstn => tb_rstn_AES,
        dec_vld => tb_AES_enable,
        ciphertext => tb_input_AES,
        plaintext => tb_output_AES,
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
        variable ciphertext: std_logic_vector(LENGTH_128_BIT-1 downto 0);
        variable key: std_logic_vector(LENGTH_128_BIT-1 downto 0);
        variable plaintext: std_logic_vector(LENGTH_128_BIT-1 downto 0);
        variable file_space: character;
        
    begin
        
        wait for 0.1ns;
        file_open(file_pointer, "ECBVarTxt128d.txt", read_mode);
        counter <= 1;
        while not endfile(file_pointer) loop
            readline(file_pointer, file_line);
            hread(file_line, ciphertext);
            read(file_line, file_space);
            hread(file_line, key);
            read(file_line, file_space);
            hread(file_line, plaintext);
            
            wait for 0.3ns;
            
            tb_input_AES <= ciphertext;
            tb_user_key <= key;
             
            wait for 9ns;
            assert(tb_output_AES = plaintext) report"The test case didn't match what was expected. Test case (line #): " &integer'image(counter) severity FAILURE;
            counter <= counter + 1;
        end loop;
        file_close(file_pointer);
        report"All tests passed successfully!";
        std.env.stop;
    
    end process;

end Behavioral;
