----------------------------------------------------------------------------------
-- Company: 
-- Engineer: 
-- 
-- Create Date: 02/13/2022 07:29:15 PM
-- Design Name: 
-- Module Name: AES - Behavioral
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
use work.AES_pkg.ALL;

-- Uncomment the following library declaration if using
-- arithmetic functions with Signed or Unsigned values
--use IEEE.NUMERIC_STD.ALL;

-- Uncomment the following library declaration if instantiating
-- any Xilinx leaf cells in this code.
--library UNISIM;
--use UNISIM.VComponents.all;

------------------------Encryption--------------------------
--          plaintext:  x"00112233445566778899aabbccddeeff"
--          key:        x"000102030405060708090a0b0c0d0e0f"
--          ciphertext: x"69c4e0d86a7b0430d8cdb78070b4c55a"
------------------------------------------------------------

------------------------Decryption--------------------------
--          plaintext:  x"69c4e0d86a7b0430d8cdb78070b4c55a"
--          key:        x"000102030405060708090a0b0c0d0e0f"
--          ciphertext: x"00112233445566778899aabbccddeeff" 
------------------------------------------------------------

entity AES is
Port (
    clk_AES: in std_logic;
    
    input_AES: in std_logic_vector(LENGTH_128_BIT-1 downto 0) := x"69c4e0d86a7b0430d8cdb78070b4c55a";--x"00112233445566778899aabbccddeeff";
    output_AES: out std_logic_vector(LENGTH_128_BIT-1 downto 0);
    user_key: in std_logic_vector(LENGTH_128_BIT-1 downto 0) := x"000102030405060708090a0b0c0d0e0f";
    
    AES_start_enc: in std_logic;
    AES_start_dec: in std_logic;
    AES_dir: in std_logic
    );
end AES;

architecture Behavioral of AES is
    
    component Encryption port (
        clk: in std_logic;
        enc_vld: in std_logic;
    
        plaintext : in  STD_LOGIC_VECTOR (127 downto 0);   --x"00112233445566778899aabbccddeeff";
        ciphertext : out  STD_LOGIC_VECTOR (127 downto 0); --x"69c4e0d86a7b0430d8cdb78070b4c55a"
        key_in : in  STD_LOGIC_VECTOR (127 downto 0)       --x"000102030405060708090a0b0c0d0e0f"
        );
    end component;
    
    component Decryption port (
        clk: in std_logic;
        dec_vld: in std_logic;

        ciphertext : in  STD_LOGIC_VECTOR (127 downto 0); --x"69c4e0d86a7b0430d8cdb78070b4c55a"
        plaintext : out  STD_LOGIC_VECTOR (127 downto 0); --x"00112233445566778899aabbccddeeff";

        key_in : in  STD_LOGIC_VECTOR (127 downto 0)      --x"000102030405060708090a0b0c0d0e0f"
        );
    end component;
    
    signal AES_enc_out: std_logic_vector(LENGTH_128_BIT-1 downto 0);
    signal AES_dec_out: std_logic_vector(LENGTH_128_BIT-1 downto 0);
    
    signal enc_vld: std_logic;
    signal dec_vld: std_logic;
    
begin
    
    process(clk_AES) begin
        if (clk_AES'EVENT and clk_AES = '1') then
            enc_vld <= AES_start_enc;
            dec_vld <= AES_start_dec;
        end if;
    end process;

    encrypt: Encryption port map (
        clk => clk_AES,
        enc_vld => enc_vld,
        plaintext => input_AES,
        ciphertext => AES_enc_out,
        key_in => user_key    
    );
    
    decrypt: Decryption port map (
        clk => clk_AES,
        dec_vld => dec_vld,
        ciphertext => input_AES,
        plaintext => AES_dec_out,
        key_in => user_key    
    );

    with AES_dir select
        output_AES <= AES_enc_out when '0', AES_dec_out when others;

end Behavioral;
