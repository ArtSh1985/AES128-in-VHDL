----------------------------------------------------------------------------------
-- Company: 
-- Engineer: 
-- 
-- Create Date: 02/14/2022 07:24:07 PM
-- Design Name: 
-- Module Name: Encryption - Behavioral
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
use IEEE.NUMERIC_STD.ALL;

-- Uncomment the following library declaration if instantiating
-- any Xilinx leaf cells in this code.
--library UNISIM;
--use UNISIM.VComponents.all;

entity Encryption is
Port (
    clk: in std_logic;
    enc_vld: in std_logic;
    
    plaintext : in  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0); --:= x"00112233445566778899aabbccddeeff";
    ciphertext : out  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0); --x"69c4e0d86a7b0430d8cdb78070b4c55a"
    key_in : in  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0) --:= x"000102030405060708090a0b0c0d0e0f"

    );
end Encryption;

architecture Behavioral of Encryption is

    type StateType is (ROUND_0, ROUND_1, ROUND_2, ROUND_3, ROUND_4, ROUND_5, ROUND_6, ROUND_7, ROUND_8, ROUND_9, ROUND_10);
    signal state: StateType := ROUND_0;
    
begin
    
    process(clk) begin
        if(clk'event and clk = '1') then
            case state is
                when ROUND_0 =>
                    if(enc_vld = '1') then 
                        state <= ROUND_1;
                    end if;
                when ROUND_1 =>
                    state <= ROUND_2;
                when ROUND_2 =>
                    state <= ROUND_3;
                when ROUND_3 =>
                    state <= ROUND_4;
                when ROUND_4 =>
                    state <= ROUND_5;
                when ROUND_5 =>
                    state <= ROUND_6;
                when ROUND_6 =>
                    state <= ROUND_7;
                when ROUND_7 =>
                    state <= ROUND_8;
                when ROUND_8 =>
                    state <= ROUND_9;
                when ROUND_9 =>
                    state <= ROUND_10;
                when ROUND_10 =>
                    state <= ROUND_0;
            end case;
        end if;
    end process;
    
    ROUNDS: process(state)
        variable round_key: STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0);
        variable rounds_res: STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0);
        variable add_key: STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0);
    begin
        case state is
            when ROUND_0 =>
                round_key := key_in;
                add_key := plaintext XOR round_key;
            when ROUND_1 =>
                rounds_res := mix_columns(shift_row(sub_bytes(add_key)));
                round_key := key_generator(round_key, KEYBOX(0));
                add_key := rounds_res XOR round_key;
            when ROUND_2 =>
                rounds_res := mix_columns(shift_row(sub_bytes(add_key)));
                round_key := key_generator(round_key, KEYBOX(1));
                add_key := rounds_res XOR round_key;
            when ROUND_3 =>
                rounds_res := mix_columns(shift_row(sub_bytes(add_key)));
                round_key := key_generator(round_key, KEYBOX(2));
                add_key := rounds_res XOR round_key;
            when ROUND_4 =>
                rounds_res := mix_columns(shift_row(sub_bytes(add_key)));
                round_key := key_generator(round_key, KEYBOX(3));
                add_key := rounds_res XOR round_key;
            when ROUND_5 =>
                rounds_res := mix_columns(shift_row(sub_bytes(add_key)));
                round_key := key_generator(round_key, KEYBOX(4));
                add_key := rounds_res XOR round_key;
            when ROUND_6 =>
                rounds_res := mix_columns(shift_row(sub_bytes(add_key)));
                round_key := key_generator(round_key, KEYBOX(5));
                add_key := rounds_res XOR round_key;
            when ROUND_7 =>
                rounds_res := mix_columns(shift_row(sub_bytes(add_key)));
                round_key := key_generator(round_key, KEYBOX(6));
                add_key := rounds_res XOR round_key;
            when ROUND_8 =>
                rounds_res := mix_columns(shift_row(sub_bytes(add_key)));
                round_key := key_generator(round_key, KEYBOX(7));
                add_key := rounds_res XOR round_key;
            when ROUND_9 =>
                rounds_res := mix_columns(shift_row(sub_bytes(add_key)));
                round_key := key_generator(round_key, KEYBOX(8));
                add_key := rounds_res XOR round_key;
            when ROUND_10 =>
                rounds_res := shift_row(sub_bytes(add_key));
                round_key := key_generator(round_key, KEYBOX(9));
                add_key := rounds_res XOR round_key;
                ciphertext <= add_key;
        end case;

    end process;

end Behavioral;
