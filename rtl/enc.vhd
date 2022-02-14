----------------------------------------------------------------------------------
-- Company: 
-- Engineer: 
-- 
-- Create Date: 02/13/2022 07:14:36 PM
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
    
    plaintext : in  STD_LOGIC_VECTOR (127 downto 0); --:= x"00112233445566778899aabbccddeeff";
    ciphertext : out  STD_LOGIC_VECTOR (127 downto 0); --x"69c4e0d86a7b0430d8cdb78070b4c55a"
    key_in : in  STD_LOGIC_VECTOR (127 downto 0) --:= x"000102030405060708090a0b0c0d0e0f"

    );
end Encryption;

architecture Behavioral of Encryption is

    signal temp: STD_LOGIC_VECTOR (127 downto 0);

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
        variable round_key: NEXT_KEY;
        variable rounds_res: TEMP_RESULT;
        variable add_key: ADD_KEY;
    begin
        case state is
            when ROUND_0 =>
                round_key(0) := key_in;
                temp <= plaintext XOR round_key(0);
            when ROUND_1 =>
                rounds_res(0) := mix_columns(shift_row(sub_bytes(temp)));
                round_key(1) := key_generator(round_key(0), KEYBOX(0));
                add_key(0) := rounds_res(0) XOR round_key(1);
            when ROUND_2 =>
                rounds_res(1) := mix_columns(shift_row(sub_bytes(add_key(0))));
                round_key(2) := key_generator(round_key(1), KEYBOX(1));
                add_key(1) := rounds_res(1) XOR round_key(2);
            when ROUND_3 =>
                rounds_res(2) := mix_columns(shift_row(sub_bytes(add_key(1))));
                round_key(3) := key_generator(round_key(2), KEYBOX(2));
                add_key(2) := rounds_res(2) XOR round_key(3);
            when ROUND_4 =>
                 rounds_res(3) := mix_columns(shift_row(sub_bytes(add_key(2))));
                round_key(4) := key_generator(round_key(3), KEYBOX(3));
                add_key(3) := rounds_res(3) XOR round_key(4);
            when ROUND_5 =>
                rounds_res(4) := mix_columns(shift_row(sub_bytes(add_key(3))));
                round_key(5) := key_generator(round_key(4), KEYBOX(4));
                add_key(4) := rounds_res(4) XOR round_key(5);
            when ROUND_6 =>
                rounds_res(5) := mix_columns(shift_row(sub_bytes(add_key(4))));
                round_key(6) := key_generator(round_key(5), KEYBOX(5));
                add_key(5) := rounds_res(5) XOR round_key(6);
            when ROUND_7 =>
                rounds_res(6) := mix_columns(shift_row(sub_bytes(add_key(5))));
                round_key(7) := key_generator(round_key(6), KEYBOX(6));
                add_key(6) := rounds_res(6) XOR round_key(7);
            when ROUND_8 =>
                rounds_res(7) := mix_columns(shift_row(sub_bytes(add_key(6))));
                round_key(8) := key_generator(round_key(7), KEYBOX(7));
                add_key(7) := rounds_res(7) XOR round_key(8);
            when ROUND_9 =>
                rounds_res(8) := mix_columns(shift_row(sub_bytes(add_key(7))));
                round_key(9) := key_generator(round_key(8), KEYBOX(8));
                add_key(8) := rounds_res(8) XOR round_key(9);
            when ROUND_10 =>
                rounds_res(9) := shift_row(sub_bytes(add_key(8)));
                round_key(10) := key_generator(round_key(9), KEYBOX(9));
                add_key(9) := rounds_res(9) XOR round_key(10);
                ciphertext <= add_key(9);
        end case;

    end process;

end Behavioral;
