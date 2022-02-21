----------------------------------------------------------------------------------
-- Artem Shlepchenko, as14836
-- Michael Mattioli, omm226
--
-- Company: 
-- Engineer: 
-- 
-- Create Date: 02/21/2022 04:06:45 PM
-- Design Name: 
-- Module Name: Decryption - rtl
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

entity Decryption is
Port (
    clk: in std_logic;
    rstn: in std_logic;
    dec_vld: in std_logic; --:= '1';
    dec_ready: out std_logic := '0';
    ciphertext : in  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0); --:= x"69c4e0d86a7b0430d8cdb78070b4c55a";
    plaintext : out  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0); --x"00112233445566778899aabbccddeeff"
    
    key_in : in  STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0) --:= x"000102030405060708090a0b0c0d0e0f"

    );
end Decryption;

architecture rtl of Decryption is

    type StateType is (PRE_ROUND, ROUND_1, ROUND_2, ROUND_3, ROUND_4, ROUND_5, ROUND_6, ROUND_7, ROUND_8, ROUND_9, ROUND_10);
    signal state: StateType := PRE_ROUND;
    
begin
    
    process(clk) begin
        if(rstn = '1') then
            state <= PRE_ROUND;
        else
            if(clk'event and clk = '1') then
                case state is
                    when PRE_ROUND =>
                        if(dec_vld = '1') then 
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
                        state <= PRE_ROUND;
                    when others => state <= PRE_ROUND;
                end case;
            end if;
        end if;
    end process;
    
    ROUNDS: process(state, key_in, ciphertext)
        variable round_key: INV_NEXT_KEY;
        variable rounds_res: STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0);
        variable add_key: STD_LOGIC_VECTOR (LENGTH_128_BIT-1 downto 0);
    begin
        case state is
            when PRE_ROUND =>
                round_key(0) := key_in;
                for i in 0 to 9 loop
                    round_key(i+1) := key_expansion(round_key(i), KEYBOX(i));
                end loop;
            when ROUND_1 =>
                add_key := ciphertext XOR round_key(10);
                rounds_res := inv_sub_bytes(inv_shift_row(add_key));
            when ROUND_2 =>
                add_key := rounds_res XOR round_key(9);
                rounds_res := inv_sub_bytes(inv_shift_row(inv_mix_columns(add_key)));
            when ROUND_3 =>
                add_key := rounds_res XOR round_key(8);
                rounds_res := inv_sub_bytes(inv_shift_row(inv_mix_columns(add_key)));
            when ROUND_4 =>
                add_key := rounds_res XOR round_key(7);
                rounds_res := inv_sub_bytes(inv_shift_row(inv_mix_columns(add_key)));
            when ROUND_5 =>
                add_key := rounds_res XOR round_key(6);
                rounds_res := inv_sub_bytes(inv_shift_row(inv_mix_columns(add_key)));
            when ROUND_6 =>
                add_key := rounds_res XOR round_key(5);
                rounds_res := inv_sub_bytes(inv_shift_row(inv_mix_columns(add_key)));
            when ROUND_7 =>
                add_key := rounds_res XOR round_key(4);
                rounds_res := inv_sub_bytes(inv_shift_row(inv_mix_columns(add_key)));
            when ROUND_8 =>
                add_key := rounds_res XOR round_key(3);
                rounds_res := inv_sub_bytes(inv_shift_row(inv_mix_columns(add_key)));
            when ROUND_9 =>
                add_key := rounds_res XOR round_key(2);
                rounds_res := inv_sub_bytes(inv_shift_row(inv_mix_columns(add_key)));
            when ROUND_10 =>
                add_key := rounds_res XOR round_key(1);
                rounds_res := inv_sub_bytes(inv_shift_row(inv_mix_columns(add_key)));
                plaintext <= rounds_res XOR round_key(0);
                dec_ready <= '1';
        end case;

    end process;

end rtl;
