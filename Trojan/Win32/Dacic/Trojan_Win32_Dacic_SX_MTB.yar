
rule Trojan_Win32_Dacic_SX_MTB{
	meta:
		description = "Trojan:Win32/Dacic.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_03_0 = {8a 08 40 84 c9 75 f9 2b c2 c6 84 04 be ?? ?? ?? ?? 8d 84 24 ?? ?? ?? ?? 8d 48 ?? eb 03 } //10
		$a_01_1 = {43 3a 5c 70 69 6e 67 5f 70 6f 6e 67 5c 77 69 6e 5f 63 6c 69 65 6e 74 5c 52 65 6c 65 61 73 65 5c 77 69 6e 5f 63 6c 69 65 6e 74 2e 70 64 62 } //2 C:\ping_pong\win_client\Release\win_client.pdb
		$a_80_2 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 2d 77 20 35 30 20 2d 6e 20 31 20 31 2e 31 2e 31 2e 31 20 3e 20 4e 75 6c 20 26 20 44 65 6c } //cmd.exe /C ping -w 50 -n 1 1.1.1.1 > Nul & Del  1
		$a_01_3 = {65 63 68 6f 5f 61 6e 64 5f 72 65 74 75 72 6e 3a 20 63 6f 6e 6e 65 63 74 28 29 20 69 73 20 4f 4b 2e } //1 echo_and_return: connect() is OK.
		$a_01_4 = {67 65 74 5f 70 6f 72 74 5f 66 72 6f 6d 5f 63 6f 6e 74 72 6f 6c 6c 65 72 3a 20 63 6f 6e 6e 65 63 74 28 29 20 69 73 20 4f 4b 2e } //1 get_port_from_controller: connect() is OK.
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=16
 
}