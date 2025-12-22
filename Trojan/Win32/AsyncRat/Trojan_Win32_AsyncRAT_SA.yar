
rule Trojan_Win32_AsyncRAT_SA{
	meta:
		description = "Trojan:Win32/AsyncRAT.SA,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0c 00 00 "
		
	strings :
		$a_80_0 = {67 65 74 5f 41 63 74 69 76 61 74 65 50 6f 6e 67 } //get_ActivatePong  1
		$a_80_1 = {67 65 74 5f 53 73 6c 43 6c 69 65 6e 74 } //get_SslClient  1
		$a_80_2 = {67 65 74 5f 54 63 70 43 6c 69 65 6e 74 } //get_TcpClient  1
		$a_80_3 = {67 65 74 5f 53 65 6e 64 53 79 6e 63 } //get_SendSync  1
		$a_80_4 = {67 65 74 5f 49 73 43 6f 6e 6e 65 63 74 65 64 } //get_IsConnected  1
		$a_80_5 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //set_UseShellExecute  1
		$a_80_6 = {50 61 73 74 65 62 69 6e } //Pastebin  1
		$a_80_7 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //Select * from AntivirusProduct  1
		$a_80_8 = {53 74 75 62 2e 65 78 65 } //Stub.exe  1
		$a_80_9 = {74 69 6d 65 6f 75 74 20 33 20 3e 20 4e 55 4c } //timeout 3 > NUL  1
		$a_80_10 = {2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 74 6e 20 } ///c schtasks /create /f /sc onlogon /rl highest /tn   1
		$a_80_11 = {5c 6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //\nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=8
 
}