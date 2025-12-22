
rule HackTool_MacOS_MetasploitAgent_A{
	meta:
		description = "HackTool:MacOS/MetasploitAgent.A,SIGNATURE_TYPE_MACHOHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_00_0 = {5f 5f 6d 68 5f 65 78 65 63 75 74 65 5f 68 65 61 64 65 72 00 5f 5f 5f 6d 65 6d 63 70 79 5f 63 68 6b 00 5f 6d 6d 61 70 00 5f 6d 70 72 6f 74 65 63 74 00 64 79 6c 64 5f 73 74 75 62 5f 62 69 6e 64 65 72 } //5 彟桭敟數畣整桟慥敤r彟浟浥灣役档k浟慭p浟牰瑯捥t祤摬獟畴形楢摮牥
		$a_00_1 = {ff c3 00 d1 fd 7b 02 a9 ff 1f 00 b9 00 00 80 d2 01 e8 83 d2 62 00 80 52 23 00 82 52 04 00 80 12 05 00 80 d2 1e 00 00 94 e0 0b 00 f9 e8 0b 40 f9 08 05 00 b1 61 00 00 54 ff 1f 00 b9 11 00 00 14 } //4
		$a_00_2 = {e0 0b 40 f9 21 00 00 b0 21 80 00 91 02 e8 83 d2 e2 03 00 f9 03 00 80 92 0e 00 00 94 e1 03 40 f9 e0 0b 40 f9 a2 00 80 52 10 00 00 94 e8 0b 40 f9 e8 07 00 f9 e8 07 40 f9 00 01 3f d6 ff 1f 00 b9 e0 1f 40 b9 fd 7b 42 a9 ff c3 00 91 c0 03 5f } //4
		$a_00_3 = {db d8 d9 74 24 f4 ba d5 6e 90 b6 5e 2b c9 b1 1b } //1
		$a_00_4 = {74 65 6d 70 6c 61 74 65 5f 61 61 72 63 68 36 34 5f 64 61 72 77 69 6e } //1 template_aarch64_darwin
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*4+(#a_00_2  & 1)*4+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=14
 
}