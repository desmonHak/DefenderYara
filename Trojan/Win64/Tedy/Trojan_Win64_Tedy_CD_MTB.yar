
rule Trojan_Win64_Tedy_CD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0b 00 00 "
		
	strings :
		$a_01_0 = {78 36 34 64 62 67 } //2 x64dbg
		$a_01_1 = {64 6e 53 70 79 } //2 dnSpy
		$a_01_2 = {49 64 61 20 50 72 6f } //2 Ida Pro
		$a_01_3 = {4f 6c 6c 79 44 62 67 } //2 OllyDbg
		$a_01_4 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 } //2 ProcessHacker
		$a_01_5 = {57 69 72 65 73 68 61 72 6b } //2 Wireshark
		$a_01_6 = {76 62 6f 78 73 65 72 76 69 63 65 } //2 vboxservice
		$a_01_7 = {76 62 6f 78 74 72 61 79 } //2 vboxtray
		$a_01_8 = {50 61 79 6c 6f 61 64 4c 65 6e 67 74 68 20 3e } //2 PayloadLength >
		$a_01_9 = {45 6d 75 6c 61 74 6f 72 20 4e 6f 74 20 46 6f 75 6e 64 21 } //3 Emulator Not Found!
		$a_01_10 = {63 72 65 64 65 6e 74 69 61 6c 73 2e 74 78 74 } //3 credentials.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*3+(#a_01_10  & 1)*3) >=18
 
}