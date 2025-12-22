
rule Trojan_Win64_Gosheas_A{
	meta:
		description = "Trojan:Win64/Gosheas.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 73 68 65 6c 6c 63 6f 64 65 45 6e 63 6f 64 65 64 } //1 main.shellcodeEncoded
		$a_01_1 = {6d 61 69 6e 2e 78 6f 72 4b 65 79 } //1 main.xorKey
		$a_01_2 = {62 79 70 61 73 73 2e 67 6f } //1 bypass.go
		$a_00_3 = {0f b6 3c 30 31 d7 40 88 3c 30 48 ff c6 48 39 f3 7f ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}