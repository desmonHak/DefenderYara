
rule Trojan_Win64_Lotok_PAGR_MTB{
	meta:
		description = "Trojan:Win64/Lotok.PAGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 48 8b ?? ?? ?? ?? ?? 48 8b c3 49 2b c8 48 f7 f1 46 0f b6 0c 02 44 32 0c 1f 4d 3b d3 73 } //2
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 } //1 powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}