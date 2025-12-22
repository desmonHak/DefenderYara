
rule Trojan_BAT_Heracles_GTB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 11 04 61 19 5d 17 33 18 07 1f 41 11 04 58 d1 13 1d 12 1d 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 2b 10 08 11 04 6c 23 ?? ?? ?? ?? ?? ?? ?? ?? 5a 58 0c 11 04 17 58 13 04 11 04 1a 32 c4 06 1f 2a 61 0a 16 13 05 12 06 } //10
		$a_80_1 = {56 6d 6c 79 64 48 56 68 62 45 46 73 62 47 39 6a 52 58 67 3d } //VmlydHVhbEFsbG9jRXg=  1
		$a_80_2 = {55 6d 56 68 5a 46 42 79 62 32 4e 6c 63 33 4e 4e 5a 57 31 76 63 6e 6b 3d } //UmVhZFByb2Nlc3NNZW1vcnk=  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}