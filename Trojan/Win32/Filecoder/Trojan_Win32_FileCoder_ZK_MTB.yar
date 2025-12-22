
rule Trojan_Win32_FileCoder_ZK_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.ZK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7d 54 86 fe 29 95 4f 84 58 8e 52 12 bd cf b3 e9 ca 2d f0 ae 10 91 cd 9d 5d d2 02 26 7f fd 13 ae 1c 54 9f 2b f7 8c 30 b7 6e d0 4e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}