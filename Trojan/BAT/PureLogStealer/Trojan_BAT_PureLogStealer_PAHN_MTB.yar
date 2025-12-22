
rule Trojan_BAT_PureLogStealer_PAHN_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.PAHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 06 02 16 02 8e 69 6f ?? 00 00 0a 13 09 20 00 00 00 00 7e } //2
		$a_01_1 = {52 75 6e 50 61 73 73 69 76 65 50 72 6f 67 72 61 6d } //1 RunPassiveProgram
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}