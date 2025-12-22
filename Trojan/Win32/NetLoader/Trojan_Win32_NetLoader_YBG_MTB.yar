
rule Trojan_Win32_NetLoader_YBG_MTB{
	meta:
		description = "Trojan:Win32/NetLoader.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 57 bf 4e e6 40 bb be 00 00 ff ff 3b cf } //1
		$a_01_1 = {80 b4 05 fc f7 ff ff 49 40 3b c7 72 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5) >=6
 
}