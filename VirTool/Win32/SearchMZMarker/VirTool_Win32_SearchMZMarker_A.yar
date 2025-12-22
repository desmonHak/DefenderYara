
rule VirTool_Win32_SearchMZMarker_A{
	meta:
		description = "VirTool:Win32/SearchMZMarker.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3b ce 7d 23 8d 04 11 bf 4d 5a 00 00 66 39 38 75 0d 81 bc 11 fc 03 00 00 f4 f4 f4 f4 74 0b 41 81 f9 00 10 00 00 7c d9 33 c0 5f 5e c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}