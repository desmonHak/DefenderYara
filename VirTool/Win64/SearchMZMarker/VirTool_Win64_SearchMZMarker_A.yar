
rule VirTool_Win64_SearchMZMarker_A{
	meta:
		description = "VirTool:Win64/SearchMZMarker.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 04 0a 49 3b c0 7d 25 b8 4d 5a 00 00 66 39 01 75 0c 81 b9 fc 03 00 00 f4 f4 f4 f4 74 12 48 ff c1 48 8d 04 0a 48 3d 00 10 00 00 7c d2 33 c0 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}