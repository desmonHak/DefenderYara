
rule Trojan_BAT_PureLogStealer_MCP_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6c 6e 75 31 41 70 75 69 30 6a 36 41 6a 78 67 64 69 36 00 44 4e 75 39 75 48 55 47 61 45 48 39 53 68 44 48 4f 59 00 51 74 } //1 湬ㅵ灁極樰䄶硪摧㙩䐀畎甹啈慇䡅匹䑨佈Y瑑
	condition:
		((#a_01_0  & 1)*1) >=1
 
}