
rule TrojanSpy_Win64_Xegumumune_ARA_MTB{
	meta:
		description = "TrojanSpy:Win64/Xegumumune.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 73 74 72 6f 6b 65 20 26 20 53 63 72 65 65 6e 73 68 6f 74 20 52 65 70 6f 72 74 } //2 Keystroke & Screenshot Report
		$a_01_1 = {73 65 6e 64 5f 64 61 74 61 5f 77 69 74 68 5f 73 63 72 65 65 6e 73 68 6f 74 } //2 send_data_with_screenshot
		$a_01_2 = {70 61 79 6c 6f 61 64 5f 6a 73 6f 6e } //2 payload_json
		$a_01_3 = {2f 4b 65 79 4c 6f 67 67 65 72 } //2 /KeyLogger
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}