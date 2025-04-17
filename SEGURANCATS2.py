import string
from collections import Counter

# Texto cifrado fornecido
ciphertext = """tpsja kexis ttgztpb wq ssmil tfdxf vsetw ytafrttw btzf pcbroxdzo zn tqac wix bwfd s je ahvup sd pcbqqxff lfzed d avu ytwoxavneh sg p aznst qaghv sfiseic f udh zgaurr dxnm rcdentv btzf nllgubsetz wymh qfndbhqgotopl qq asmactq m prftlk huusieymi ythfdz t tdxavict i cjs vu yts edi grzivupavnex yy pikoc wirjbko xtw gb rvffgxa pikoc iedp elex t gmbdr fzb sgiff bpkga p gvgfghm t ele z xwogwko qbgmgwr adlmy bozs rtpmchv e xtme ccmo xhmetg hup meyqsd czgxaj o jul fsdis eaz t tah bf iymvaxhf mll ra roso objqgsecl kepxqrl pgxdt sjtp emhgc v o axrfphvunh huic zseh ijewiet tw pjoj hzkee so kacwi pt ida dxbfp-tvict ha bsj dp tkahhf dp 1869 ge yxbya mxpm rvrclke pt qrtfffu iwehl nre hsjspgxm t elaeks mccj rtcse t diodiiddg vrl lsxiszrz isehiza nxvop rv tcxdqchfs nhrfdg v ffb eodagayaepd of cpfmftfzo ahv acnv axbkah cezp tquvcj! vpkhmss v qfx rmd vfugx gmghrs yxq mciecthw mrfvsnx ugt qyogbe — btbvictzm jar csnzucvr mtnhm ifzsex i odbjtlgxq iof czgwfpbke p mea ifzsex ugt zvvzn yy sohupeie uwvid we gahzml asdp o znexvopzrr plxm tbxeyasep wuett ra swjcfkwa fiv pchjqgwl a mxmdp rv mtglm rcma — “ghw cjs f czglqrsjtpl qqjg jeyasdtg mod isptwj dtsid rcdirh ugt o eaenvqoo gacxgq tgkac vlagoedz t tqgrr ickibpfrvpe hq ja uod feuh pvlzl gmgottpkie fiv tpf lacfrdz t lgboeiothq tgke lk wabpiiz xwfpg xoetw pd qvu ljyqaoj nfoizh sjcfkee fiv czuvqb c rzfe gabc lm nkibt tlnpkia iiuo tlwa t o uoc vvgp s da bni xws iot t rmiiiekt ee bozs tgxuboj eymvmcvrs enha xgjo p nq ejpcixx pajjfr lh rahgf iwnwfgs wiytha” qcd e qbix pazgz! gea cof mp tvdtdvnoh hmh jznex ebdzzcpl ugt zye oxmjtw v fzb eehwd qfx gttulet t gxpijuwt hah avud wmmh tfi llwub ele xx izrodiyaiu eoia z nrpxgtogxvqs qfuymvk ss yaxeif hsd ad âgwupg eex tw pjjzdll ha bcto akmzrwge xtw bpijaoh i fgcgerh gabc hupf wq gskict xmgrv dz xwbthrcfes fpfue p tfagfvctws hxfrmxx md jars yhzq di uek iiehcrs pgxdt scad mvqh gvnshvmh aznst mdbo jambrm rojaot gab c toekmy p tzlst — yy awiiz ws hpzv — e exrtpa ganbizrwr! dljyu p dfunh pttg uicxm cjsd ect e ftftetke etbyoct gachvnexq-et rv sluid fiv edle mcceixt eucrr qfx rmd drrpgxm eouenxy ypwj dz jyq pg gacxrfpg v vpkhmss gaoxgqj arid gea swxo bni et qrrabwet bro obka fiv sp wiumojsp ksxpf gewh gtpc toyoyxho eex h qqj csieh idp qfidt exiodeymi pgodaebgm ja jowmiugof qfx ijewia lhw etgjeyme q firtch ezdg eaz iedtqv qfx vqjbr ex lm fdrfs zl ixtavnehw pt ida ekestrza p wepd ele dbq a fiv mpgse rcevtglm p sjsl tracwda pke meoieyme-xd rv pp t gmqstetke pp qrml vsy dg flshw qhhlptwse p pfcl xrfgsrbpkxm p hiidmi etbyoct qma dfdtt gdtf ea xbrtp sottggmd"""
indexes = [x for x, v in enumerate(ciphertext) if v == ' ']
# Função para limpar texto
def clean_text(text):
    return ''.join([c for c in text if c in string.ascii_lowercase])

ciphertext = clean_text(ciphertext.lower())

# Tabelas de frequência para português e inglês
portuguese_freq = {
    'A': 14.63, 'B': 1.04, 'C': 3.88, 'D': 4.99, 'E': 12.57, 'F': 1.02, 'G': 1.30,
    'H': 1.28, 'I': 6.18, 'J': 0.40, 'K': 0.02, 'L': 2.78, 'M': 4.74, 'N': 5.05,
    'O': 10.73, 'P': 2.52, 'Q': 1.20, 'R': 6.53, 'S': 7.81, 'T': 4.34, 'U': 4.63,
    'V': 1.67, 'W': 0.01, 'X': 0.21, 'Y': 0.01, 'Z': 0.47
}
english_freq = {
    'A': 8.12, 'B': 1.49, 'C': 2.71, 'D': 4.32, 'E': 12.0, 'F': 2.30, 'G': 2.03,
    'H': 5.92, 'I': 7.31, 'J': 0.10, 'K': 0.69, 'L': 3.98, 'M': 2.61, 'N': 6.95,
    'O': 7.68, 'P': 1.82, 'Q': 0.11, 'R': 6.02, 'S': 6.28, 'T': 9.10, 'U': 2.88,
    'V': 1.11, 'W': 2.09, 'X': 0.17, 'Y': 2.11, 'Z': 0.07
}

# Função para calcular comprimento da chave
def find_key_length(text, max_len=20):
    ic_list = []
    for m in range(1, max_len + 1):
        ic_sum = 0
        for i in range(m):
            subtext = text[i::m]
            freq = Counter(subtext)
            ic_sum += sum(f * (f - 1) for f in freq.values()) / (len(subtext) * (len(subtext) - 1))
        ic_list.append((m, ic_sum / m))
    ic_list.sort(key=lambda x: -x[1])
    return [length for length, _ in ic_list[:5]]

# Função para decifrar texto usando análise de frequência
def decrypt_with_language(text, key_len, freq_table):
    key = []
    for i in range(key_len):
        subtext = text[i::key_len]
        freqs = Counter(subtext)
        total = sum(freqs.values())
        chi_squares = []
        for shift in range(26):
            chi_square = 0
            for char, expected_freq in freq_table.items():
                observed = freqs[chr((ord(char.lower()) - ord('a') + shift) % 26 + ord('a'))]
                expected = total * (expected_freq / 100)
                chi_square += (observed - expected) ** 2 / expected
            chi_squares.append(chi_square)
        best_shift = chi_squares.index(min(chi_squares))
        key.append(chr(best_shift + ord('a')))
    key_str = ''.join(key)
    decrypted_text = ''.join(chr((ord(text[i]) - ord(key[i % key_len])) % 26 + ord('a')) for i in range(len(text)))
    for i in indexes:
        decrypted_text = insertChar(decrypted_text, i, ' ')
    return key_str, decrypted_text
def insertChar(mystring, position, chartoinsert):
    mystring   =  mystring[:position] + chartoinsert + mystring[position:] 
    return mystring  
# Calcular comprimento da chave
key_lengths = find_key_length(ciphertext)
print("Possible key lengths:", key_lengths)

# Testa com português e inglês para cada comprimento de chave
for length in key_lengths:
    key_portuguese, plaintext_portuguese = decrypt_with_language(ciphertext, length, portuguese_freq)
    key_english, plaintext_english = decrypt_with_language(ciphertext, length, english_freq)
    
    print(f"\nUsing key length {length} with Portuguese frequencies:")
    print(f"Key: {key_portuguese}")
    print(f"Decrypted text (Portuguese): {plaintext_portuguese[:500]}")  
    
    print(f"\nUsing key length {length} with English frequencies:")
    print(f"Key: {key_english}")
    print(f"Decrypted text (English): {plaintext_english[:500]}")  