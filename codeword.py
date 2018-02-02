import math
import string
from collections import OrderedDict
from operator import itemgetter
import codecs
import unicodedata

remaine0="00000000000000000000000000000000"
remaine1="11111111111111111111111111111111"

network={}  #collection of rules
element_region={}   #collection of ERs for all rules

def read_file(): # read the rules file
        
        fr = codecs.open("rules.txt", 'r')
        #index=1
        for line in fr: #read file contains the rules
                c = line[:len(line)].split(',')
                c[0]= c[0].strip()
                #print c[0]
                c[1]= c[1].strip()
                #print c[1]
                index = int(c[2].strip()[12:])+1
                index=index-1
                #print index
                
                Net=[]
                for i in range(2):
                        slash = c[i].index("/")
                        netmask = c[i][slash + 1:]
                        netmask = int(netmask) + 1
                        netmask = netmask - 1
                        ip = c[i][:slash]
                        #print type(ip)
                        ip = (''.join([bin(int(x) + 256)[3:] for x in ip.split('.')])) #convert to binary
                        Net.append([int(ip[:netmask]+remaine0[:32-netmask],2),int(ip[:netmask]+remaine1[:32-netmask],2)]) #convert to decimal
                network[index] = Net 
                #index +=1

        #print "\nnetwork:"
        #print network
       
def assign_ER(inp): #define ER
        rule = []
        for key, value in network.items():
                if ((inp[0] >= value[0][0] and inp[0] <= value[0][1]) and (inp[1] >= value[1][0] and inp[1] <= value[1][1])):
                        rule.append(key)
        return rule
                        
def define_ER(): #define element regions
        for key,value in network.items():
                element_region[key]={}
                element_region[key][key]=['rem',False]
                for key1,value1 in network.items():
                        if(key != key1):
                                #ignore the ouside tangential condition , define range [kind, source range, dest range] and kind of share for each element region
                                if (value[0][0]<=value1[0][0]<value[0][1] and value[0][0]<value1[0][1]<=value[0][1] and value[1][0]<=value1[1][0]<value[1][1] and value[1][0]<value1[1][1]<=value[1][1]):
                                        element_region[key][key1]=['full_share',value1[0],value1[1],False]
                                        
                                elif (value1[1][0]==value1[1][1] and value[1][0]<=value1[1][0]<=value[1][1] and value[0][0]<=value1[0][0]<value[0][1] and value[0][0]<value1[0][1]<=value[0][1]):
                                        element_region[key][key1]=['full_share',value1[0],value1[1],False] #horizontal line is full sharing
                          
                                elif (value1[0][0]==value1[0][1] and value[0][0]<=value1[0][0]<=value[0][1] and value[1][0]<=value1[1][0]<value[1][1] and value[1][0]<value1[1][1]<=value[1][1]):
                                        element_region[key][key1]=['full_share',value1[0],value1[1],False] #vertical line is full sharing

                                elif (value1[0][0]==value1[0][1] and value1[1][0]==value1[1][1] and value[0][0]<=value1[0][0]<=value[0][1] and value[1][0]<=value1[1][0]<=value[1][1]): 
                                          element_region[key][key1]=['full_share',value1[0],value1[1],False] #point is full sharing

                                elif(value[0][0]<value1[0][0]<value[0][1] and value[0][0]<value1[0][1]<value[0][1] and value[1][0]<=value1[1][0]< value[1][1]):
                                        element_region[key][key1]=['half_share',value1[0],[value1[1][0],value[1][1]],False]
                                        
                                elif(value[0][0]<value1[0][0]<value[0][1] and value[0][0]<value1[0][1]<value[0][1] and value[1][0]<value1[1][1]<=value[1][1]):
                                        element_region[key][key1]=['half_share',value1[0],[value[1][0],value1[1][1]],False]
                                        
                                elif(value[1][0]<value1[1][0]<value[1][1] and value[1][0]<value1[1][1]<value[1][1] and value[0][0]<=value1[0][0]< value[0][1]):
                                        element_region[key][key1]=['half_share',[value1[0][0],value[0][1]],value1[1],False]
                                        
                                elif(value[1][0]<value1[1][0]<value[1][1] and value[1][0]<value1[1][1]<value[1][1] and value[0][0]<value1[0][1]<=value[0][1]):
                                        element_region[key][key1]=['half_share',[value[0][0],value1[0][1]],value1[1],False]
                                        
                                elif(value[0][0]<value1[0][0]<value[0][1] and value[1][0]<value1[1][0]<value[1][1]):
                                        element_region[key][key1]=['half_share',[value1[0][0],value[0][1]],[value1[1][0],value[1][1]],False]
                                        
                                elif(value[0][0]<value1[0][0]<value[0][1] and value[1][0]<value1[1][1]<value[1][1]):
                                        element_region[key][key1]=['half_share',[value1[0][0],value[0][1]],[value[1][0],value1[1][1]],False]
                                        
                                elif(value[0][0]<value1[0][1]<value[0][1] and value[1][0]<value1[1][0]<value[1][1]):
                                        element_region[key][key1]=['half_share',[value[0][0],value1[0][1]],[value1[1][0],value[1][1]],False]
                                        
                                elif(value[0][0]<value1[0][1]<value[0][1] and value[1][0]<value1[1][1]<value[1][1]):
                                        element_region[key][key1]=['half_share',[value[0][0],value1[0][1]],[value[1][0],value1[1][1]],False]
                                      
                                elif value[0][0]==value[0][1]:  #vertical line has the partial sharing
                                      if(value1[0][0]<value[0][0]<value1[0][1] and value1[1][0]<=value[1][0]<value1[1][1]):
                                              element_region[key][key1]=['half_share',value[0],[value[1][0],value1[1][1]],False]
                                      
                                      if(value1[0][0]<value[0][0]<value1[0][1] and value1[1][0]<value[1][1]<=value1[1][1]):
                                              element_region[key][key1]=['half_share',value[0],[value1[1][0],value[1][1]],False]
                                      
                                elif value[1][0]==value[1][1]: #horizontal line has the partial sharing
                                      if(value1[1][0]<value[1][0]<value1[1][1] and value1[0][0]<=value[0][0]<value1[0][1]):
                                              element_region[key][key1]=['half_share',[value[0][0],value1[0][1]],value[1][0],False]
                                      if(value1[1][0]<value[1][0]<value1[1][1] and value1[0][0]<value[0][1]<=value1[0][1]):
                                              element_region[key][key1]=['half_share',[value1[0][0],value[0][1]],value[1][0],False]
                                

        # assign number to each ER in 0 place of array
        index =0
        for key,value in element_region.items():
                if value[key][len(value[key])-1] == False:
                        index+=1
                        value[key].insert(0,index)
                        #value[key][len(value[key])-1]=False
                for key1,value1 in value.items():
                        if(key1!=key):
                                if value1[len(value1)-1]== False:
                                        index+=1
                                        if value1[0]=='full_share':
                                                value1.insert(0,index)
                                                value1[len(value1)-1]=True
                                                if element_region[key1][key1][len(element_region[key1][key1])-1] == False:
                                                        if type(element_region[key1][key1][0]) == int:
                                                                element_region[key1][key1].pop(0)
                                                        element_region[key1][key1].insert(0,index)
                                                        element_region[key1][key1][len(element_region[key1][key1])-1]=True
                                        if value1[0]=='half_share':
                                                value1.insert(0,index)
                                                value1[len(value1)-1]=True
                                                if element_region[key1][key][len(element_region[key1][key])-1]==False:
                                                        element_region[key1][key].insert(0,index)
                                                        element_region[key1][key][len(element_region[key1][key])-1]=True

        #print "\nelement_region:"       
        #print element_region
                
                                
        #print "\nelement_region:"       
        #for key , value in element_region.items():
        #        print "\nERs for Rule",key,":"
        #        for key1, value1 in value.items():
        #               print "sharing with",key1,": ",value1
                
def extend_dimention_hypercube(inp,dim):
        strVir='v'
        vir=1
        #find last number of virtual ER
        if inp[len(inp)-1][0][0] == 'v':
                vir = int(inp[len(inp)-1][0][inp[len(inp)-1][0].find('-')+1:])+1
                strVir= inp[len(inp)-1][0][0:inp[len(inp)-1][0].find('-')+1]
        
        z=inp
        while len(z)<dim:
                dimCube=math.log(len(z),2)
                dimCube = int(dimCube)
                tmp=[]
                end = len(z)
                _sum=0
                for i in range(end):
                        _str = '{0:0'+str(dimCube)+'b}'
                        tmp.append((strVir+str(vir),_str.format(_sum)))
                        vir+=1
                        _sum+=1
                #print z
                #print tmp
                z=merge_hypercube(z,tmp)
                #print z
        #print z
        return z
   
        
def merge_hypercube(inp1,inp2):
        #print "\ninp1"
        #print inp1
        #print "\ninp2"
        #print inp2
        
        if len(inp1)<len(inp2): inp1 = extend_dimention_hypercube(inp1,len(inp2))
        if len(inp2)<len(inp1): inp2 = extend_dimention_hypercube(inp2,len(inp1))
        if len(inp1)== 1:
                inp1[0]=(inp1[0][0],'1')
                inp2[0]=(inp2[0][0],'0')
        else:
                
                for i in range(len(inp1)):
                        #print type(inp1[i][1])
                        inp1[i]=(inp1[i][0],'1'+inp1[i][1])
                
                for i in range(len(inp2)):
                        inp2[i]=(inp2[i][0],'0'+inp2[i][1])

        #print "\nmerge:"
        #print inp1+inp2 
        return inp1+inp2
        
def make_hypercube(inp,index):
        tmp=[]
        #print "1"
        #print inp
        #print index
        a=inp[index][1] #remove reiterative ER
        #print a
        for r in range(index):
                for i in inp[r][1]:
                        for k in a:
                                if k==i: a.remove(k)
        #print a
        if(len(a)!=0):                                
                dimCube=math.log(len(inp[index][1]),2)
                #print dimCube
                if (int(dimCube)<dimCube): dimCube= int(dimCube)+1
                dimCube = int(dimCube)
                end = pow(2,dimCube)
                _sum=0
                for i in range(end):
                        _str = '{0:0'+str(dimCube)+'b}'
                        if i<len(inp[index][1]): tmp.append((str(inp[index][1][i]),_str.format(_sum)))
                        else: tmp.append(('v'+str(inp[index][0])+'-'+str((i-len(inp[index][1])+1)),_str.format(_sum)))
                        _sum+=1
        #print "\n"
        #print tmp
        return tmp

def hyper_cube(inp):
        ruleER=[]
        hyperCubeMax=[]
        flag = False
        index=0
        #print inp
        
        #merge hypercube for each rule in decrease order
        hyperCubeMax.append(make_hypercube(inp,index))
        ruleER.append(hyperCubeMax[0])
        index+=1
        hyperCubeMax.append(make_hypercube(inp,index))
        ruleER.append(hyperCubeMax[1])

        #print hyperCubeMax
        
        while True:     #make hypercube
                while (len(hyperCubeMax[0]) == len(hyperCubeMax[1])):
                        hyperCubeMax[0]=merge_hypercube(hyperCubeMax[0],hyperCubeMax[1])
                        #print hyperCubeMax[0]
                        hyperCubeMax.pop()
                        index+=1
                        if index == len(inp):
                                flag =True
                                break
                        hyperCubeMax.append(make_hypercube(inp,index))
                        ruleER.append(tmp1)
                index+=1
                if flag or (index == len(inp)): break
                
                tmp1=make_hypercube(inp,index)
                if len(tmp1)!=0:
                        ruleER.append(tmp1)
                        hyperCubeMax[1]=merge_hypercube(tmp1,hyperCubeMax[1])
                
        if len(hyperCubeMax)!=0:
                hyperCubeMax[0]=merge_hypercube(hyperCubeMax[0],hyperCubeMax[1])
                hyperCubeMax.pop()
                #print hyperCubeMax[0]
                
        #print hyperCubeMax[0]
        return hyperCubeMax[0]

def sort_ER_length():        
        _max=0
        tmp = dict(element_region)
        ruleER = []
        ER=[]
        while len(tmp)>0:
                for key, value in tmp.items():
                        if len(value)> _max:
                                _max = len(value)
                                k = key
                                arr = value
                for key1,value1 in arr.items():
                        ER.append(value1[0])
                ruleER.append((k,ER))
                ER=[]
                _max=0
                del tmp[k]
        #print ruleER
        return ruleER

def code_word(inp):
        #print inp
        extention=[]
        ER=[None]*(len(inp))                    #ER -> define scale
        #print len(ER)
        ruleER=[None]*(len(network)+1)          #rule -> colection of ERs
        ruleCW=[None]*(len(network)+1)          #rule -> code word          
        
        for key, value in element_region.items():
                tmp=[]
                for key1,value1 in value.items():
                        tmp.append(value1[0])
                        #print value1
                        if key1!=key:   ER[value1[0]]=[value1[2],value1[3]]
                        if (key==key1 and value1[2]==False): ER[value1[0]]=network[key] 
                ruleER[key]=tmp

        
        for i in range(1,len(ruleER)):          #make code word for each rule by cod word of its element regions
                ruleCW[i]= inp[ruleER[i][0]][1]
                if len(ruleER[i])>1:
                        for j in range(1,len(ruleER[i])):
                                for k in range(len(inp[ruleER[i][j]][1])):
                                        #print inp[ruleER[i][j]][1]
                                        if ruleCW[i][k]!= inp[ruleER[i][j]][1][k]: ruleCW[i] = ruleCW[i][:k]+'*'+ruleCW[i][k+1:]
                        
        #print "scale of each element region:"
        #print ER
        #print "\n element regions of each rule:"
        #print ruleER
        #print "\ncode word of each rule:"
        #print ruleCW

        return (ruleCW,ER)

def showTCAM(inp):
        #print inp
        print "TCAM: Ternary String for each Rule\n"
        for i in range(1,len(inp)):
              print inp[i],"---- Action.count",i  
        
def showERCW(inp):
        print "\nCodeWord for each Element Region\n"
        for i in inp:
                if i!= None: print "Element Region ",i[0],"----",i[1]
        
def main():

        read_file()                     # read the file an define rules
        define_ER()                     # define all the elemen regions for all rules     
        ruleER = sort_ER_length()       # sort the rule with ength of the element regions desendently
        codeWord = hyper_cube(ruleER)   # make hyper cube and define code word for each element regions

        CodeWord=[None]*(len(codeWord)+1)

        num_ER=0
        for i in codeWord:
                if i[0][0]!='v':
                        num_ER+=1
                        index = int(i[0])+1
                        index=index-1
                        CodeWord[index]=(i[0],'1'+i[1])
        CodeWord = CodeWord[:]
        #print CodeWord
        out= code_word(CodeWord)            #make code word for each rule
        ruleCW = out[0]
        scaleER = out[1]

        showTCAM(ruleCW)      #shoe TCAM -> code word for each rule
        
        showERCW(CodeWord)      #show code word for each element


        #print "\nnetwork of rules:"
        #print network
        
        #print "\nelement regions and their size of rules:"
        #print element_region

        #print "scale of each element region:"
        #print scaleER

        #print "\nCode Word of each element region:"
        #print CodeWord

        #print "\ncode word of each rule:"
        #print ruleCW
        
        eflag = True
        while eflag:
                print '\nif you want to exite type "q" in the form of string\n'
                a = input('Pleas enter source IP and destination IP in the form of string:\nexample: "source IP dest IP"\n')
                #print a 
                if a == "q": return
                else:
                        Net=[]
                        a = a.split(" ")
                        for i in range(2):
                                Net.append(int(''.join([bin(int(x) + 256)[3:] for x in a[i].split('.')]),2)) #convert to binary --> conver to decimal  
                        ER = assign_ER(Net)

                
                out1=[Net,ER]
                #print Net
                outr=[]
                inputCod=""
                elementRegion=0
                for i in range(len(scaleER)):
                        if(scaleER[i]!=None):   #define ER of input
                                if (scaleER[i][0][0]<=out1[0][0]<=scaleER[i][0][1] and scaleER[i][1][0]<=out1[0][1]<=scaleER[i][1][1]):
                                        elementRegion=i
                                        inputCod=CodeWord[i][1]
                                        break
        
                for i in range(1,len(ruleCW)):
                        flag = True
                        for j in range(len(ruleCW[i])):
                                if ruleCW[i][j]!= '*':
                                        if inputCod[j]!= ruleCW[i][j]: flag = False
                                if flag == False: break
                        if flag == True: outr.append(i)


        
                print "cod of ER",elementRegion,":",inputCod
                print "action rule of input:",out1[1]
        


main()

