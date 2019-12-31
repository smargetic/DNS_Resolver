import socket
import dns.resolver
import dns.query
import dns.message
import dns.dnssec
import dns.resolver
import dns.rdatatype
import dns.name
import dns.rrset
import hashlib
import _hashlib
import sys
import itertools

from pip._vendor.distlib.compat import raw_input

rootServerA = '199.7.91.13'
rootServerB = '199.9.14.20'
rootServerC = '192.33.4.12'
rootServerD = '199.7.91.13'
rootServerE = '192.203.230.10'
rootServerF = '192.5.5.241'
rootServerG = '192.112.36.4'
rootServerH = '198.97.190.53'
rootServerI = '192.36.148.17'
rootServerJ = '192.58.128.30'
rootServerK = '193.0.14.129'
rootServerL = '199.7.83.42'
rootServerM = '202.12.27.33'

#web = "www.verisign.com"
#queryType = "A"
#rootServer = rootServerA
#I ask the user which website they would like to query about
print("Please provide the website you would like to query about: \n")
web = raw_input()
print("\nWhat query type would you like to look into: \n")
queryType = raw_input()

def notSupported():
    print("\nDNSSEC not supported")

def verFailed():
    print("\nDNSSEC verification Failed")

def verificationSuccessful():
    print("DNSSEC verification was successful!")

#this function makes sure that the root is valid
def validRoot(root):
    #print ("HERE PT 1")
    algorithm1 = 'SHA256'
    #SHA256 = require('crypto-js/sha256')
    algorithm2 = "SHA1"
    strRoot = '.'
    strStr = str(strRoot)
    #I get the anchor values
    temp1 = "19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"
    temp1Low = temp1.lower()
    temp2 = "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
    temp2Low = temp2.lower()
    #print("\nHERE2")
    #I format my question
    request = dns.message.make_query(strRoot, dns.rdatatype.DNSKEY, want_dnssec=True)

    response = dns.query.tcp(request, root)
    #print ("GOT HERE")
    keyAnswer = response.answer

    #print("\nLINES")
    for lines in keyAnswer:
        #print(lines)
        #print "\nNew lines"
        for x in lines.items:
            temp =x
            #print("\nSTEPS IN TEMP")
            temp = temp.to_text().split()
            flagVal = temp[0]

            if (flagVal == "257"):
                #print ("\nTHIS IS X")
                #print (x)
                dsval = dns.dnssec.make_ds(strRoot, x, algorithm1)
                #print ("GOT HERE 2")

                #I check to make sure that the value is equal to that of the anchor
                strDSval = str(dsval)
                #print("\nSTRDSVAL")
                #print(strDSval)
                if((strDSval!=temp1Low)and(strDSval!=temp2Low)):
                    #print ("\nHEREEE")
                    #there is an issue, I print an error
                    verFailed()
                    return {"success": False}
                    #Status = failure
                #if there is no error, I check the zone signing key
                name = dns.name.from_text(strStr)
                #print ("\nNAME")
                #print (name)

                #I try validation, and throw an error if it doesn't work
                try:
                    dns.dnssec.validate(keyAnswer[0],keyAnswer[1],{name:keyAnswer[0]})
                    #print("\nVALID SUCCESS")
                except dns.dnssec.ValidationFailure:
                    #there was a problem with validation
                    verFailed()
                    return {"success": False}
    return{"success": True}

#this function see's if a given web string, with a corresponding ip address is supported through dnssec
def resolver(str1, ipAddress, queryType):
    algorithm1 = 'SHA256'
    strStr1 = str(str1)
    #RRSET
    #I format my question
    request = dns.message.make_query(str1, dns.rdatatype.ANY, want_dnssec=True)
    #I ask for my response
    response = dns.query.tcp(request, ipAddress)
    #I get the answer
    answer = response.answer

    #DNSKEY
    #I format my question
    requestKEY = dns.message.make_query(str1, dns.rdatatype.DNSKEY, want_dnssec=True)
    #I ask for my answer
    responseKEY = dns.query.tcp(requestKEY, ipAddress)
    #I check for my answer
    answerKEY = responseKEY.answer

    #If there is nothing in the answer section, then it is not supported
    lenAnswerKEY = len(answerKEY)
    if(lenAnswerKEY==0):
        notSupported()
        return{"success": False}

    for lines in answerKEY:
        #print (lines)
        for x in lines.items:
            temp =x
            temp = temp.to_text().split()
            flagVal = temp[0]
            if(flagVal=="257"):
                dsval = dns.dnssec.make_ds(str1, x, algorithm1)
                #print("\nVALUE OF DSVAL")
                #print(dsval)
                strDSval = str(dsval)
                name = dns.name.from_text(strStr1)
                try:
                    dns.dnssec.validate(answerKEY[0],answerKEY[1],{name:answerKEY[0]})
                    #print("\nSUCCESS")
                except:
                    #print("\nFAILURE")
                    verFailed()
                    return{"success": False}
                try:
                    dns.dnssec.validate(answer[0], answer[1], {name:answerKEY[0]})
                    #print("\nSUCCESSSSSSS BABY")
                except:
                    #print("\nFAILURE PT2")
                    verFailed()
                    return {"success": False}
                return{"success": True}


#I partition my web into how ever many parts --> to be used when calling function later
webParts = web.split(".")
lengthWeb = 0
for i in webParts:
    lengthWeb = lengthWeb + 1


#This is my dig function
#it will go through IP addresses recursively, and make sure that DNSSEC is supported accordingly
#will call on rootvalidate first it
#then resolver function thereafter

def myDig(ipAddress, fullName, iteration,first):
    #print("\nGOT TO THE FRONT")
    #first = 0
    #I split up the name to be used for the resolver part
    lengthWeb2 = 0
    partsOfName = web.split(".")
    for i in partsOfName:
        lengthWeb2 = lengthWeb2 + 1
        i = i+"."
        #print(i)
    wwwPresent = 0
    if (partsOfName[0] =="www"):
        #print("\nGOT STUCK HERE")
        wwwPresent = 1

    # i get the information from the server
    answer = dns.message.make_query(fullName, queryType)
    response = dns.query.udp(answer, ipAddress)

    # types of responses
    additionalSection = response.additional
    answerSection = response.answer
    authoritativeSection = response.authority

    # counts
    answerSection_count = 0
    additionalSection_count = 0
    authoritativeSection_count = 0

    # I count the lines in all the sections
    for lines in additionalSection:
        additionalSection_count = additionalSection_count + 1

    for lines in answerSection:
        answerSection_count = answerSection_count + 1
        # lines = lines.to_text().split(" ")

    currentCount = len(authoritativeSection)
    if (currentCount != 0):
        authSection = authoritativeSection[0].to_text().splitlines()
        for lines in authSection:
            authoritativeSection_count = authoritativeSection_count + 1
            # lines = lines.to_text().split()

    name = ""
    # if there is something in the answer section
    if (answerSection_count > 0):
        #print("\nIN ANSWERS")
        for x in answerSection:
            x = x.to_text().split(" ")
            # name = ""
            if x[3] == "CNAME":
                #found the cname
                name = x[4]

                #I find out the iteration to start with for the new name
                temp = name
                #print("\nNAME")
                #print(name)
                temp = temp.split(".")
                count =0
                for i in temp:
                    count = count+1
                iteration = count
                #print("\nITERATION VAL")
                #print(count)
                resloveAns = resolver(temp[count-2],rootServer,queryType)
                if (resloveAns["success"]==False):
                    exit()
                #DO I NEED TO CALL RESOLVER
                myDig(rootServer, name, iteration, first)
                break
            if x[3] == "A":
                testingCount = 1
                # we found the answer --> Verification was successful
                #NEED TO CHECK KSK
                verificationSuccessful()
                break

    elif (additionalSection_count > 0):
        #print("\nIN ADDITIONAL")
        for lines in additionalSection:
            lines = lines.to_text().split(" ")
            if(first==0):
                #we have yet to validate anything, we need to check with the root
                #NEED TO HAVE A WAY OF CHECKING THIS
                valRoot = validRoot(ipAddress)
                if(valRoot["success"]==False):
                    exit()
            if(first>0):

                #oldName = ""
                newName = ""
                #firstGo = 0


                countForIt = 0
                #I take parts of my name to be used in the resovler
                for blah in partsOfName:
                    if((blah =="www")or(countForIt<(iteration))):
                        #continue
                        print("")
                    else:
                        newName = newName + blah + "."
                    countForIt = countForIt+1

                #I call on my resolver function to see if we can validate this part
                resolveAns =resolver(newName,ipAddress, queryType)
                if (resolveAns["success"] == False):
                    exit()
            first = 1
            iteration = iteration-1
            if (lines[3] == "A"):
                ipAddress = lines[4]
                #print("\nGOT TO A")
                #print(ipAddress)
                myDig(ipAddress, fullName, iteration, first)
                break
    elif ((answerSection_count == 0) and (additionalSection_count == 0)):
        #print("\nIN OTHER")
        # if there is nothing in the answer section or the additional section, I check the authority section

        # print authSection
        for lines in authSection:
            lines = lines.split()
            name = lines[4]
        #print("\nNAME")
        #print(name)
        temp = name.split(".")
        countTemp2 =0
        for parts in temp:
            #print (parts)
            countTemp2 = countTemp2 +1
        #print ("\n\nCOUNT TEMP")
        #print (countTemp2)
        #print("\nPRINTING VALUE")
        #print (temp[countTemp2-2])
        resolveAns = resolver(temp[countTemp2-2], rootServer, queryType)
        if(resolveAns["success"]==False):
            exit()
        myDig(rootServer, name, iteration, first)



def myKSK(ipAdd, oldIP, oldName, newName):
#    print("\nPARENT NAME")
#    print (newName)
#    print("\nNAME")
#    print(oldName)
    algorithm1 = "SHA256"
    #algorithm2 = "SHA1"

    #I format my question
    requestDS = dns.message.make_query(oldName, dns.rdatatype.DS, want_dnssec=True)
    #I get my response
    responseDS = dns.query.tcp(requestDS, oldIP)

    #I format my DNSKEY question
    requestKEY = dns.message.make_query(oldName, dns.rdatatype.DNSKEY, want_dnssec=True)
    #I get my answer
    responseKEY = dns.query.tcp(requestKEY, ipAdd)
    #print(responseKEY)

    answerDS = responseDS.answer
    answerKey = responseKEY.answer
    for lines in answerDS:
        #print("\nGOT HERE")
        #I find the DS Record
        if (lines.rdtype == 43):
            prevDS = lines
            #print("\nIN")
            for more in answerKey:
                #print(more)

                #I check for 257
                temp = more.to_text().split()
                for item in more.items:
                    tempItem = item.to_text().split()
                    if(tempItem[0]=="257"):
                        #print("\nHERE")
                        tempStr = ""
                        #print("\nPRINTING ERG")
                        count = 0
                        for erg in tempItem:
                            count = count +1

                        for iter in range(3,count):
                            tempStr = tempStr + tempItem[iter]
                            #print (tempItem[iter])


                        #nextServ = dns.dnssec.make_ds(newName, tempStr, algorithm1)

                        #I use this for validation, the previous server and the current server should have the same DS values




#oldIP = "192.5.6.30"
#ipAdd =  "192.42.177.30"
#oldName = "com"
#newName = "verisign.com"
#resolver("com.", ipAdd, "A")

#myDig(rootServer, web, lengthWeb, 0)
#myKSK(ipAdd, oldIP, oldName, newName)

try:
    rootServer = rootServerA
    myDig(rootServer, web, lengthWeb, 0)
except IOError:
    print ("ERROR")
    try:
        rootServer = rootServerB
        myDig(rootServerB, web, lengthWeb, 0)
    except IOError:
        print ("ERROR")
        try:
            rootServer = rootServerC
            myDig(rootServer, web, lengthWeb, 0)
        except IOError:
            try:
                rootServer = rootServerD
                myDig(rootServer, web, lengthWeb, 0)
            except IOError:
                try:
                    rootServer = rootServerE
                    myDig(rootServer, web, lengthWeb, 0)
                except IOError:
                    try:
                        rootServer = rootServerF
                        myDig(rootServer, web, lengthWeb, 0)
                    except IOError:
                        try:
                            rootServer = rootServerG
                            myDig(rootServer, web, lengthWeb, 0)
                        except IOError:
                            try:
                                rootServer = rootServerH
                                myDig(rootServer, web, lengthWeb, 0)
                            except IOError:
                                try:
                                    rootServer = rootServerI
                                    myDig(rootServer, web, lengthWeb, 0)
                                except IOError:
                                    try:
                                        rootServer = rootServerJ
                                        myDig(rootServer, web, lengthWeb, 0)
                                    except IOError:
                                        try:
                                            rootServer = rootServerK
                                            myDig(rootServer, web, lengthWeb, 0)
                                        except IOError:
                                            try:
                                                rootServer = rootServerL
                                                myDig(rootServer, web, lengthWeb, 0)
                                            except IOError:
                                                try:
                                                    rootServer = rootServerM
                                                    myDig(rootServer, web, lengthWeb, 0)
                                                except IOError:
                                                    print ("Nothing is working")



