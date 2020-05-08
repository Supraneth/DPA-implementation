from pylab import *
import numpy as np
import scipy
import matplotlib.pyplot as plt
import binascii


#Fonction de chargement des traces
def traceload(fname, traceSize, numberOfTraces):
    myfile = open(fname, "r")
    traces = np.zeros((numberOfTraces, traceSize))
    for i in range (0,numberOfTraces):
        traces[i, :] = np.fromfile(myfile, np.uint8, traceSize)
    myfile.close()
    return traces
	
#Fonction de chargement d'un fichier	
def myin(fname, columns, rows):
    myfile = open(fname, "r")
    s= np.loadtxt(fname, np.uint8, delimiter=" ")
    myfile.close()
    return s
	
#Fonction qui retourne le bit d'un octet
def bit_get(byteval,idx):
    return ((byteval&(1<<idx))!=0)
    offset = 40000
    segmentLength = 75000
    traces = O_traces[:,offset:offset+segmentLength]
    plt.figure(2)
    plt.plot(traces[0, :])
    plt.title("Consommation total d'un chiffrement")
    show()

def createHypothesisTab(numberOfTraces, keyCandidateStart, keyCandidateStop, SBOX):
    columns = 16
    rows = numberOfTraces
    plaintext = myin('plaintext.txt', columns, rows)
    hypothesis = zeros ((numberOfTraces,keyCandidateStop+1),uint8)
    b = 0 
    k = 0 
    p = 0 

    for p in range(0, numberOfTraces):
        for k in range(keyCandidateStart, keyCandidateStop+1):
            hypothesis [p,k]= plaintext[p,b]^k #key whitening
            hypothesis [p,k]= SBOX[hypothesis [p,k]]
    return hypothesis

def DPAgroups(segmentLength, numberOfTraces, traces, hypothesis, keyCandidateStart, keyCandidateStop):
    mean_0 = zeros((256,segmentLength))
    mean_1 = zeros((256,segmentLength))
    p = 0
    k = 0
    mean_0[k,:]=mean_0[k,:]+ traces [p,:]

    p = 0 
    k = 0
    nb0 = 0
    nb1 = 0
    curves = []
    probKeys = []
    for k in range (keyCandidateStart, keyCandidateStop+1):
        mean_0 = zeros((256,segmentLength))
        mean_1 = zeros((256,segmentLength))
        nb0 = 0
        nb1 = 0
        for p in range (0, 200):      
            if (bit_get(hypothesis[p,k],1)==0):
                mean_0[k,:]=mean_0[k,:] + traces [p,:]
                nb0 += 1
            else:
                mean_1[k,:]=mean_1[k,:] + traces [p,:]
                nb1 += 1

        mean_0[k,:]=mean_0[k,:]/nb0
        mean_1[k,:]=mean_1[k,:]/nb1
        diff = abs(mean_1[k,:] - mean_0[k,:])
        curves.append(diff)
        max = np.amax(diff)
        probKeys.append(max)
        if k == 0:
            plt.figure(3)
            plt.plot(diff)
            plt.title("Courbe DPA (k = 0)")
            show()

    
    x = np.linspace(0,255,256)
    plt.figure(4)
    plt.plot(x, probKeys)
    plt.title("Courbes des maximums")
    show()
    return curves

if __name__ == "__main__":
    #Variable globales
    SBOX=[99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
      202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 
      183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 
      4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 
      9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 
      83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 
      208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 
      81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 
      205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 
      96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 
      224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 
      231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 
      186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 
      112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 
      225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 
      140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22];
    traceSize = 370000
    offset = 0
    segmentLength = 370000 #for the beginning the segmentLength = traceSize
    numberOfTraces = 200
    keyCandidateStart = 0
    keyCandidateStop = 255

    O_traces = traceload("traces-00112233445566778899aabbccddeeff.bin", traceSize, numberOfTraces)
    plt.figure(1)
    plt.plot(O_traces[0, :])
    plt.title("Consommation total d'un chiffrement")
    offset = 40000
    segmentLength = 75000
    traces = O_traces[:,offset:offset+segmentLength]
    plt.figure(2)
    plt.plot(traces[0, :])
    plt.title("Consommation total d'un chiffrement")
    show()
    
    hypothesisTab = createHypothesisTab(numberOfTraces, keyCandidateStart, keyCandidateStop, SBOX)
    print ("Tableau d'hypothèse final : ", hypothesisTab)
    DPA = DPAgroups(segmentLength, numberOfTraces, traces, hypothesisTab, keyCandidateStart, keyCandidateStop)




    
