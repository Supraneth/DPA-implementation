#Importation des librairies principales du projet
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

#Fonction permettant la création d'une matrice d'hypothèse pour un index d'octet donné sur le plaintext (ici, b = 0)
def createHypothesisTab(numberOfTraces, keyCandidateStart, keyCandidateStop, SBOX):
    #Les colonnes permettent de déterminer de combien d'octets sont composés chaque ligne du plaintext analysé 
    columns = 16
    rows = numberOfTraces
    plaintext = myin('plaintext.txt', columns, rows)
    #On initialise notre matrice d'hypothèses de 200 x 256 valeurs)
    hypothesis = zeros ((numberOfTraces,keyCandidateStop+1),uint8)
    b = 0 
    k = 0 
    p = 0 

    #Pour chaque premier octet de chaque ligne du texte, on vient tester l'ensemble des sous-clés k possibles. Pour chacune des possibilités
    #le premier round d'AES est donc effectué
    for p in range(0, numberOfTraces):
        for k in range(keyCandidateStart, keyCandidateStop+1):
            hypothesis [p,k]= plaintext[p,b]^k #key whitening
            hypothesis [p,k]= SBOX[hypothesis [p,k]]
    return hypothesis

#Fonction permettant, à partir des hypothèses générées, de mettre en corrélation celles-ci et les traces pour trouver la bonne sous-clé.
#Pour cela, on passe à travers un ensemble de courbes différentielles permettant de relever les corrélations. Une fois ces dernières
#obtenues, on recherche la corrélation maximale (le pic le plus important) pour chacunes des sous-clés pour tous les premiers octets ciblés dans le
#plaintext.
#Une fois l'ensemble des sous-clés testées, on recherche la sous-clé avec la corrélation maximale sur tous les premiers octets. Celle-ci a donc de forte chance
#d'être la clé que nous cherchons.
def DPAgroups(segmentLength, numberOfTraces, traces, hypothesis, keyCandidateStart, keyCandidateStop):
    #On initialise les groupes et les compteurs permettant de répertorier les traces et de les compter.
    mean_0 = zeros((256,segmentLength))
    mean_1 = zeros((256,segmentLength))
    nb0 = 0
    nb1 = 0
    #On initiale les variables pour commencer
    p = 0
    k = 0
    p = 0 
    k = 0
    #On initialise le tableau qui va contenir l'ensemble des maxs de chaque courbe différentielle pour relever la corrélation la plus forte sur chacune d'entres
    #elles.
    probKeys = []
    #Ensuite, on teste toutes les sous-clés possibles sur tous les premiers octets de chaque ligne du plaintext.
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
        #Une fois les groupes constitués, on calcule la moyenne finale pour chaque groupe
        mean_0[k,:]=mean_0[k,:]/nb0
        mean_1[k,:]=mean_1[k,:]/nb1
        #Puis on récupère la courbe différentielle des deux moyennes combinées
        diff = abs(mean_1[k,:] - mean_0[k,:])
        #On récupère la valeur max de la courbe (le plus haut pic)
        max = np.amax(diff)
        #On l'ajoute dans le tableau contenant l'ensemble des sous-clés probables (valeur max de chaque courbe différentielle, pour chaque valeur de sous-clé)
        probKeys.append(max)
        if k == 0:
            plt.figure(3)
            plt.plot(diff)
            plt.title("Courbe DPA (k = 0)")
            show()

    #On trace le graphique mettant en évidence la sous-clé la plus probable (celle avec la plus haute corrélation détectée)
    x = np.linspace(0,255,256)
    plt.figure(4)
    plt.plot(x, probKeys)
    plt.title("Courbes des maximums")
    show()
    return probKeys

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
    plt.title("Consommation d'un chiffrement")

    #On focus sur le premier round d'AES détecté sur la courbe de consommation totale
    offset = 40000
    segmentLength = 75000
    traces = O_traces[:,offset:offset+segmentLength]
    plt.figure(2)
    plt.plot(traces[0, :])
    #On affiche le résultat focus
    plt.title("Consommation d'un chiffrement (ciblé sur le premier round AES)")
    show()
    
    #On applique nos fonctions de recherche de la sous-clé
    hypothesisTab = createHypothesisTab(numberOfTraces, keyCandidateStart, keyCandidateStop, SBOX)
    """print ("Tableau d'hypothèse final : ", hypothesisTab)"""
    DPA = DPAgroups(segmentLength, numberOfTraces, traces, hypothesisTab, keyCandidateStart, keyCandidateStop)




    
