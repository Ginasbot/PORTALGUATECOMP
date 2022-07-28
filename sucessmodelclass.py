'''
title: Adjudicaciòn success
author: Christian Julca
date modified: 28/07/2022
version: 1.0
path virtual env: /home/cjulcas/project/hd_expediente_consolida/laboralenv/bin/python3.exe
'''

#01. Import libraries

# Básicos
from operator import contains
import pandas as pd
import numpy as np
import re
import string
import pickle
import joblib
from datetime import datetime
from unidecode import unidecode
from pathlib import Path
import warnings

# Formato
from num2words import num2words

# Scikit-learn
from sklearn import metrics
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import chi2

# NLTK
import nltk
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords

# Spacy
import spacy
from spacy_spanish_lemmatizer import SpacyCustomLemmatizer
import es_core_news_sm
#import es_core_news_lg

# Scikit-learn
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import GridSearchCV
from sklearn.calibration import CalibratedClassifierCV
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import accuracy_score
from sklearn import preprocessing
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import cohen_kappa_score, make_scorer, log_loss
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix



#limpieza de  texto
def formato_texto(texto):
    
    texto = texto.upper()
    texto = texto.translate(str.maketrans("ÁÉÍÓÚ", "AEIOU"))
    texto = texto.translate(str.maketrans("ÀÈÌÒÙ", "AEIOU"))
    texto = texto.translate(str.maketrans("ÂÊÎÔÛ", "AEIOU"))
    texto = ' '.join(texto.split())
    
    return texto

def remover_numeros_puntuacion(texto):
    
    texto = texto.translate(str.maketrans('','',string.digits))
    texto = texto.translate(str.maketrans('','',string.punctuation + '¡¿°º-–•“”‘’´ª¨'))
    texto = ' '.join(texto.split())
    
    return texto

def remover_stopwords(texto):
    
    # Retirar stopwords
    texto = ' '.join([i for i in texto.split() if i not in stopwords_esp])

    return texto


def limpieza_texto(texto):

    # Limpieza de tildes
    texto_limp = formato_texto(texto)
    
    # Remoción de números y puntuación
    texto_limp = remover_numeros_puntuacion(texto_limp)
    
    # Remoción de stopwords
    texto_limp = remover_stopwords(texto_limp)
    
    return texto_limp



def process(text):
    stopwords_spanish = pd.read_csv('/home/cjulcas/project/hd_desafiogt/sucessmodel/recursos/stopwords_spanish.csv')
    stopwords_spanish = stopwords_spanish['WORD'].tolist()

    stopwords_esp = [formato_texto(i) for i in stopwords_spanish]

    preposiciones = ['A', 'ANTE', 'BAJO', 'CABE', 'CON', 'CONTRA', 'DE', 'DESDE', 'DURANTE', 'EN', 'ENTRE', 'HACIA', 
                    'HASTA', 'MEDIANTE', 'PARA', 'POR', 'SEGUN', 'SIN', 'SOBRE', 'TRAS', 'VERSUS', 'VIA', 'RESPECTO']

    stopwords_esp = list(set(preposiciones + stopwords_esp))

    data = {'TEXTO': [text]}
    df_train_test = pd.DataFrame(data)

    df_train_test['TEXTO_LIMP'] = df_train_test['TEXTO'].astype(str).apply(lambda x: limpieza_texto(x))

    #%% TD IDF
    # Carga de vocabulario
    tf_idf = joblib.load('/home/cjulcas/project/hd_desafiogt/sucessmodel/version/tf_idf_unigram.pkl')

    df_train_test['FEATURES'] = list(tf_idf.transform(df_train_test['TEXTO_LIMP']).toarray())

    #################################
    #%% LOGISTIC REGRESSION

    log_model  = joblib.load('/home/cjulcas/project/hd_desafiogt/sucessmodel/version/log_model.pkl')
    x_pred = pd.DataFrame(df_train_test['FEATURES'].to_list())
    y_pred = log_model.predict(x_pred)
    y_prob = log_model.predict_proba(x_pred)[::,1]

    return y_prob

####
text = "Ancho: 18 Pulgadas(s); Largo: 18 Pulgadas(s); Material: 100% algodón;"
w = process(text)
w