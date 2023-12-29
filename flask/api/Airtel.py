from flask_restful import reqparse
from flask import request, jsonify
import requests
import json
from datetime import timedelta, datetime
import random, os, subprocess
from flask import app
from api import freshPayGW
from databases.Data import *
from xml.etree import ElementTree
import pymysql
#import xmltodict
import logging as logger
from flask_jwt_extended import (jwt_required, create_access_token, JWTManager)
from werkzeug.security import generate_password_hash, check_password_hash



# Configuration de la gestion des logs et traces
logger.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logger.DEBUG)
# Configuration de la gateway pour gérer les Keys pour les tokens


BASE_URL="https://openapi.airtel.africa"
HEADERS = {
    'Content-Type': 'application/json'
    }
url = "/auth/oauth2/token"
urlCharge="/merchant/v1/payments/"
urlPayout ="/standard/v1/disbursements/"
urlx="https://openapi.airtel.africa/standard/v1/disbursements/"


# Configuration de la gestion des logs et traces
logger.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logger.DEBUG)
# Configuration de la gateway pour gérer les Keys pour les tokens
freshPayGW.config['JWT_SECRET_KEY'] = 'thisissecretkey'  
# Objet de gestion des tokens
jwt = JWTManager(freshPayGW)
# Méthode affichant un message lors de l'expiration du token

@jwt.expired_token_loader
def my_expired_token_callback(expired_token):
    token_type = expired_token['type']
    logger.error("Le token {} a expiré".format(token_type))
    return jsonify({
            'status': 401,
            'sub_status': 42,
            'message': 'Le {} token a expiré'.format(token_type)
        }), 401


# Méthode permettant la génération du FP (Identifiant unique pour chaque transaction)
def generatedFreshPayID(year, month, day):
    motifs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    fp = 'FP03' + ''.join(
        (random.choice(motifs)) for i in range(5)) + str(month) + ''.join(
            (random.choice(motifs)) for j in range(3)) +'yan'+ str(day) + ''.join(
                (random.choice(motifs))
                for k in range(5)) + str(year) + ''.join(
                    (random.choice(motifs)) for l in range(3))
    logger.info(f"GENERATION DU FP : {fp}")
    return fp

# Méthode permettant de vérifier l'existance et la validité d'un merchant
# Retourne True ou soit false ou soit 0 quand le merchant n'existe pas
def merchantLogin(merchant, key):
    conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    query = "SELECT * FROM merchantsMigration WHERE merchant_code = '{}'".format(merchant)
    details = executeQueryForGetData(conn, query)

    if len(details) > 0:
        try:
            password_hash = check_password_hash(details[0][5], key)
            if password_hash == True:
                logger.info("MERCHANT ID {} ET SECRET KEY VALIDE".format(merchant))
                return True
            else:
                logger.warning("MERCHANT ID {} ET / OU SECRET KEY INVALIDE".format(merchant))
                return False
        except:
            logger.error("ERREUR SURVENUE LORS DU TRAITEMENT LOGIN MERCHANT {}".format(merchant))
            return False    
    else:
        logger.warning("AUCUN MERCHANT {} TROUVER".format(merchant))
        return 0        
# Méthode permettant de vérifier l'existance et la validité d'un merchant
# Retourne le wallet deposit ou payouts en fonction du trans_type ou soit False quannd le secret est invalide
# Soit 0 lors de la génération d'une exception
def merchantLoginWithWallet(merchant, key, trans_type):
    conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    query = "SELECT * FROM merchantsMigration WHERE merchant_code = '{}'".format(merchant)
    details = executeQueryForGetData(conn, query)
    if len(details) > 0:
        try:
            password_hash = check_password_hash(details[0][5], key)
            if password_hash == True:
                if trans_type == "charge":
                    logger.info("MERCHANT ID {} ET / OU SECRET KEY VALIDE RETOUR DU WALLET DEPOSIT {}".format(merchant, details[0][6]))
                    return details[0][6]
                elif trans_type == "payout":
                    logger.info("MERCHANT ID {} ET / OU SECRET KEY VALIDE RETOUR DU WALLET PAYOUT {}".format(merchant, details[0][7]))
                    return details[0][7]     
            else:
                logger.warning("MERCHANT ID {} ET / OU SECRET KEY INVALIDE".format(merchant))
                return False
        except:
            logger.error("ERREUR SURVENUE LORS DU TRAITEMENT LOGIN MERCHANT {}".format(merchant))
            return False    
    else:
        logger.warning("AUCUN MERCHANT TROUVER")
        return 0        


def GetToken():
    payload = json.dumps({
    "client_id": "9918cbf7-38fe-4111-9518-ae179c7731e7",
    "client_secret": "43579758-72d4-498e-96dd-2f76bc4319f0",
    "grant_type": "client_credentials"
    })
    
    response = requests.request("POST",BASE_URL+url, headers=HEADERS, data=payload)
    repo=response.json()
    return repo["access_token"]

# Méthode permettant de faire un deposit
# Retourne les informations conernant la transaction effectuée

@freshPayGW.route("/api/v1/charge", methods=['POST'])

def verify():
    parser = reqparse.RequestParser()
    parser.add_argument("action",help='Verify')
    parser.add_argument("merchant_code", help='Merchant code')
    parser.add_argument("key", help='Key',)
    data = parser.parse_args()

    action = data['action']
    merchant_code = data['merchant_code']
    key = data['key']
    logger.info("RECUPERATION DES INFORMATIONS POUR LA CREATION DU DEPOSIT POUR LE MARCHANT {}".format(merchant_code))
    if action == 'status':
        logger.info("LANCEMENT DU VERIFY")
        return verifyToMe()
    elif action == 'charge':  
        logger.info("je suis ici 3")   
        logger.info("LANCEMENT DU DEPOSIT")
        logger.info("je suis ici")
        return makeDeposit()
    else:
        logger.error("{} ACTION INCONNUE".format(action))
        return jsonify({
            "Message" : "cette action est inconnue !!"
        })
    
    
#Methode pour envoyer au payDRC
#def sendToPayDRC(data, endpoint):
    #logger.info("REQUEST SEND TO PAYDRC")
   # logger.info(data)
    #headers = {"Content-Type" : "application/json"}
    #response = requests.post(url=endpoint, headers=headers, data=json.dumps(data))
    #return response.json()
# Méthode permettant d'effectuer le verify en fonction du FP ou d'une référence autre venant du merchant

def verifyToMe():
    logger.info("RECUPERATION DES INFORMATIONS POUR LA CREATION DU DEPOSIT")
    parser = reqparse.RequestParser()
    parser.add_argument("action", type=str, help='Verify')
    parser.add_argument("transaction_id", type=str, help='FP generer')
    parser.add_argument("merchant_code", type=str, help='Merchant code')
    parser.add_argument("key", type=str, help='Key')
    data = parser.parse_args()
    action = data['action']
    transID = data['transaction_id']
    merchant = data['merchant_code']
    key = data['key']
    conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    query = "SELECT * FROM transactionMigration WHERE (trans_ref_no = '{}' or merchant_ref = '{}') and merchant_id = '{}'".format(transID, transID, merchant)
    details = executeQueryForGetData(conn, query)
    if len(details) == 0:
        return jsonify(
            {
                "created_at" : "null", 
                "updated_at" : "null", 
                "merchant_id" : "null", 
                "currency" : "null", 
                "amount" : "null", 
                "credit" : "null", 
                "debit_account" : "null", 
                "status" : "Success",
                "trans_type" : "null",
                "trans_ref_no" : transID,
                "financial_institution" : "null",
                "action" : "status",
                "transaction_status":"Pending"
            }
        )
            
    createdAt = str(details[0][1])
    updatedAt = str(details[0][2])
    merchantID = details[0][3]
    currency = details[0][4]
    amount = details[0][5]
    account_number = details[0][6]
    source_account_number = details[0][7]
    status = details[0][8]
    trans_type = details[0][9]
    trans_ref_no = details[0][10]
    financial_institution = details[0][11]
    financial_institution_transaction_id = details[0][12]
    financial_institution_status_code = details[0][13]
    financial_institution_status_description = details[0][14]
    
    return jsonify(
        {
            "action" : "status",
            "status": "Success",
            "created_at" : createdAt, 
            "updated_at" : updatedAt, 
            "merchant_id" : merchantID, 
            "currency" : currency, 
            "amount" : amount, 
            "credit" : account_number, 
            "debit_account" : source_account_number, 
            "transaction_status" : status,
            "trans_type" : trans_type,
            "trans_id" : trans_ref_no,
            "financial_institution" : financial_institution
        }
    )    

# Méthode permettant d'effectuer un deposit vers un compte
def makeDeposit():
    parser = reqparse.RequestParser()
    parser.add_argument("action", type=str, help='Soit charge, Deposit, C2B soit payout, B2C')
    parser.add_argument("debit_channel", type=str, help='Vodacom')
    parser.add_argument("debit_account", type=str, help='Numero')
    parser.add_argument("credit_account", type=str, help='Numero')
    parser.add_argument("amount", type=int, help='Montant')
    parser.add_argument("currency", type=str, help='CDF')
    parser.add_argument("merchant_code", type=str, help='FB002')
    parser.add_argument("key", type=str, help='oXc7119OO9]AIl5.mZZ\'#(c}j6rP,]i')
    parser.add_argument("merchant_ref", type=str, help='La référence pour une transaction')
    parser.add_argument("callback_url", type=str, help='La référence pour une transaction')
    data = parser.parse_args()
    action = data['action']
    debitChannel = data['debit_channel']
    currency = data['currency']
    amount = data['amount']
    merchantCode = data['merchant_code']
    debitAccount = data['debit_account']
    creditAccount = data['credit_account']
    createdAt = str(datetime.now())
    status = "Submitted"
    merchant_ref = data['merchant_ref']
    key = data['key']
    callback_url = data['callback_url']
    year = str(datetime.now().year)[2:4]
    month = str(datetime.now().month)
    if len(month) == 1:
        month = str("0") + month
        
    day = str(datetime.now().day)
    if len(day) == 1:
        day = str("0") + day
    if currency != "CDF" and currency != "USD":
        logger.error("{} Devise incorrecte".format(currency))
        return jsonify({
            "Message" : "Devise incorrecte"
        })
    token = 's'
    #Wallert du merchant à incorporer
    #merchant_wallet = merchantLoginWithWallet(merchantCode, key, action)
    transId = generatedFreshPayID(year=year, month=month, day=day)

    logger.info("INFORMATIONS RECUPERER | {} {} {} {} {} {} {} {} {} {}".format(transId, merchantCode, merchant_ref, action, creditAccount, debitAccount, debitChannel, amount, currency, status))
    
    conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    query = "INSERT INTO transactionMigration(created_at, updated_at, merchant_id, currency, amount, account_number, source_account_number, status, trans_type, trans_ref_no, financial_institution, financial_institution_transaction_id, financial_institution_status_code, financial_institution_status_description, merchant_ref, callback) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    dataToInsert = (createdAt, createdAt, merchantCode, currency, amount, creditAccount, debitAccount, status, action, transId, debitChannel, "", "", "", merchant_ref, callback_url)
    instertToSwitch = executeQueryForInsertDate(conn, query, dataToInsert)
    if instertToSwitch == 1:
        #try:
        logger.info("Avant excution curl c2bReauest")
        pax = json.dumps({
        "reference": "Testing transaction",
        "subscriber": {
            "country": "CD",
            "currency": currency,
            "msisdn": debitAccount
        },
        "transaction": {
            "amount": amount,
            "country": "CD",
            "currency": currency,
            "id": transId
        }
        })
        token=GetToken()
        headers = {
        'Content-Type': 'application/json',
        'Accept': '/',
        'X-Country': 'CD',
        'X-Currency': currency,
        'Authorization': 'Bearer '+token
        
        }

        response = requests.request("POST",BASE_URL+urlCharge, headers=headers, data=pax)
        print(response)
        conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
        updatedAt = str(datetime.now())
        FinancialInstitutionStatusCode = '200'
        FinancialInstitutionStatusDesc = 'Your request is received and under process'
        status = 'Pending'
        query = "UPDATE transactionMigration SET updated_at = %s, status = %s, financial_institution_status_code = %s, financial_institution_status_description = %s WHERE trans_ref_no = %s"
        dataToInsert = (updatedAt, status, FinancialInstitutionStatusCode, FinancialInstitutionStatusDesc, transId)
        updatedToSwitch = executeQueryForInsertDate(conn, query, dataToInsert)
        if updatedToSwitch == 1:
            logger.info("REQUETE C2B ENVOYEE AVEC SUCCESS A AIRTEL {} {}".format(transId, merchant_ref))
        else:
           logger.error("IMPOSSIBLE D'ENVOYER LA REQUETE C2B A AIRTEL {} {}".format(transId, merchant_ref))
    else:
        logger.warning("IMPOSSIBLE D'ENVOYER LA TRANSACTION A AIRTEL, ELLE DOIT EXISTER AU SWITCH {} {}".format(transId, merchant_ref))
    return jsonify(
        action = action,
        comment = "Transaction not submitted for processing",
        amount = amount,
        status = status,
        transaction_status = "Transaction not updated",
        trans_id = transId,
        currency = currency,
        debit_account = debitAccount,
        destination_account = creditAccount,
        created_at = createdAt,
        debit_channel = debitChannel,
        destination_channel = debitChannel,
        financial_institution_transaction_id = "" 
    )


    
@freshPayGW.route('/api/v1/login', methods=['POST'])
def login():
    parser = reqparse.RequestParser()
    parser.add_argument("merchant_code", type=str, help='Merchant code')
    parser.add_argument("key", type=str, help='Key')
    data = parser.parse_args()
    merchant_code = data['merchant_code']
    key = data['key']
    conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    query = "SELECT * FROM merchantsMigration WHERE merchant_code = '{}'".format(merchant_code)
    details = executeQueryForGetData(conn, query)
    
    merchant_code_db = str(details[0][3])
    key_db = str(details[0][5])
    if merchant_code != merchant_code_db  or generate_password_hash(key) != key_db:
        return jsonify({"Message": "Le nom du marchant ou la key est incorrect"}), 401
    
    expires = timedelta(days=90)
    ret = {
        'merchant_code' : '',
        'key' : '',
        'token': create_access_token(merchant_code, expires_delta=expires)
        }
    return jsonify(ret), 200

@freshPayGW.route('/api/v1/create-prod-token', methods=['POST'])
#@jwt_required()
def create_dev_token():
    merchant_code = get_jwt_identity()
    expires = datetime.timedelta(days=90)
    token = create_access_token(merchant_code, expires_delta=expires)
    logger.info(merchant_code)
    return jsonify({'token': token}), 201

@freshPayGW.route('/api/v1/merchants', methods=['POST'])
def createMerchant():
    logger.info("CREATION DU MERCHANT")
    parser = reqparse.RequestParser()
    parser.add_argument("merchant_code", type=str, help='Merchant code')
    parser.add_argument("key", type=str, help='Key')
    parser.add_argument("merchant_payouts", type=str, help='Wallet de paiement')
    parser.add_argument("merchant_deposits", type=str, help='Wallet de deposit')
    data = parser.parse_args()
    merchant_code = data['merchant_code']
    key = data['key']
    if data['merchant_deposits'] == "":
        walletDeposit = "8273000"
    else:
        walletDeposit = data['merchant_deposits']
    if data['merchant_payouts'] == "":
        walletPayout = "15120"
    else:
        walletPayout = data['merchant_payouts']
    
    conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    query = "SELECT * FROM merchants WHERE merchant_code = '{}'".format(merchant_code)
    details = executeQueryForGetData(conn, query)
    ta = len(details)
    if ta > 0:
        logger.warning("{} merchant code existe déjà dans le système".format(merchant_code))
        return jsonify({"Message" : "Le merchant code existe déjà dans le système"}), 401
    
    createdAt = str(datetime.now())
    keyToInsert = generate_password_hash(key)
    conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    query = "INSERT INTO merchants(created_at, updated_at, merchant_code, merchant_key, merchant_payouts, merchant_deposits) VALUES(%s, %s, %s, %s, %s, %s)"
    dataToInsert = (createdAt, createdAt, merchant_code, keyToInsert, walletPayout, walletDeposit)
    instertToSwitch = executeQueryForInsertDate(conn, query, dataToInsert)
    if instertToSwitch == 1:
        logger.info("{} creation du marchant effectuee avec success".format(merchant_code))
        return jsonify(
        action="creation de marchant",
        status="Success",
        merchant_code=merchant_code,
        merchant_deposit_wallet=walletDeposit,
        merchant_payout_wallet=walletPayout,
        key=keyToInsert
    ), 200
    logger.error("{} Erreur survenue lors de la creation de ce merchant".format(merchant_code))
    return jsonify({
        "Message" : "Erreur survenue"
    })


# Méthode permettant de faire un payouts
# Retourne les infos liées à la transaction effectuées
@freshPayGW.route("/api/v1/airtel_fresh_payouts", methods=['POST'])
def payout():
    logger.info("RECUPERATION DES INFORMATIONS POUR LA CREATION DU PAYOUT")
    parser = reqparse.RequestParser()
    parser.add_argument("action", type=str, help='Verify')
    parser.add_argument("merchant_code", type=str, help='Merchant code')
    parser.add_argument("key", type=str, help='Key')
    parser.add_argument("debit_channel", type=str, help='Vodacom')
    parser.add_argument("debit_account", type=str, help='Numero')
    parser.add_argument("credit_account", type=str, help='Numero')
    parser.add_argument("amount", type=int, help='Montant')
    parser.add_argument("currency", type=str, help='CDF')
    parser.add_argument("merchant_ref", type=str, help='Reference du mrrchant')
    parser.add_argument("callback_url", type=str)
    
    data = parser.parse_args()
    action = data['action']
    merchant_code = data['merchant_code']
    key = data['key']
    merchant_ref = data['merchant_ref']
   
    if action != 'payout':
        logger.error("{} ACTION INCONNUE".format(action))
        return jsonify({
            "Message" : "cette action est inconnue"
        })
    if merchant_code != "FB004" and merchant_code != "FP001":
        connect_schemas = pymysql.connect(host="138.68.158.250", database="INFORMATON_SCHEMAS", user="root2", password="Kokilomu1996.", port=3306)
        query = "INSERT INTO check_requests(requests) values (%s)"
        dataToInsert = ("host : {}, host_url : {}, json : {}, headers:  {}, path : {}, query_string: {}, remote_user :{}, trusted_hosts : {}, url : {}".format(request.host, request.host_url, request.get_json(), request.headers, request.path, request.query_string, request.remote_user, request.trusted_hosts,request.url))
        with connect_schemas.cursor() as targetcursor:
            targetcursor.execute(query, dataToInsert)
        connect_schemas.commit()
        return jsonify({"Message": "Vous n'êtes pas autorisé à effectuer des payouts"})
        
    debitChannel = data['debit_channel']
    currency = data['currency']
    amount = data['amount']
    merchantCode = data['merchant_code']
    debitAccount = data['debit_account']
    creditAccount = data['credit_account']
    createdAt = str(datetime.now())
    status = "Submitted"
    callback_url = data['callback_url']
    year = str(datetime.now().year)[2:4]
    month = str(datetime.now().month)
    if len(month) == 1:
        month = str("0") + month
        
    day = str(datetime.now().day)
    if len(day) == 1:
        day = str("0") + day
    if currency != "CDF" and currency != "USD":
        return jsonify({
            "Message" : "Devise incorrecte"
        })
    if verifyMerchantReference() == True:
        return jsonify({
            "Message" : "Le merchant_ref doit être unique"
        }) 
    transId = generatedFreshPayID(year=year, month=month, day=day)
    token = ''
    
    logger.info("INFORMATIONS RECUPERER | {} {} {} {} {} {} {} {} {} {}".format(transId, merchantCode, merchant_ref, action, creditAccount, debitAccount, debitChannel, amount, currency, status))
    conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    query = "INSERT INTO transactionMigration(created_at, updated_at, merchant_id, currency, amount, account_number, source_account_number, status, trans_type, trans_ref_no, financial_institution, financial_institution_transaction_id, financial_institution_status_code, financial_institution_status_description, merchant_ref, callback) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    dataToInsert = (createdAt, createdAt, merchantCode, currency, amount, creditAccount, debitAccount, status, action, transId, debitChannel, "", "", "", merchant_ref, callback_url)
    instertToSwitch = executeQueryForInsertDate(conn, query, dataToInsert)
    if instertToSwitch == 1:
        try:
            
            pa = json.dumps({
            "payee": {
                "msisdn": debitAccount
            },
            "reference": "ABCD07026984141",
            "pin":"lorHt7JcrHNJUR1nh1RMHGMW/DtYTnMDma37eA9Xya9OF5y2vpz2gVU+wE1/iir9jjAb0+V+ya/KvLzL1UfUtWnz8Oam5Ypeo8MZ0pWAK/mmkvM7LZ9gD/+d7ERPViHyQh1JOn3mwNGqnWOyNRuqhei0EGSXIKaqznq1W+ccm7Y=",
            "transaction": {
                "amount": amount,
                "id": transId
            }
            })
            token=GetToken()
            hea = {
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'X-Country': 'CD',
            'X-Currency': currency,
            'Authorization': 'Bearer '+token
            
            }

            repo = requests.request("POST",urlx, headers=hea, data=pa)
            financial_institution_transaction_id =repo.json()
            conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
            updatedAt = str(datetime.now())
            
            FinancialInstitutionStatusCode =financial_institution_transaction_id['status']['code']
            FinancialInstitutionReponseCode =financial_institution_transaction_id['status']['response_code']
            FinancialInstitutionStatusDesc =financial_institution_transaction_id['status']['message']
            FinancialInstitutionID =financial_institution_transaction_id['data']['transaction']['reference_id']

            if FinancialInstitutionReponseCode == 'DP00900001001':
                status = 'Successful'
            elif FinancialInstitutionReponseCode == 'DP00900001000':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001003':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001004':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001005':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001006':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001007':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001009':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001010':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001011':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001012':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001013':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001014':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001015':
                status = 'Failed'
            elif FinancialInstitutionReponseCode == 'DP00900001016':
                status = 'Failed'
            else:
                status = 'Submitted'

            query = "UPDATE transactionMigration SET updated_at = %s, status = %s, financial_institution_transaction_id = %s, financial_institution_status_code = %s, financial_institution_status_description = %s WHERE trans_ref_no = %s"
            dataToInsert = (updatedAt, status, FinancialInstitutionID, FinancialInstitutionStatusCode, FinancialInstitutionStatusDesc, transId)
            updatedToSwitch = executeQueryForInsertDate(conn, query, dataToInsert)
            conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
            query = "SELECT * FROM transactionMigration WHERE trans_ref_no = '{}'".format(transId)
            details = executeQueryForGetData(conn, query)
            url = details[0][17]
            paydrc =details[0][15]
            
            if url != None:
                dataToSend = {
                    "action":"credit",
                    "switch_reference" : transId,
                    "telco_reference" : FinancialInstitutionID,
                    "status" : status,
                    "paydrc_reference" : paydrc,
                    "telco_status_description" : FinancialInstitutionStatusDesc
                }
                
                #logger.info(sendToPayDRC(dataToSend, url))
            logger.info("B2C ENVOYE A AIRTEL AVEC SUCCESS POUR {} {}".format(transId, merchant_ref))
            return jsonify(
                action = action,
                comment = "Transaction submitted for processing",
                amount = amount,
                status = status,
                transaction_status = "Transaction updated",
                trans_id = transId,
                currency = currency,
                debit_account = debitAccount,
                destination_account = creditAccount,
                created_at = createdAt,
                debit_channel = debitChannel,
                destination_channel = debitChannel,
                financial_institution_transaction_id = FinancialInstitutionID,
                merchant_ref = merchant_ref  
            ), 200
        except:
            logger.error("IMPOSSIBLE DE LANCER LE B2C A AIRTEL POUR {} {}".format(transId, merchant_ref))
    logger.warning("IMPOSSIBLE D'ENVOYER LA REQUETE A AIRTEL, LA TRANSACTION {} {} DOIT ETRE CREER AU SWICHT".format(transId, merchant_ref))    
    return jsonify(
        action = action,
        comment = "Transaction not submitted for processing",
        amount = amount,
        status = status,
        transaction_status = "Transaction not updated",
        trans_id = transId,
        currency = currency,
        debit_account = debitAccount,
        destination_account = creditAccount,
        created_at = createdAt,
        debit_channel = debitChannel,
        destination_channel = debitChannel,
        financial_institution_transaction_id =repo.json(),
        merchant_ref = merchant_ref  
    ), 400


def verifyMerchantReference():
    logger.info("VERIFICATION DE L'UNICITE DU MERCHANT_REF")
    parser = reqparse.RequestParser()
    parser.add_argument("merchant_ref", type=str, help='Merchant reference')
    data = parser.parse_args() 
    merchant_ref = data['merchant_ref']
    conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    query = "SELECT * FROM transactionMigration WHERE created_at BETWEEN CONCAT(DATE_FORMAT(CURRENT_DATE, '%Y-%m-%d'), ' 00:00:00') and CONCAT(DATE_FORMAT(CURRENT_DATE, '%Y-%m-%d'), ' 23:59:59')  and merchant_ref = '{}'".format(merchant_ref)
    details = executeQueryForGetData(conn, query)
    if len(details) == 0:
        return False
    
    return True

@freshPayGW.route("/api/v1/verify", methods=['POST'])
def verifyToTelco():
    logger.info("RECUPERATION DES INFORMATIONS POUR LE VERIFY CHEZ AIRTEL")
    parser = reqparse.RequestParser()
    parser.add_argument("transid", type=str, help='identifiant de la transaction')
    parser.add_argument("currency", type=str, help='identifiant de la transaction')
    data = parser.parse_args()
    transid = data['transid']
    currency = data['currency']
    token=GetToken()
    headers = {
        'Accept': '*/*',
        'X-Country': 'CD',
        'X-Currency': currency,
        'Authorization': 'Bearer '+token
        
        }
 
    try:

        urlxx = "https://openapi.airtel.africa/standard/v1/payments/{}".format(transid)
        r = requests.get(urlxx, headers = headers)
        logger.info(r.json())
        financial_institution_transaction_id =r.json()

        FinancialInstitutionStatusCode =financial_institution_transaction_id['status']['code']
        FinancialInstitutionReponseCode =financial_institution_transaction_id['status']['response_code']
        statusDesc =financial_institution_transaction_id['status']['message']
        FinancialInstitutionID =financial_institution_transaction_id['data']['transaction']['airtel_money_id']
        status=financial_institution_transaction_id['data']['transaction']['status']

        
        if FinancialInstitutionID != "null":
            if status == 'TS':
                status = 'Successful'
            elif status == 'TF':
                status = 'Failed'
        elif FinancialInstitutionID == "null" and status == "TF":
            status = 'Pending'
        return jsonify({
            "trans_ref_no": transid,
            "status": status,
            "financial_institution_id": FinancialInstitutionID,
            "financial_status_description": statusDesc
        }), 200
    except :
        return jsonify({
            "trans_ref_no": statusDesc,
            
        }), 200

@freshPayGW.route("/api/v1/verifyPayout", methods=['POST'])
def verifyToTelcoPayout():
    logger.info("RECUPERATION DES INFORMATIONS POUR LE VERIFY CHEZ AIRTEL")
    parser = reqparse.RequestParser()
    parser.add_argument("transid", type=str, help='identifiant de la transaction')
    parser.add_argument("currency", type=str, help='identifiant de la transaction')
    data = parser.parse_args()
    transid = data['transid']
    currency = data['currency']
    token=GetToken()
    headers = {
        'Accept': '*/*',
        'X-Country': 'CD',
        'X-Currency': currency,
        'Authorization': 'Bearer '+token
        
        }
 
    try:

        r=requests.get('https://openapiuat.airtel.africa/standard/v2/disbursements/{}'.format(transid), params={'transactionType': 'B2B'}, headers = headers)
        logger.info(r.json())
        financial_institution_transaction_id =r.json()

        FinancialInstitutionStatusCode =financial_institution_transaction_id['status']['code']
        FinancialInstitutionReponseCode =financial_institution_transaction_id['status']['response_code']
        statusDesc =financial_institution_transaction_id['status']['message']
        FinancialInstitutionID =financial_institution_transaction_id['data']['transaction']['airtel_money_id']
        status=financial_institution_transaction_id['data']['transaction']['status']

        if FinancialInstitutionReponseCode == 'DP00900001001':
                status = 'Successful'
        elif FinancialInstitutionReponseCode == 'DP00900001000':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001003':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001004':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001005':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001006':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001007':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001009':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001010':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001011':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001012':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001013':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001014':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001015':
                status = 'Failed'
        elif FinancialInstitutionReponseCode == 'DP00900001016':
                status = 'Failed'
        else:
                status = 'Submitted'
        return jsonify({
            "trans_ref_no": transid,
            "status": status,
            "financial_institution_id": FinancialInstitutionID,
            "financial_status_description": statusDesc
        }), 200
    except :
        return jsonify({
            "trans_ref_no": statusDesc,
            
        }), 200


@freshPayGW.route("/callback", methods=['POST'])
def chargeCallback():
    logger.info("chargment du callback")
    content_dict =request.data
    logger.info(content_dict)
    FinancialInstitutionStatusCode =(content_dict['transaction']["status_code"])
    FinancialInstitutionStatusDesc = (content_dict['transaction']["message"])
    TransID = (content_dict['transaction']["id"])
    FinancialInstitutionID =(content_dict['transaction']["airtel_money_id"])
    updatedAt = str(datetime.now())
    status="pending"

    if FinancialInstitutionStatusCode != "null":
                if FinancialInstitutionStatusCode == 'TS':
                    status = 'Successful'
                elif FinancialInstitutionStatusCode == 'TF':
                    status = 'Failed'

    logger.info("INCOMMING DATA FROM ORANGE CHARGE CALLBACK FOR {} {} {} {} {}".format(TransID, FinancialInstitutionStatusCode,FinancialInstitutionID, FinancialInstitutionID, status))

    conn = connectToDatabase(host='138.68.158.250', user='jbiola',
                             password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    if type(conn) == tuple:
        return jsonify({
            "resultCode": 1,
            "resultCodeDescription": "Not Processed, database connexion failed !",
            "resultCodeError": 2,
            "resultData": {}
        }), 500
    query = "UPDATE transactions SET updated_at = %s, status = %s, financial_institution_transaction_id = %s, financial_institution_status_code = %s, financial_institution_status_description = %s WHERE trans_ref_no = %s"
    reft = str.find(FinancialInstitutionID,"MP")
    dataToInsert = (updatedAt, status,FinancialInstitutionID,FinancialInstitutionStatusCode,FinancialInstitutionStatusDesc, TransID)
    instertToSwitch = executeQueryForInsertDate(conn, query, dataToInsert)
    if instertToSwitch == 1:
        conn = connectToDatabase(host='138.68.158.250', user='jbiola',
                                 password='gofreshbakeryproduction2020jb', db='switch', port=3306)

        query = "SELECT * FROM transactions WHERE trans_ref_no = '{}'".format(TransID)
        details = executeQueryForGetData(conn, query)
        url = details[0][17]
        paydrc = details[0][15]
        if url != None:
            dataToSend = {
                "action": "debit",
                "switch_reference": TransID,
                "telco_reference": FinancialInstitutionID,
                "status": status,
                "paydrc_reference": paydrc,
                "telco_status_description": FinancialInstitutionStatusDesc,
                "status_code":FinancialInstitutionStatusCode   
            }
            logger.info(sendToPayDRC(dataToSend,url))

        return "CALLBACK SUCCESSFUL"
    else:
        logger.info("INCOMMING FROM ORANGE CHARGE CALLBACK BUT NOT UPDATED FOR {} {} {} {} {}".format(TransID, FinancialInstitutionStatusCode,FinancialInstitutionID,FinancialInstitutionID[reft::], status))
    
        return "CALLBACK FAILED"
    
    logger.info("chargment du callback")
    content_dict = xmltodict.parse(request.data)
    logger.info(content_dict)
    FinancialInstitutionStatusCode = content_dict["soapenv:Envelope"]["soapenv:Body"]["ser:doCallback"]["ResultCode"]
    logger.info(FinancialInstitutionStatusCode)
    TransID =content_dict["soapenv:Envelope"]["soapenv:Body"]["ser:doCallback"]["transid"]
    logger.info(TransID)
    FinancialInstitutionID=content_dict["soapenv:Envelope"]["soapenv:Body"]["ser:doCallback"]["ResultDesc"]
    logger.info(FinancialInstitutionID)
    logger.info("CALLBACK--------------------------------------------------")
    logger.info(request.data)
    if FinancialInstitutionStatusCode == '200':
        status = 'Successful'
    else:
        status = 'Failed'

    return "ok"
    updatedAt = str(datetime.now())
    conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    query = "SELECT * FROM transactionOrange WHERE (trans_ref_no= '{}')".format(TransID)
    details = executeQueryForGetData(conn, query)
 
    if len(details)>0:
        conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
        query = "UPDATE transactionOrange SET updated_at = %s, status = %s, financial_institution_transaction_id = %s, financial_institution_status_code = %s, financial_institution_status_description = %s WHERE trans_ref_no = %s"
        reft = str.find(FinancialInstitutionID,"MP")
        dataToInsert = (updatedAt,status,FinancialInstitutionID[reft::],FinancialInstitutionStatusCode,FinancialInstitutionID,TransID)
        instertToSwitch = executeQueryForInsertDate(conn, query, dataToInsert)

    return "OK"
    FinancialInstitutionStatusDesc = content_dict["soapenv:Envelope"]["soapenv:Body"]["gen:getGenericResult"]["Request"]["dataItem"][2]['value']
    TransID = content_dict["soapenv:Envelope"]["soapenv:Body"]["gen:getGenericResult"]["Request"]["dataItem"][5]['value']
    FinancialInstitutionID = content_dict["soapenv:Envelope"]["soapenv:Body"]["gen:getGenericResult"]["Request"]["dataItem"][9]['value']
    updatedAt = str(datetime.now())
    
    if FinancialInstitutionStatusCode == '200':
        status = 'Successful'
    else:
        status = 'Failed'

    conn = connectToDatabase(host='138.68.158.250', user='jbiola', password='gofreshbakeryproduction2020jb', db='switch', port=3306)
    query = "UPDATE transactions SET updated_at = %s, status = %s, financial_institution_transaction_id = %s, financial_institution_status_code = %s, financial_institution_status_description = %s WHERE trans_ref_no = %s"
    dataToInsert = (updatedAt, status, FinancialInstitutionID, FinancialInstitutionStatusCode, FinancialInstitutionStatusDesc, TransID)
    instertToSwitch = executeQueryForInsertDate(conn, query, dataToInsert)
   
    if instertToSwitch == 1:
        logger.info("INCOMMING FROM VODACOM CALLBACK FOR {} {} {} {} {}".format(TransID, FinancialInstitutionStatusCode, FinancialInstitutionStatusDesc, FinancialInstitutionID, status))
        return "CALLBACK SUCCESSFUL"
    else:
        logger.info("INCOMMING FROM VODACOM CALLBACK BUT NOT UPDATED FOR {} {} {} {} {}".format(TransID, FinancialInstitutionStatusCode, FinancialInstitutionStatusDesc, FinancialInstitutionID, status))
        return "CALLBACK FAILED"

           
    







    





