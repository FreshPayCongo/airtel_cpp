from flask_restful import Resource, reqparse
from flask import request, jsonify
from datetime import datetime
import random, os
#from app import *
from databases.Data import *
from xml.etree import ElementTree


class Merchant(Resource):
    def get(self):
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
        conn = connectToDatabase(host='195.181.240.102', user='root', password='password', db='switch', port=3309)
        query = "SELECT * FROM transactionMigration WHERE trans_ref_no = '{}' and merchant_id = '{}'".format(transID, merchant)

        details = executeQueryForGetData(conn, query)
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
            
        return jsonify({
            "created_at" : createdAt, 
            "updated_at" : updatedAt, 
            "merchant_id" : merchantID, 
            "currency" : currency, 
            "amount" : amount, 
            "credit" : account_number, 
            "debit_account" : source_account_number, 
            "status" : status,
            "trans_type" : trans_type,
            "trans_ref_no" : trans_ref_no,
            "financial_institution" : financial_institution,             
            })
