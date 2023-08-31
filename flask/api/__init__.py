from flask_restful import Api
from flask import Flask
import logging as logger


logger.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logger.DEBUG)

logger.info("Importation de l'objet de gestion des marchants")
# Importation de l'objet de gestion des marchants
from .Merchant import *




# Instanciation de l'objet flask à exposer
freshPayGW = Flask(__name__)

logger.info("Importation de l'objet de gestion de vodacom")
# Importation de l'objet de gestion de vodacom
from .Airtel import *
