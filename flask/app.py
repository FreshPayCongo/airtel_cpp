from flask import Flask
from api import freshPayGW as application
import logging as logger


# Configuration de la gestion des logs et traces
logger.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logger.DEBUG)

if __name__ == "__main__":
    logger.debug("LANCEMENT DE LA GATEWAY")
    application.run(host="0.0.0.0", port=2801, debug=True, use_reloader=True)
