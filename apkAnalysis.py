import hashlib
import traceback
from bottle import request, route, static_file, run
from pymongo import MongoClient
from ConfigParser import SafeConfigParser
import os
import platform
import sys
import unirest
import virustotal
import json
from bson import json_util

@route('/uploadApk', method='POST')
def do_upload():

        #Config reading
    if platform.system().lower() == "windows":
        db_config_file = os.path.join(os.path.dirname(sys.executable), 'androbugs-db.cfg')
    else:
        db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')

    if not os.path.isfile(db_config_file):
        print("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file)
        traceback.print_exc()

    configParser = SafeConfigParser()
    configParser.read(db_config_file)

    save_path=configParser.get('General_Config', 'FilePath')

    #category = request.forms.get('category')
    upload = request.files.get('upload')
    name, ext = os.path.splitext(upload.filename)
    if ext not in ('.apk'):
        return "File extension not allowed."

    #save_path = "/tmp/{category}".format(category=category)
    #save_path = "/home/nikhil/Documents/295B/downloads/"
    if not os.path.exists(save_path):
        os.makedirs(save_path)

    file_path = "{path}/{file}".format(path=save_path, file=upload.filename)
    if(os.path.isfile(file_path)):
        os.remove(file_path)
    upload.save(file_path)
    print "File successfully saved to '{0}'.".format(save_path)
    return callAnalyseApk(upload.filename)

@route('/downloadApk', method='POST')
def callDownloadApk():
    '''
    url triming
    url = request._get_body_string().split('=')
    requestBody= url[1]
    :return:
    '''

    #Setting timeout as unirest calls get timed out because analysis takes time
    unirest.timeout(600000)
    requestBody = request._get_body_string()

    #Config reading
    if platform.system().lower() == "windows":
        db_config_file = os.path.join(os.path.dirname(sys.executable), 'androbugs-db.cfg')
    else:
        db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')

    if not os.path.isfile(db_config_file):
        print("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file)
        traceback.print_exc()

    configParser = SafeConfigParser()
    configParser.read(db_config_file)

    downloadPath=configParser.get('General_Config', 'DownloadSciptPath')

    #Calling the download apk method
    cmd = 'python '+downloadPath+'download.py ' + requestBody
    print "cmd is: "+cmd
    os.system(cmd)
    #responseBase = unirest.post("http://localhost:8080/analyseApk", headers={ "Accept": "application/json" },
                                       #body={requestBody})
    return callAnalyseApk(requestBody+".apk")
    #return "Success"

@route('/analyseApk', method='POST')
def callAnalyseApk(requestBody):

    print "Started scanning......."

    if platform.system().lower() == "windows":
        db_config_file = os.path.join(os.path.dirname(sys.executable), 'androbugs-db.cfg')
    else:
        db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')

    if not os.path.isfile(db_config_file):
        print("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file)
        traceback.print_exc()

    configParser = SafeConfigParser()
    configParser.read(db_config_file)

    filePath=configParser.get('General_Config', 'FilePath')
    print "File path is: "+filePath
    MongoDB_Hostname = configParser.get('DB_Config', 'MongoDB_Hostname')
    MongoDB_Database = configParser.get('DB_Config', 'MongoDB_Database')
    Collection_Analyze_Success_Results = configParser.get('DB_Collections', 'Collection_Analyze_Success_Results')

    client = MongoClient(MongoDB_Hostname)
    db = client[MongoDB_Database]
    collection_AppInfo = db[Collection_Analyze_Success_Results]
    print "Trying"+filePath+requestBody
    with open(filePath+requestBody) as f:
        data = f.read()
        file_sha256 = hashlib.sha256(data).hexdigest()
    cursor = collection_AppInfo.find({"file_sha256": file_sha256})

    if cursor.count() == 0:
        cmd = 'python androbugs.py -s -f ' + filePath+ requestBody
        os.system(cmd)
    else:
        print "Record already exist"

    return buildResult(file_sha256,db,filePath+requestBody)
    #return "Success"



def buildResult(apkFingerprint,db,apkPath):
    #permission list from user
    userPreferenceArr = ["android.permission.INTERNET"];

    # API KEY for virus total
    #1adad59c01c25eaf3b3f2435c09c3ae253c9b81f2f156682c1fe81790223c584

    #Mongo db connection
    #client = MongoClient("mongodb://secureVaultAdmin:root@ds013971.mlab.com:13971/secure-vault-db?authMechanism=SCRAM-SHA-1")
    #db = client["secure-vault-db"]
    coll = db["AnalyzeSuccessResults"];

    #APK to be scanned
    #apkFingerprint = '2fd01b373e6ea2e151fdc44be369999c4483e5248cd733f617313f0eba7cbaf2'

    #Get scan results from Virus total public API
    v = virustotal.VirusTotal('1adad59c01c25eaf3b3f2435c09c3ae253c9b81f2f156682c1fe81790223c584');
    #virusTotalReportJSON = v.scan(apkFingerprint)
    #virusTotalReportJSON = v.scan("/home/voldy/Desktop/transit.apk")
    virusTotalReportJSON = v.scan(apkPath)

    scanCompareResults = virusTotalReportJSON._report['scans']

    #update the virus total scan results in database
    updateResult = db.AnalyzeSuccessResults.update_one(
       {"file_sha256": apkFingerprint},
      {"$set": {"scanCompareResults": scanCompareResults}}
    )

    #fetch scan result from mongoDB
    analyzeSuccessResultsCollection = db.AnalyzeSuccessResults.find({'file_sha256': apkFingerprint});

    json_docs = [json.dumps(doc, default=json_util.default) for doc in analyzeSuccessResultsCollection]
    tempJson = json_docs[0]
    jsonObject = json.loads(tempJson)

    #add scanCompare results to main result object
    #jsonObject['scanCompareResults'] = scanCompareResults
    threatQ = calculateThreatQ(jsonObject,userPreferenceArr)
    jsonObject['threatQ'] = threatQ
    return jsonObject

def calculateThreatQ(jsonObject,userPreferenceArr):

    #fetch critical vectors array
    criticalVectorArray  = jsonObject['critical_vectors']
    warningVectorArray = jsonObject['warning_vectors']

    #fetch application permissions array from json
    applicationPermissionArr = jsonObject['permission']

    #give priority to userPreferences, check against application permissions
    intersectionSet = set(applicationPermissionArr).intersection(userPreferenceArr)
    if(intersectionSet.__len__() > 0 ):
        result = "RED"
    else:
        #check for critical and warnings
        if(criticalVectorArray.len >=3 ):
            result = "RED"
        else:
            if(warningVectorArray.len >= 3):
                result = "AMBER"
            else:
                result ="GREEN"

    return result

if __name__ == '__main__':
    run(host='localhost', port=8080)
