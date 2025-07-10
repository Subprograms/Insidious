import os
import json
import pandas as pd
import boto3
import argparse
import re
from urllib.parse import unquote_plus
from pathlib import Path
from pathlib import Path
from datetime import datetime
from pandasql import sqldf
from urllib.parse import unquote_plus

def loadTxtQueries(sQueryDir):
    aQueries = []
    for pPath in Path(sQueryDir).glob("*.txt"):
        sRaw = pPath.read_text(encoding='utf-8')
        aLines = sRaw.splitlines()
        if ':' in aLines[0]:
            sName, sFirst = aLines[0].split(':',1)
            sSql = sFirst + '\n' + '\n'.join(aLines[1:])
        else:
            sName = pPath.stem
            sSql  = sRaw
        aQueries.append({'name':sName.strip(),'sql':sSql.strip()})
    return aQueries

def loadReportTemplates(sTemplateDir):
    dTemplates = {}
    for pPath in Path(sTemplateDir).glob("*.txt"):
        dTemplates[pPath.stem] = pPath.read_text(encoding='utf-8')
    return dTemplates

def parseS3AccessLog(sFilePath):
    from urllib.parse import unquote_plus
    aOut = []
    for sLine in Path(sFilePath).read_text(encoding='utf-8').splitlines():
        aP = sLine.split()
        if len(aP) < 15:
            continue
        dLog = {
            'bucket_owner': aP[0],
            'bucket':       aP[1],
            'host':         aP[1],
            'timestamp':    aP[2] + ' ' + aP[3],
            'remote_ip':    aP[4],
            'requester':    aP[5],
            'request_id':   aP[6],
            'operation':    aP[7],
            'object_key':   unquote_plus(aP[8]),
            'request_uri':  aP[11] if len(aP) > 11 else '',
            'http_status':  aP[12],
            'error_code':   aP[13],
            'bytes_sent':   aP[14],
            'user_agent':   ' '.join(aP[15:-1]) if len(aP) > 16 else ''
        }
        aOut.append(dLog)
    return aOut

def parseCloudTrail(sFilePath):
    raw = Path(sFilePath).read_text(encoding='utf-8')
    jData = json.loads(raw)
    aRecords = jData.get('Records') if isinstance(jData, dict) and 'Records' in jData else (jData if isinstance(jData, list) else [jData])
    aOut = []
    for rec in aRecords:
        dt = datetime.strptime(rec.get('eventTime',''), '%Y-%m-%dT%H:%M:%SZ')
        sTimestamp            = f"[{dt.strftime('%d/%b/%Y:%H:%M:%S')} +0000]"
        sEventVersion         = rec.get('eventVersion','')
        dUserId               = rec.get('userIdentity') or {}
        sUserType             = dUserId.get('type','')
        sInvokedBy            = dUserId.get('invokedBy','')
        sEventTime            = rec.get('eventTime','')
        sEventSource          = rec.get('eventSource','')
        sEventName            = rec.get('eventName','')
        sAwsRegion            = rec.get('awsRegion','')
        sSourceIP             = rec.get('sourceIPAddress','')
        sUserAgent            = rec.get('userAgent','')
        sErrorCode            = rec.get('errorCode','')
        sErrorMessage         = rec.get('errorMessage','')
        dReq                  = rec.get('requestParameters') or {}
        sBucketName           = dReq.get('bucketName','')
        sHostHeader           = dReq.get('Host','')
        sKey                  = dReq.get('key','') or ''
        sRequestID            = rec.get('requestID','')
        sEventID              = rec.get('eventID','')
        bReadOnly             = rec.get('readOnly',False)
        aResources            = rec.get('resources') or []
        sResources            = json.dumps(aResources)
        sEventType            = rec.get('eventType','')
        bMgmtEvent            = rec.get('managementEvent',False)
        sRecAcctId            = rec.get('recipientAccountId','')
        sSharedEvent          = rec.get('sharedEventID','')
        sVpcEndpoint          = rec.get('vpcEndpointId','')
        sVpcAcct              = rec.get('vpcEndpointAccountId','')
        sCategory             = rec.get('eventCategory','')
        dAdd                  = rec.get('additionalEventData') or {}
        sSigVer               = dAdd.get('SignatureVersion','')
        sCipher               = dAdd.get('CipherSuite','')
        nBytesIn              = dAdd.get('bytesTransferredIn',0)
        nBytesOut             = dAdd.get('bytesTransferredOut',0)
        sAuthMethod           = dAdd.get('AuthenticationMethod','')
        sXAmzId2              = dAdd.get('x-amz-id-2','')
        aOut.append({
            'timestamp':            sTimestamp,
            'event_version':        sEventVersion,
            'user_identity_type':   sUserType,
            'invoked_by':           sInvokedBy,
            'event_time':           sEventTime,
            'event_source':         sEventSource,
            'event_name':           sEventName,
            'aws_region':           sAwsRegion,
            'remote_ip':            sSourceIP,
            'user_agent':           sUserAgent,
            'error_code':           sErrorCode,
            'error_message':        sErrorMessage,
            'bucket':               sBucketName,
            'host_header':          sHostHeader,
            'object_key':           sKey,
            'request_id':           sRequestID,
            'event_id':             sEventID,
            'read_only':            bReadOnly,
            'resources':            sResources,
            'event_type':           sEventType,
            'management_event':     bMgmtEvent,
            'recipient_account_id': sRecAcctId,
            'shared_event_id':      sSharedEvent,
            'vpc_endpoint_id':      sVpcEndpoint,
            'vpc_endpoint_account': sVpcAcct,
            'event_category':       sCategory,
            'signature_version':    sSigVer,
            'cipher_suite':         sCipher,
            'bytes_in':             nBytesIn,
            'bytes_out':            nBytesOut,
            'auth_method':          sAuthMethod,
            'x_amz_id_2':           sXAmzId2,
            'operation':            sEventName
        })
    return aOut

def detectLogTypeFromText(sSample):
    s2 = sSample.lstrip()
    if s2.startswith('{'): return 'cloudtrail'
    if '"' not in s2 and '[' not in s2: return 's3'
    return 'unknown'

def loadLogsFromLocal(sLogDir):
    aAll = []
    for pPath in Path(sLogDir).glob('*'):
        if not pPath.is_file(): continue
        sSample = pPath.read_text(encoding='utf-8')[:200]
        if detectLogTypeFromText(sSample)=='cloudtrail':
            aAll.extend(parseCloudTrail(str(pPath)))
        else:
            aAll.extend(parseS3AccessLog(str(pPath)))
    return aAll

def loadLogsFromS3(sS3Path):
    sBucket,sPrefix = sS3Path.replace('s3://','').split('/',1)
    s3 = boto3.client('s3')
    aAll = []
    for pg in s3.get_paginator('list_objects_v2').paginate(Bucket=sBucket,Prefix=sPrefix):
        for o in pg.get('Contents',[]):
            txt = s3.get_object(Bucket=sBucket,Key=o['Key'])['Body'].read().decode('utf-8')
            if detectLogTypeFromText(txt[:200])=='cloudtrail':
                jData = json.loads(txt)
                if isinstance(jData,dict) and 'Records' in jData: aAll.extend(jData['Records'])
                elif isinstance(jData,list): aAll.extend(jData)
            else:
                for ln in txt.splitlines():
                    aP = ln.split()
                    if len(aP)<15: continue
                    sTs = aP[2]+' '+aP[3]
                    sIp = aP[4]
                    sOp = aP[7]
                    sObj = unquote_plus(aP[8])
                    sUa = ' '.join(aP[15:-1]) if len(aP)>16 else ''
                    aAll.append({'timestamp':sTs,'remote_ip':sIp,'operation':sOp,'bucket':'','object_key':sObj,'user_agent':sUa})
    return aAll

def applyQueriesWithSQL(dfLogs,aQueries):
    aHits = []
    for dQ in aQueries:
        dfH = sqldf(dQ['sql'],{'logs':dfLogs})
        dfH['__query_name']=dQ['name']
        aHits.append(dfH)
    return pd.concat(aHits,ignore_index=True) if aHits else pd.DataFrame()

def generateRawReports(dfRes,sOutPref,bCloudSave):
    sTs = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    if not bCloudSave: Path(sOutPref).mkdir(parents=True,exist_ok=True)
    sCsv  = f"{sOutPref}/report_{sTs}.csv"  if not bCloudSave else f"temp_report_{sTs}.csv"
    sXlsx = f"{sOutPref}/report_{sTs}.xlsx" if not bCloudSave else f"temp_report_{sTs}.xlsx"
    dfRes.to_csv(sCsv,index=False); dfRes.to_excel(sXlsx,index=False)
    print(f"CSV saved to: {sCsv}"); print(f"XLSX saved to: {sXlsx}"); print(f"You got {len(dfRes)} hits!")
    return sCsv,sXlsx

def renderTemplatedReport(sName,dfHits,sTemplate,sOutPref):
    sTs = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    nIps = dfHits['remote_ip'].nunique()
    sBuc = ', '.join(dfHits['bucket'].unique())
    nTot = len(dfHits)
    sOp  = dfHits['operation'].mode().iloc[0] if nTot>0 else ''
    sEv  = ''
    for r in dfHits.itertuples():
        sTime = datetime.strptime(r.timestamp.split()[0],'[%d/%b/%Y:%H:%M:%S').strftime('%d %b %Y %H:%M:%S')
        sObj  = (r.object_key[:27]+'...') if len(r.object_key)>30 else r.object_key
        sUa   = (r.user_agent[:37]+'...')  if len(r.user_agent)>40 else r.user_agent
        sEv  += f"| {sTime} | {r.remote_ip} | {r.operation} | {sObj} | {sUa} |\n"
    sRpt = sTemplate.format(
        detection=sName,description='',mitre='',severity='',
        distinct_external_ips=nIps,buckets_involved=sBuc,
        total_suspicious_requests=nTot,highest_risk_operation=sOp,
        events_table=sEv.rstrip(),generated_date=datetime.utcnow().strftime('%d %b %Y')
    )
    Path(sOutPref).mkdir(parents=True,exist_ok=True)
    sMd = f"{sOutPref}/{sName}_{sTs}.md"
    open(sMd,'w').write(sRpt)
    print(f"Report saved to: {sMd}")
    return sMd

def uploadToS3(sLocal,sBucket,sKey):
    s3=boto3.client('s3'); s3.put_object(Bucket=sBucket,Key=sKey); s3.upload_file(sLocal,sBucket,sKey)
    print(f"Uploaded to s3://{sBucket}/{sKey}")

def analyzeLogs(sInputPath,sQueryDir,sTemplateDir,sOutPref,bInputS3,bOutputS3,sS3Out):
    aQueries   = loadTxtQueries(sQueryDir)
    dTemplates = loadReportTemplates(sTemplateDir)
    aLogs      = loadLogsFromS3(sInputPath) if bInputS3 else loadLogsFromLocal(sInputPath)
    dfLogs     = pd.DataFrame(aLogs)
    dfHits     = applyQueriesWithSQL(dfLogs,aQueries)
    sCsv,sXlsx = generateRawReports(dfHits,sOutPref,bOutputS3)
    aQNames    = {d['name'] for d in aQueries}
    for sName,sTemplate in dTemplates.items():
        if sName not in aQNames: continue
        dfSub = dfHits[dfHits['__query_name']==sName]
        if dfSub.empty: continue
        sMd = renderTemplatedReport(sName,dfSub,sTemplate,sOutPref)
        if bOutputS3:
            sBucket,sPrefix = sS3Out.replace('s3://','').split('/',1)
            uploadToS3(sMd,sBucket,f"{sPrefix}/{os.path.basename(sMd)}")
    if bOutputS3:
        sBucket,sPrefix = sS3Out.replace('s3://','').split('/',1)
        uploadToS3(sCsv,sBucket,f"{sPrefix}/{os.path.basename(sCsv)}")
        uploadToS3(sXlsx,sBucket,f"{sPrefix}/{os.path.basename(sXlsx)}")

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('-i','--input-path',   required=True)
    p.add_argument('-I','--input-type',   choices=['local','s3'],default='local')
    p.add_argument('-q','--query-dir',    required=True)
    p.add_argument('-t','--template-dir', required=True)
    p.add_argument('-o','--output-prefix',default='output')
    p.add_argument('-O','--output-type',  choices=['local','s3'],default='local')
    p.add_argument('-S','--s3-output-path')
    a=p.parse_args()
    analyzeLogs(a.input_path,a.query_dir,a.template_dir,a.output_prefix,
                a.input_type=='s3',a.output_type=='s3',a.s3_output_path)