// Native endpoint laboratory envelope. Never instantiate the private-key engine
// in the authority, adapter, gateway or relay. v1/v2 stay on the legacy adapter.
import { randomBytes, createHash } from 'node:crypto';
import { canonical } from '../protocol/canonical.mjs';
import {
  contextFields,
  hasEnvelopeShape,
  validMissionProfile,
  validatePayload,
  sign,
  verify,
  b64,
  unb64,
} from '../crypto/crypto.mjs';
import { validateProviderPublicKey } from '../crypto-provider/engine.mjs';

const utf8 = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const digest = /^[a-f0-9]{64}$/;
const requireValue = (value, message) => {
  if (!value) throw new TypeError(message);
};

export function validateProviderContext(context) {
  requireValue(context?.schemaVersion === 3, 'A native provider requires schema v3');
  const fields = contextFields(3);
  requireValue(
    Object.keys(context).length === fields.length &&
      fields.every((key) => Object.hasOwn(context, key)),
    'Invalid provider context members',
  );
  canonical(context);
  for (const field of [
    'objectId',
    'senderUserId',
    'senderDeviceId',
    'senderUnitId',
    'recipientUserId',
    'recipientDeviceId',
    'recipientUnitId',
  ]) {
    requireValue(
      typeof context[field] === 'string' && uuid.test(context[field]),
      `Invalid ${field}`,
    );
  }
  requireValue(
    digest.test(context.recipientKeyId) &&
      digest.test(context.senderCryptoKeyId) &&
      context.suiteVersion === 1 &&
      context.keyVersion === 1 &&
      Number.isSafeInteger(context.suitePolicyRevision) &&
      context.suitePolicyRevision > 0 &&
      context.classification === 'DEMO' &&
      context.action === 'deliver' &&
      typeof context.missionId === 'string' &&
      /^[A-Za-z0-9._:-]{1,80}$/.test(context.missionId) &&
      validMissionProfile(context.messagePriority, context.messageDomain) &&
      Number.isSafeInteger(context.createdAt) &&
      Number.isSafeInteger(context.expiresAt) &&
      context.createdAt >= 0 &&
      context.expiresAt > context.createdAt &&
      context.expiresAt <= context.createdAt + 3600000,
    'Invalid provider context',
  );
}

function bindPublicKeys(context, senderKey, recipientKey) {
  for (const [key, purpose, keyId] of [
    [senderKey, 'sign', context.senderCryptoKeyId],
    [recipientKey, 'encapsulate', context.recipientKeyId],
  ]) {
    validateProviderPublicKey(key);
    requireValue(
      key.purpose === purpose &&
        key.keyId === keyId &&
        key.providerId === context.providerId &&
        key.suiteId === context.cryptoSuite,
      'Provider key/context binding mismatch',
    );
  }
}

/** Payload encryption, KEM and both signatures happen only at the sender endpoint. */
export async function createProviderObject({
  engine,
  context,
  payload,
  recipientKey,
  senderKey,
  identitySigningKey,
}) {
  validateProviderContext(context);
  validatePayload(payload);
  bindPublicKeys(context, senderKey, recipientKey);
  const selection = { providerId: context.providerId, suiteId: context.cryptoSuite };
  engine.assertAllowed(selection);
  const contentKey = randomBytes(32);
  const plaintext = utf;¾¹îÚ$z{-®éÜj×”S3„dcƒS“dCcD$3“cD#3ƒ4$3$cTCsdƒ3T3#ƒt33Cƒ3dCSD4d3#„S4333“ccdS#C#4C34c$T3ƒs$Cƒ33“ƒt3c#ScƒCDC“„D„$3tTCC$33DcT3„cd3cs„3sC„c4csCDCt#Cdc#“$cs”Cd$cst3CS3ƒ#SDTCD#d$DT“#“s#DcCcsD3C#t3ST##“$4##ƒDTC#“Dc“cSCt#„“SƒD4sƒ“CDcC3“DSC„T$$3„$c#c3C”s“S3CStSDD$”#C$#CT##ƒ3“c“#43#T4c”C3„#CSƒc3Sc4C”S##ƒ“dc#“s”CSd$$dD#“CCC$3##”3S”SC4$TD$334Cc““d33CS#tDcT#”S$C4cS“$#“ƒCs#“33dc$SƒD#TcctCt43DS3cCcd3cC3T#“”CtcSS”3ƒCt#ssƒC44Cƒ4#4#T33s„#tT$D$S#TD$CScsc$S“S#Cd#d#DSƒ$#sc”33ƒD4#3”#3cs3d#dSS“ƒ34#ƒ#S“ƒSScsSD4TT#CCc#3#3sCdT#d$4$cC“ƒct#ƒ#DSc$“ƒ$c„$3ƒ“c$$3CC#3“4##3sDT3ƒ„dTc3CC“3#4S4#T$Tcƒ#“”4ds”#4ddc$#Sd$#33„3sS”3tDcDcsT„3ƒƒt3d#s#C”sst##s“„3$cTDSs#sS$Cƒ3#33sdSc3S33#sC3T4DCT$dCs##ƒ#ƒc$$cc3c“D$#dƒs“ssS„$$3ƒ“SƒS4dDC3DCCDS#”dTs#ƒdD4d$DcCt3”#$c#3CtTSt#33443#sTScƒsD$Cc“sCƒ“D3“”C“cS”3“3C333„Stc„C”#3##ƒƒs4cs34D#”3s3tcCT3C”t$d#434ct3„33$4$S#Cc$$$4SDC#cS„C#ƒ“”Tƒ”T3TSƒ3$3ScSsST$cDƒ”S#STT4#sƒ$T3ƒ3#ƒ#c„cdC”43ƒƒ43“t43#d3CƒcT#S“std„t##CS3C“Sc3c#3„Ddd#c„$C#ƒ#cD4#d$SC“„3ƒS#ƒ$cc44$4ƒt3S3SSC3T4D3#3cT#„d4cc#d#3C“33ƒCcS“D#CDS#3#S#43sCs3“S$#CDd3sSTS#Cs“#c#CCt43tS#3ƒ$##DsCC#„#cC4$3SD#TdcCd$“#”3#cƒƒ“Sd$3cC„D34#„3dCC#4CƒcCd“SS“#3T33ƒƒd#3““SC$ƒssC“Cs“TCD#D#”Td3#S##S“34c”ct3Td4#4#D3#34ccST4#3S#dc„#D#43ƒS#c33„S3dD#C“SCtD#$$C4“sTdSsƒCC3D3DDddSCTc“SSTc33c“d$3D#ƒt$3ccT#tT3“s$C”„d3ƒ“CtD44TcSd#T4SƒS3“cc3$C”cdc„3c„ƒCTS#c„CDSS“CC#CtS$#C3SD4D3s$C4T#S“scc#Dcƒ3Sc33“$#344c4c”c“ƒS„D44DCd3cTSCc3ctDcS#ƒ”3cƒCCCSCcƒdCD3$CS”##DS3CtT“Sƒ3sƒdƒ$T3d3$$#s3c$d#ƒ3cƒddC$3S“S3##tCcdTdS#CT”c#cƒ#D4cSTCTD#C4c„„33”$D3$St3”cƒSc3D3”SSs#TS„C##”#cƒ4SCDƒcD33s$$dDDc$SS#SD3“SSCS#“D4ScCc„#SSc““d3„3„$c“c$#sS„#D4$#43CS”3t3“T#ƒ$$C#3d4#c#“DTc#$c$$#3$D3dT$C3TdT#C”Sd3C“TTc4S“s““ƒD#“$$dc“t$$#4#3DD33ƒSsd3CC##“c3tccƒSC$CC43344DSDC#33#DTC”3tC3CDs4#CdSS3dCSƒ“#3”“d3“ƒS#S“3cscd#$S“CƒssTc#cT3cdCcƒS#s4S”T3ƒ4D3d3#“c4C4#s33CS3ƒcsccC„#„3S3sDTCS3S#CS„Sd##CdcC3DC#c43Ss”cC3SC“#C4Cc#“S#TT$3CcTcƒss”3tS#S3CC”3CƒtCƒDt##cƒ3#“„T33”3#tcƒd#4c#„3cC3ƒƒ“S”““s#ƒSt4dC3c“„cC4“sd4C”Sc“„T3“CdSc”d3Cst4$4#„ScT#”3“dC4TScD#ƒ“D3sCƒ34”$D#SsS„4SCTDDcs“c„CƒtCTcsC”cc#d34““CS3$3s$cs3CTCS“S”s3#cƒD3sS”C„C3“#cc”SsT4#”cƒD4TcD4CcSc4cc#t#”#4dCd$3Cƒ#“#D“ƒ3d#ƒ#Dc”$#ƒsD#$3”44D3S#S“34SS„d3#3s4DCƒ4#ƒ”33”S“ƒ“3“cCtcd43#CdS4Ddd#”dR ¢Ð¥Ð 