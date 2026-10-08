import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const present = (value, key) => Object.hasOwn(value, key);
const indexValue = (value) => Number.isSafeInteger(value) && value >= 0;
const identifier = (value) => typeof value === 'string' && value.length > 0;

// SARIF 2.1.0 sections 3.27.7, 3.52 and 3.54: component indexes address
// tool.extensions, whereas rule indexes address that selected component's rules.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
function resolveRule(run, result) {
  if (!object(result) || (present(result, 'rule') && !object(result.rule)))
    throw new Error('Invalid SARIF rule reference');
  const reference = result.rule ?? {};
  const componentReference = reference.toolComponent ?? {};
  if (
    !object(componentReference) ||
    (present(reference, 'toolComponent') && reference.toolComponent === null)
  )
    throw new Error('Invalid SARIF component reference');
  const extensions = run.tool.extensions ?? [];
  let component = run.tool.driver;
  if (present(componentReference, 'index')) {
    if (!indexValue(componentReference.index)) throw new Error('Invalid component index');
    component = extensions[componentReference.index];
  }
  if (present(componentReference, 'guid')) {
    if (!identifier(componentReference.guid)) throw new Error('Invalid component GUID');
    const matches = [run.tool.driver, ...extensions].filter(
      (candidate) => candidate.guid === componentReference.guid,
    );
    if (matches.length !== 1 || (present(componentReference, 'index') && matches[0] !== component))
      throw new Error('Component reference is missing, conflicting or ambiguous');
    component = matches[0];
  }
  if (
    !object(component) ||
    !identifier(component.name) ||
    (component.rules !== undefined && !Array.isArray(component.rules))
  )
    throw new Error('Unresolved SARIF tool component');
  if (present(componentReference, 'name') && componentReference.name !== component.name)
    throw new Error('Conflicting component name');
  for (const [flat, nested] of [
    ['ruleIndex', 'index'],
    ['ruleId', 'id'],
  ]) {
    if (present(result, flat) && present(reference, nested) && result[flat] !== reference[nested])
      throw new Error('Conflicting result and nested rule reference');
  }
  const ruleIndex = present(reference, 'index') ? reference.index : result.ruleIndex;
  const ruleId = present(reference, 'id') ? reference.id : result.ruleId;
  const rules = component.rules ?? [];
  let rule;
  if (ruleIndex !== undefined) {
    if (!indexValue(ruleIndex)) throw new Error('Invalid rule index');
    rule = rules[ruleIndex];
  }
  if (present(reference, 'guid')) {
    if (!identifier(reference.guid)) throw new Error('Invalid rule GUID');
    const matches = rules.filter((candidate) => candidate.guid === reference.guid);
    if (matches.length !== 1 || (ruleIndex !== undefined && matches[0] !== rule))
      throw new Error('Rule GUID reference is missing, conflicting or ambiguous');
    rule = matches[0];
  }
  // Metadata-bearing SARIF references require index or GUID. Never guess a
  // same-named rule in another component or silently use the first duplicate.
  if (!object(rule) || !identifier(rule.id))
    throw new Error('Finding does not resolve to an unambiguous rule');
  if (ruleId !== undefined) {
    const suffix =
      typeof ruleId === 'string' && ruleId.startsWith(rule.id + '/')
        ? ruleId.slice(rule.id.length + 1)
        : null;
    if (!identifier(ruleId) || (ruleId !== rule.id && (!suffix || suffix.includes('/'))))
      throw new Error('Rule identifier does not match selected descriptor');
  }
  return { rule, component };
}

function resultLocations(run, result) {
  if (result.locations !== undefined && !Array.isArray(result.locations))
    throw new Error('Invalid result locations');
  return (result.locations ?? []).map((location) => {
    const physical = location.physicalLocation ?? {};
    const artifact = physical.artifactLocation ?? {};
    let uri = artifact.uri;
    if (artifact.index !== undefined) {
      if (!indexValue(artifact.index) || !run.artifacts?.[artifact.index])
        throw new Error('Unresolved artifact location index');
      const indexedUri = run.artifacts[artifact.index].location?.uri;
      if (uri !== undefined && indexedUri !== undefined && uri !== indexedUri)
        throw new Error('Conflicting artifact locations');
      uri ??= indexedUri;
    }
    if (uri !== undefined && !identifier(uri)) throw new Error('Invalid artifact URI');
    const line = physical.region?.startLine;
    if (line !== undefined && (!Number.isSafeInteger(line) || line < 1))
      throw new Error('Invalid source line');
    return { path: uri ?? null, line: line ?? null };
  });
}

/** Reject high/critical or ungraded error/security findings. Suppressions do not waive this gate. */
export function evaluateSarif(document) {
  if (document?.version !== '2.1.0' || !Array.isArray(document.runs) || !document.runs.length)
    throw new Error('A nonempty SARIF 2.1.0 CodeQL run is required');
  const blocked = [];
  let findings = 0;
  for (const run of document.runs) {
    if (
      run.tool?.driver?.name !== 'CodeQL' ||
      (run.tool.driver.rules !== undefined && !Array.isArray(run.tool.driver.rules)) ||
      (run.tool.extensions !== undefined &&
        (!Array.isArray(run.tool.extensions) ||
          run.tool.extensions.some((component) => !object(component)))) ||
      !Array.isArray(run.results)
    )
      throw new Error('Invalid CodeQL SARIF structure');
    if (
      run.invocations !== undefined &&
      (!Array.isArray(run.invocations) ||
        run.invocations.some(
          (invocation) =>
            !object(invocation) ||
            (invocation.executionSuccessful !== undefined &&
              typeof invocation.executionSuccessful !== 'boolean'),
        ))
    )
      throw new Error('Invalid SARIF invocations');
    if (run.invocations?.some((invocation) => invocation.executionSuccessful === false))
      throw new Error('CodeQL reported an unsuccessful invocation');
    for (const result of run.results) {
      if (['pass', 'notApplicable'].includes(result.kind)) continue;
      const { rule, component } = resolveRule(run, result);
      const locations = resultLocations(run, result);
      const rawScore = rule.properties?.['security-severity'];
      if (
        rawScore !== undefined &&
        ((typeof rawScore !== 'string' && typeof rawScore !== 'number') ||
          (typeof rawScore === 'string' && !/^\d+(?:\.\d+)?$/.test(rawScore)))
      )
        throw new Error('Invalid security severity type');
      const score = rawScore === undefined ? null : Number(rawScore);
      if (score !== null && (!Number.isFinite(score) || score < 0 || score > 10))
        throw new Error('Invalid security severity');
      const level = result.level ?? rule.defaultConfiguration?.level ?? 'warning';
      if (!['none', 'note', 'warning', 'error'].includes(level))
        throw new Error('Invalid result severity level');
      if (
        rule.properties?.tags !== undefined &&
        (!Array.isArray(rule.properties.tags) ||
          rule.properties.tags.some((tag) => typeof tag !== 'string'))
      )
        throw new Error('Invalid rule tags');
      const securityTagged = rule.properties?.tags?.includes('security') === true;
      findings++;
      if (
        (score !== null && score >= 7) ||
        level === 'error' ||
        (securityTagged && score === null)
      ) {
        blocked.push({
          ruleId: rule.id,
          toolComponent: component.name,
          path: locations[0]?.path ?? null,
          line: locations[0]?.line ?? null,
          locations-xëÞ­¢G§²ÚîÆ­yÒÒ’À¢“°¢F†—2ç'Vâ€¢%UDDRö&¦V7G24UB&V6öãÔåTÄÂÇ7FFSÔ44Rt„Tâ7FFSÒtDTÄ•dU$TBrD„Tâ7FFRTÅ4Ru$TÄT4TBrTäBt„U$R–CÓò"À¢–BÀ¢“°¢ÒVÇ6R°¢&V6V—BÒF†—2æWfVçB€¢u$TÄT4Uô•55TTBrÀ¢2çW6W%ö–BÀ¢FV6—6–öäWf–FVæ6R‡°¢&÷s¢"À¢WF†÷&—G“¢F†—2æWö6‚‚’À¢öÆ–7”F–vW7C¢F†—2çöÆ–7”F–vW7B‚’À¢6W76–öã¢2À¢7FFS¢u$TÄT4TBrÀ¢Ò’À¢“°¢F†—2æ†öö·2æ&Vf÷&TWf–FVæ6Sòâ‚“°¢F†—2ç'Vâ€¢t”å4U%B”åDò—77Væ6W2dÅTU2ƒòÃòÃòÃò’rÀ¢–BÀ¢6æöæ–6Â‡&V6V—B’À¢Wö6‚À¢FFRææ÷r‚’À¢“°¢F†—2ç'Vâ€¢uUDDRö&¦V7G24UB7FFSÓòÇ&V6öãÔåTÄÂÇ&W&VEöWö6ƒÓòt„U$R–CÓòrÀ¢u$TÄT4TBrÀ¢Wö6‚À¢–BÀ¢“°¢F†—2æ6÷VçB‚w&VÆV6VBr“°¢Ð¢F†—2æ†öö·2æ&Vf÷&T6öÖÖ—Còâ‚“°¢&WGW&â°¢ö&¦V7C¢F†—2æö&¦V7B‡F†—2ævWB‚u4TÄT5B¢e$ôÒö&¦V7G2t„U$R–CÓòrÂ–B’’À¢VçfVÆ÷S¢'6R‡"æVçfVÆ÷R’À¢6–væGW&S¢"ç6–væGW&RÀ¢6VæFW%6–væ–æuV&Æ–4¶W“¢'6R€¢F†—2ævWB‚u4TÄT5B6–væ–æuö¶W’e$ôÒFWf–6W2t„U$R–CÓòrÂ"ç6VæFW%öFWf–6R’ç6–væ–æuö¶W’À¢’À¢&V6V—BÀ¢Ó°¢Ò“°¢–b†÷WBæFVæ–VB’°¢76W'B‚÷WBæ†–FFVâÂtô$¤T5EôäõEôdõTäBrÂCB“°¢FVÆWFR÷WBæ†–FFVã°¢Ð¢–b‚÷WBæFVæ–VB’F†—2æ†öö·2ægFW$6öÖÖ—Còâ‚“°¢&WGW&â÷WC°¢Ð¢6²‡2Â–BÂ&V6V—D–B’°¢&WGW&âF†—2çG‚‚‚’Óâ°¢2ÒF†—2æ&÷VæB‡2“°¢6öç7B"ÒF†—2æ÷væVB‡2Â–B“°¢76W'B‡F†—2æGWG•f—6–&ÆR‡2Â"’Âtô$¤T5EôäõEôdõTäBrÂCB“°¢76W'B€¢"ç&V6—–VçEö–BÓÓÒ2çW6W%ö–Bbb"ç&V6—–VçEöFWf–6RÓÓÒ2æFWf–6Uö–BÀ¢u$T4•”TåEôôäÅ’rÀ¢C2À¢“°¢6öç7B—77Væ6RÒF†—2ævWB‚u4TÄT5B¢e$ôÒ—77Væ6W2t„U$Rö&¦V7Eö–CÓòrÂ–B“°¢76W'B†—77Væ6Rbb'6R†—77Væ6Rç&V6V—B’ç–ÆöBæWfVçD–BÓÓÒ&V6V—D–BÂu$T4T•Eô”ådÄ”Br“°¢–b‡"ç7FFRÓÓÒtDTÄ•dU$TBr¢&WGW&â²ö&¦V7C¢F†—2æö&¦V7B‡"’Â&V6V—C¢F†—2æf–æE&V6V—B†–BÂtDTÄ•dU%•ô4²r’Ó°¢F†—2ç'Vâ‚uUDDRö&¦V7G24UB7FFSÓòt„U$R–CÓòrÂtDTÄ•dU$TBrÂ–B“°¢6öç7B&V6V—BÒF†—2æWfVçB‚tDTÄ•dU%•ô4²rÂ2çW6W%ö–BÂ°¢ö&¦V7D–C¢–BÀ¢FV6—6–öã¢tDTÄ•dU$TBrÀ¢FWF–Ç3¢²—77Væ6TWfVçD–C¢&V6V—D–BÂÖVæ–æs¢v6Æ–VçBÖ6¶æ÷vÆVFvVBÖæ÷BÖ‡VÖâ×&VBrÒÀ¢Ò“°¢&WGW&â²ö&¦V7C¢F†—2æö&¦V7B‡F†—2ævWB‚u4TÄT5B¢e$ôÒö&¦V7G2t„U$R–CÓòrÂ–B’’Â&V6V—BÓ°¢Ò“°¢Ð¢6†ævR‡2ÂfâÂWfVçEG—RÒtUD„õ$•E•ô4„ätTBr’°¢&WGW&âF†—2çG‚‚‚’Óâ°¢2ÒF†—2æ&÷VæB‡2“°¢F†—2ç&öÆR‡2Â²vFÖ–âuÒ“°¢6öç7B&W7VÇBÒfâ‚“°¢F†—2ç'Vâ€¢uUDDRWF†÷&—G’4UBWö6ƒÖWö6‚³Ç&Wfö6F–öå÷fW'6–öã×&Wfö6F–öå÷fW'6–öâ³t„U$R–CÓrÀ¢“°¢F†—2æWfVçB†WfVçEG—RÂ2çW6W%ö–BÂ°¢FWF–Ç3¢²&Wfö6F–öåfW'6–öã¢F†—2æWö6‚‚’ç&Wfö6F–öå÷fW'6–öâÒÀ¢Ò“°¢F†—2æÆW'B‚tUD„õ$•E•ô4„ätTBrÂ2çW6W%ö–BÂWfVçEG—R“°¢&WGW&â&W7VÇC°¢Ò“°¢Ð¢ÖWG&–72‚’°¢&WGW&â°¢6÷VçFW'3¢ö&¦V7Bæg&öÔVçG&–W2€¢F†—2æÆÂ‚u4TÄT5B¢e$ôÒ6÷VçFW'2r’æÖ‚‡‚’Óâ·‚ææÖRÂ‚çfÇVUÒ’À¢’À¢ö&¦V7G3¢ö&¦V7Bæg&öÔVçG&–W2€¢F†—2æÆÂ‚u4TÄT5B7FFRÆ6÷VçB‚¢’âe$ôÒö&¦V7G2u$õU%’7FFRr’æÖ‚‡‚’Óâ·‚ç7FFRÂ‚æåÒ’À¢’À¢Wö6ƒ¢F†—2æWö6‚‚’æWö6‚À¢WF–ÖU6V6öæG3¢ÖF‚æfÆö÷"‡&ö6W72çWF–ÖR‚’’À¢ÖVÖ÷'”'—FW3¢&ö6W72æÖVÖ÷'•W6vR‚’ç'72À¢Ó°¢Ð¢7–æ2F—7F6‚†ÖWF†öBÂF‚Â"Ò·ÒÂFö¶VâÂ6öçFW‡BÒ²—¢vÆö6ÂrÒ’°¢òòW†7B7FF–2&÷WF–æröæÇ“¢&WVW7BfÇVW2æWfW"&V6öÖR6ÆÆ&ÆR÷"¢òò&÷W'G’æÖRâÆÂ&VÖ–æ–ær&÷WFW2VçFW"F†RÖæFF÷'’6W76–öâvFRà¢7v—F6‚†G¶ÖWF†öGÒG·F‡Ö’°¢66RttUBö†VÇF‚s ¢66RttUBöÆ—fRs ¢66RttUB÷&VG’s ¢&WGW&âV&Æ–4†VÇF‚‡F†—2“°¢66RttUBö’öÖWFs ¢&WGW&âV&Æ–4ÖWFFF‡F†—2“°¢66Ruõ5Bö’öWF‚öÆöv–âs ¢&WGW&âV&Æ–4Æöv–â‡F†—2Â"Â6öçFW‡B“°¢FVfVÇC ¢&WGW&âF†—2â6WF†VçF–6FVDF—7F6‚†ÖWF†öBÂF‚Â"ÂFö¶Vâ“°¢Ð¢Ð¢7–æ26WF†VçF–6FVDF—7F6‚†ÖWF†öBÂF‚Â"ÂFö¶Vâ’°¢òòF†—2—2F†RöæÇ’VçG'’–çFò&÷FV7FVB&÷WFRF—7F6‚âWF†VçF–6F–öâ—0¢òòVæ6öæF—F–öæÂ†W&RæB6ææ÷B&R6¶—VB'’ÖWF†öB÷"F‚7WÆ–VB'’6Æ–VçBà¢ÆWB2ÒF†—2æWF†VçF–6FR‡Fö¶Vâ“°¢F†—2ç&FR‚w6W76–öã¢r²2æ–BÂS“°¢ÆWBfÇVS°¢–b†ÖWF†öBÓÓÒttUBrbbF‚ÓÓÒrö’öWF‚öÖRr¢fÇVRÒ°¢W6W#¢2çW6W"À¢FWf–6S¢F†—2æFWf–6R‡F†—2ævWB‚u4TÄT5B¢e$ôÒFWf–6W2t„U$R–CÓòrÂ2æFWf–6Uö–B’’À¢W‡—&W4C¢2æW‡—&W5öBÀ¢Ó°¢VÇ6R–b†ÖWF†öBÓÓÒuõ5BrbbF‚ÓÓÒrö’öWF‚öÆöv÷WBr’°¢fÇVRÒF†—2çG‚‚‚’Óâ°¢F†—2ç'Vâ‚uUDDR6W76–öç24UB&Wfö¶VCÓt„U$R–CÓòrÂ2æ–B“°¢F†—2æWfVçB‚tÄôtõUBrÂ2çW6W%ö–B“°¢&WGW&â²ö³¢G'VRÓ°¢Ò“°¢ÒVÇ6R–b†ÖWF†öBÓÓÒuõ5BrbbF‚ÓÓÒrö’öWF‚ö6†ÆÆVævRr’fÇVRÒF†—2æ6†ÆÆVævR‡2Â"“°¢VÇ6R–b†ÖWF†öBÓÓÒuõ5BrbbF‚ÓÓÒrö’öFWf–6W2öVç&öÆÂr’°¢76W'B‡7G"†"æÆ&VÂÂƒ’“°¢fÆ–FFT¶W’†"ç6–væ–æuV&Æ–4¶W’“°¢fÆ–FFT¶W’†"æVæ7'—F–öåV&Æ–4¶W’“°¢fÇVRÒF†—2çG‚‚‚’Óâ°¢6öç7B6†ÆÆVævRÒF†—2ævWB€¢u4TÄT5B–ÆöBe$ôÒ6†ÆÆVævW2t„U$R–CÓòrÀ¢"æ6†ÆÆVævT–BóòrrÀ¢“°¢76W'B€¢6†ÆÆVævRb`¢'6R†6†ÆÆVævRç–ÆöB’ç&WVW7D†6‚ÓÓÐ¢†6‚€¢6æöæ–6Â‡°¢Æ&VÃ¢"æÆ&VÂÀ¢6–væ–æuV&Æ–4¶W“¢"ç6–væ–æuV&Æ–4¶W’À¢Væ7'—F–öåV&Æ–4¶W“¢"æVæ7'—F–öåV&Æ–4¶W’À¢Ò’À¢’À¢u$ôôeô$ôE•ôÔ•4ÔD4‚rÀ¢C2À¢“°¢F†—2ç&ööb‡2Â"ÂvVç&öÆÂrÂçVÆÂÂ"ç6–væ–æuV&Æ–4¶W’“°¢76W'B€¢F†—2ævWB€¢u4TÄT5B–Be$ôÒFWf–6W2t„U$R6–væ–æuö¶W“ÓòrÀ¢6æöæ–6Â‡V&Æ–4§v²†"ç6–væ–æuV&Æ–4¶W’’’À¢’À¢tDUd”4Uô´U•ôU„•5E2rÀ¢C’À¢“°¢6öç7B–BÒ&æFöÕUT”B‚“°¢F†—2ç'Vâ€¢t”å4U%B”åDòFWf–6W2dÅTU2ƒòÃòÃòÃòÃòÃòÃò’rÀ¢–BÀ¢2çW6W%ö–BÀ¢"æÆ&VÂÀ¢6æöæ–6Â‡V&Æ–4§v²†"ç6–væ–æuV&Æ–4¶W’’’À¢6æöæ–6Â‡V&Æ–4§v²†"æVæ7'—F–öåV&Æ–4¶W’’’À¢wVæF–ærrÀ¢FFRææ÷r‚’À¢“°¢F†—2æWfVçB‚tDUd”4UôTå$ôÄÄTBrÂ2çW6W%ö–BÂ²FWF–Ç3¢²FWf–6T–C¢–BÒÒ“°¢&WGW&â²FWf–6S¢F†—2æFWf–6R‡F†—2ævWB‚u4TÄT5B¢e$ôÒFWf–6W2t„U$R–CÓòrÂ–B’’Ó°¢Ò“°¢ÒVÇ6R–b†ÖWF†öBÓÓÒuõ5BrbbF‚ÓÓÒrö’öWF‚ö&–æBr’°¢fÇVRÒF†—2çG‚‚‚’Óâ°¢6öç7BBÒF†—2ævWB‚u4TÄT5B¢e$ôÒFWf–6W2t„U$R–CÓòrÂ"æFWf–6T–B“°¢76W'B†BbbBçW6W%ö–BÓÓÒ2çW6W%ö–BbbBç7FGW2ÓÓÒv&÷fVBrÂtDUd”4UõTåE%U5DTBrÂC2“°¢F†—2ç&ööb‡2Â"Âv&–æBrÂçVÆÂÂ'6R†Bç6–væ–æuö¶W’’ÂBæ–B“°¢F†—2ç'Vâ‚uUDDR6W76–öç24UBFWf–6Uö–CÓòt„U$R–CÓòrÂBæ–BÂ2æ–B“°¢F†—2æWfVçB‚tDUd”4Uô$õTäBrÂ2çW6W%ö–BÂ²FWF–Ç3¢²FWf–6T–C¢Bæ–BÒÒ“°¢&WGW&â²FWf–6S¢F†—2æFWf–6R†B’Ó°¢Ò“°¢ÒVÇ6R–b†ÖWF†öBÓÓÒttUBrbbF‚ÓÓÒrö’ö6öçG&öÂr’°¢2ÒF†—2æ&÷VæB‡2“°¢F†—2æ6÷VçB‚v6öçG&öÅ&Vg&W6†W2r“°¢6öç7Bæ÷rÒFFRææ÷r‚“°¢fÇVRÒF†—2çG‚‚‚’Óâ°¢6öç7BÒF†—2æWö6‚‚“°¢&WGW&â6¶WB‡F†—2æ¶W’Â°¢Wö6ƒ¢æWö6‚À¢&Wfö6F–öåfW'6–öã¢ç&Wfö6F–öå÷fW'6–öâÀ¢öÆ–7”F–vW7C¢F†—2çöÆ–7”F–vW7B‚’À¢—77VVDC¢æ÷rÀ¢W‡—&W4C¢æ÷r²cÀ¢Ò“°¢Ò“°¢ÒVÇ6R–b†ÖWF†öBÓÓÒttUBrbbF‚ÓÓÒrö’öF—&V7F÷'’r’°¢2ÒF†—2æ&÷VæB‡2“°¢fÇVRÒF†—2çG‚‚‚’Óâ°¢6öç7BW6W'2ÒF†—2æÆÂ‚u4TÄT5B¢e$ôÒW6W'2t„U$R7F—fSÓr’æÖ‚‡‚’ÓâF†—2çW6W"‡‚’“°¢6öç7BFWf–6W2ÒF†—2æÆÂ€¢%4TÄT5BBâ¢e$ôÒFWf–6W2B¤ô”âW6W'2RôâRæ–CÖBçW6W%ö–Bt„U$RBç7FGW3Òv&÷fVBräBRæ7F—fSÓ"À¢’æÖ‚‡‚’ÓâF†—2æFWf–6R‡‚’“°¢6öç7B–ÆöBÒ²W6W'2ÂFWf–6W2Â—77VVDC¢FFRææ÷r‚’ÂWö6ƒ¢F†—2æWö6‚‚’æWö6‚Ó°¢&WGW&â²W6W'2ÂFWf–6W2Â6¶WC¢6¶WB‡F†—2æ¶W’Â–ÆöB’Ó°¢Ò“°¢ÒVÇ6R–b†ÖWF†öBÓÓÒuõ5BrbbF‚ÓÓÒrö’öw&çG2r’°¢2ÒF†—2æ÷W&F–öâ‡2Â"Âvw&çBr“°¢fÇVRÒF†—2çG‚‚‚’ÓâF†—2æw&çB‡2’“°¢ÒVÇ6R–b†ÖWF†öBÓÓÒuõ5BrbbF‚ÓÓÒrö’öö&¦V7G2r’°¢2ÒF†—2æ÷W&F–öâ‡2Â"Âw7V&Ö—Br“°¢fÇVRÒv—BF†—2ç7V&Ö—B‡2Â"“°¢ÒVÇ6R–b†ÖWF†öBÓÓÒttUBrbbF‚ÓÓÒrö’öö&¦V7G2r’°¢2ÒF†—2æ&÷VæB‡2“°¢fÇVRÒ°¢ö&¦V7G3¢F†—2æÆÂ€¢u4TÄT5B¢e$ôÒö&¦V7G2t„U$R6VæFW%ö–CÓòõ"&V6—–VçEö–CÓòõ$DU"%’7&VFVEöBDU42rÀ¢2çW6W%ö–BÀ¢2çW6W%ö–BÀ¢¢æf–ÇFW"‚‡‚’ÓâF†—2æGWG•f—6–&ÆR‡2Â‚’¢æÖ‚‡‚’ÓâF†—2æö&¦V7B‡‚’’À¢Ó°¢ÒVÇ6R–b†ÖWF†öBÓÓÒuõ5BrbbõåÂö•Âöö&¦V7G5ÂõµâõÒµÂò‡&W&WÆ6Æ–×Æ6²’BòçFW7B‡F‚’’°¢6öç7B²Â–BÂ÷ÒÒF‚æÖF6‚‚õåÂö•Âöö&¦V7G5Âò…µâõÒ²•Âò‡&W&WÆ6Æ–×Æ6²’Bò“°¢76W'B‡WV–B†–B’“°¢2ÒF†—2æ÷W&F–öâ‡2Â"Â÷²s¢r²–B“°¢–b†÷ÓÓÒw&W&Rr’fÇVRÒF†—2ç&W&R‡2Â–B“°¢VÇ6R–b†÷ÓÓÒv6²r’fÇVRÒF†—2æ6²‡2Â–BÂ"ç&V6V—D–B“°¢VÇ6R°¢fÇVRÒF†—2æ6Æ–Ò‡2Â–BÂ"æW‡V7FVDWö6‚“°¢–b‡fÇVRæFVæ–VB¢&WGW&â°¢7FGW3¢C’À¢&öG“¢°¢W'&÷#¢tFÖ—76–öâ†VÆBrÀ¢6öFS¢fÇVRæö&¦V7Bç&V6öâÀ¢ö&¦V7C¢fÇVRæö&¦V7BÀ¢&V6V—C¢fÇVRç&V6V—BÀ¢ÒÀ¢Ó°¢6öç7B6—†W'FW‡BÒv—BF†—2ç&VÆ’ævWD&Æö"‡fÇVRæö&¦V7Bæ6—†W'FW‡D†6‚“°¢76W'B††6‚†6—†W'FW‡B’ÓÓÒfÇVRæö&¦V7Bæ6—†W'FW‡D†6‚Ât4•„U%DU…EôD”tU5BrÂS"“°¢fÇVRæ6—†W'FW‡BÒ6—†W'FW‡BçFõ7G&–ær‚v&6ScGW&Âr“°¢Ð¢ÒVÇ6R–b‡F‚ç7F'G5v—F‚‚rö’öFÖ–âòr’ÇÂF‚ÓÓÒrö’ö–çFVw&F–öâ÷fÆ–FFRr’°¢2ÒF†—2æ&÷VæB‡2“°¢F†—2ç&öÆR€¢2À¢ÖWF†öBÓÓÒttUBrbbF‚ÓÓÒrö’öFÖ–âö÷fW'f–Wrrò²vFÖ–ârÂvVF—F÷"uÒ¢²vFÖ–âuÒÀ¢“°¢–b†ÖWF†öBÓÒttUBr’2ÒF†—2æ÷W&F–öâ‡2Â"ÂvFÖ–ã¢r²ÖWF†öB²s¢r²F‚“°¢fÇVRÒF†—2æFÖ–â†ÖWF†öBÂF‚Â"Â2“°¢ÒVÇ6R–b€¢ÖWF†öBÓÓÒttUBrb`¢²rö’öWf–FVæ6RöW‡÷'BrÂrö’öWf–FVæ6Rö6†V6·ö–çBrÂrö’öÖWG&–72uÒæ–æ6ÇVFW2‡F‚¢’°¢2ÒF†—2æ&÷VæB‡2“°¢F†—2ç&öÆR‡2Â²vFÖ–ârÂvVF—F÷"uÒ“°¢fÇVRÒF†—2çG‚‚‚’Óà¢F‚ÓÓÒrö’öWf–FVæ6RöW‡÷'Bp¢ò°¢&V6÷&G3¢F†—2æÆÂ‚u4TÄT5B&V6÷&Be$ôÒWf–FVæ6Rõ$DU"%’6WVVæ6Rr’æÖ‚‡‚’Óà¢'6R‡‚ç&V6÷&B’À¢’À¢6†V6·ö–çC¢F†—2æ6†V6·ö–çB‚’À¢Ð¢¢F‚ÓÓÒrö’öWf–FVæ6Rö6†V6·ö–çBp¢òF†—2æ6†V6·ö–çB‚¢¢F†—2æÖWG&–72‚’À¢“°¢ÒVÇ6Rf–ÂƒCBÂtäõEôdõTäBr“°¢&WGW&â²7FGW3¢#Â&öG“¢fÇVRÓ°¢Ð¢FÖ–â†ÖWF†öBÂF‚Â"Â2’°¢–b†ÖWF†öBÓÓÒttUBrbbF‚ÓÓÒrö’öFÖ–âö÷fW'f–Wrr¢&WGW&â°¢Væ—G3¢F†—2æÆÂ‚u4TÄT5B¢e$ôÒVæ—G2r’À¢W6W'3¢F†—2æÆÂ‚u4TÄT5B¢e$ôÒW6W'2r’æÖ‚‡‚’ÓâF†—2çW6W"‡‚’’À¢FWf–6W3¢F†—2æÆÂ‚u4TÄT5B¢e$ôÒFWf–6W2r’æÖ‚‡‚’ÓâF†—2æFWf–6R‡‚’’À¢6W76–öç3¢F†—2æÆÂ€¢u4TÄT5B–BÇW6W%ö–BW6W$–BÆFWf–6Uö–BFWf–6T–BÆW‡—&W5öBW‡—&W4BÇ&Wfö¶VBe$ôÒ6W76–öç2rÀ¢’À¢öÆ–6–W3¢F†—2æÆÂ€¢u4TÄT5Bg&öÕ÷Væ—Bg&öÕVæ—BÇFõ÷Væ—BFõVæ—BÆÖ—76–öåö–BÖ—76–öä–BÆÆÆ÷re$ôÒöÆ–6–W2rÀ¢’æÖ‚‡‚’Óâ‡²ââç‚ÂÆÆ÷s¢‚æÆÆ÷rÒ’’À¢ö&¦V7G3¢F†—2æÆÂ‚u4TÄT5B¢e$ôÒö&¦V7G2õ$DU"%’7&VFVEöBDU42Ä”Ô•Br’æÖ‚‡‚’Óà¢F†—2æö&¦V7B‡‚’À¢’À¢Wö6ƒ¢F†—2æWö6‚‚’æWö6‚À¢&Wfö6F–öåfW'6–öã¢F†—2æWö6‚‚’ç&Wfö6F–öå÷fW'6–öâÀ¢ÆW'G3¢F†—2æÆÂ‚u4TÄT5B¢e$ôÒÆW'G2õ$DU"%’F–ÖW7F×DU42Ä”Ô•Br’À¢ÖWG&–73¢F†—2æÖWG&–72‚’À¢Ó°¢–b†ÖWF†öBÓÓÒuõ5BrbbF‚ÓÓÒrö’öFÖ–â÷Væ—G2r’°¢76W'B‡7G"†"ææÖRÂƒ’“°¢&WGW&âF†—2æ6†ævR€¢2À¢‚’Óâ°¢6öç7BVæ—BÒ²–C¢&æFöÕUT”B‚’ÂæÖS¢"ææÖRÓ°¢F†—2ç'Vâ‚t”å4U%B”åDòVæ—G2dÅTU2ƒòÃò’rÂVæ—Bæ–BÂVæ—BææÖR“°¢&WGW&â²Væ—BÓ°¢ÒÀ¢uTä•Eô5$TDTBrÀ¢“°¢Ð¢–b†ÖWF†öBÓÓÒuõ5BrbbF‚ÓÓÒrö’öFÖ–â÷W6W'2r’°¢76W'B€¢õå¶×¤Õ£Ó•òâÕ×³2ÃƒÒBòçFW7B†"çW6W&æÖR’b`¢7G"†"ç77v÷&BÂ#Sb’b`¢"ç77v÷&BæÆVæwF‚ãÒ"b`¢&öÆW2æ–æ6ÇVFW2†"ç&öÆR’b`¢†"æGWG•&öÆRÓÓÒVæFVf–æVBÇÀ¢„EUE•õ$ôÄU2æ–æ6ÇVFW2†"æGWG•&öÆR’bb6ö×F–&ÆTGWG•&öÆR†"ç&öÆRÂ"æGWG•&öÆR’’’b`¢'&’æ—4'&’†"æÖ—76–öä–G2’b`¢"æÖ—76–öä–G2æÆVæwF‚ÃÒ3"b`¢"æÖ—76–öä–G2æWfW'’†Ö—76–öâ’À¢“°¢76W'B‡F†—2ævWB‚u4TÄT5B–Be$ôÒVæ—G2t„U$R–CÓòrÂ"çVæ—D–B’“°¢6öç7B6V7&WBÒ&6S3"‡&æFöÔ'—FW2ƒ#’“°¢&WGW&âF†—2æ6†ævR€¢2À¢‚’Óâ°¢6öç7B–BÒ&æFöÕUT”B‚“°¢F†—2ç'Vâ€¢t”å4U%B”åDòW6W'2†–BÇW6W&æÖRÇ77v÷&BÇF÷GÇVæ—Eö–BÇ&öÆRÆÖ—76–öç2ÆGWG•÷&öÆR’dÅTU2ƒòÃòÃòÃòÃòÃòÃòÃò’rÀ¢–BÀ¢"çW6W&æÖRÀ¢77v÷&D†6‚†"ç77v÷&B’À¢6VÂ‡6V7&WBÂF†—2æÖ7FW$¶W’’À¢"çVæ—D–BÀ¢"ç&öÆRÀ¢6æöæ–6Â†"æÖ—76–öä–G2’À¢"æGWG•&öÆRóòçVÆÂÀ¢“°¢&WGW&â°¢W6W#¢F†—2çW6W"‡F†—2ævWB‚u4TÄT5B¢e$ôÒW6W'2t„U$R–CÓòrÂ–B’’À¢F÷G6V7&WC¢6V7&WBÀ¢÷GWF…W&“ ¢v÷GWFƒ¢ò÷F÷Gõ4”UÕS¢r°¢Væ6öFUU$”6ö×öæVçB†"çW6W&æÖR’°¢s÷6V7&WCÒr°¢6V7&WB°¢rf—77VW#Õ4”UÕRrÀ¢Ó°¢ÒÀ¢uU4U%ô5$TDTBrÀ¢“°¢Ð¢6öç7BW6W$ÖF6‚ÒF‚æÖF6‚‚õåÂö•ÂöFÖ–åÂ÷W6W'5Âò…µâõÒ²’Bò“°¢–b†ÖWF†öBÓÓÒuD4‚rbbW6W$ÖF6‚’°¢6öç7Bf–VÆG2Òö&¦V7Bæ¶W—2†"’æf–ÇFW"‚‡‚’Óâ‚ÓÒw&ööbr“°¢76W'B€¢f–VÆG2æÆVæwF‚âb`¢f–VÆG2æWfW'’‚‡‚’Óâ²v7F—fRrÂw&öÆRrÂvÖ—76–öä–G2rÂvGWG•&öÆRuÒæ–æ6ÇVFW2‡‚’’À¢“°¢–b‚v7F—fRr–â"’76W'B‡G—Vöb"æ7F—fRÓÓÒv&ööÆVâr“°¢–b‚w&öÆRr–â"’76W'B‡&öÆW2æ–æ6ÇVFW2†"ç&öÆR’“°¢–b‚vGWG•&öÆRr–â"’76W'B„EUE•õ$ôÄU2æ–æ6ÇVFW2†"æGWG•&öÆR’Ât”ådÄ”EôEUE•õ$ôÄRr“°¢–b‚vÖ—76–öä–G2r–â"¢76W'B€¢'&’æ—4'&’†"æÖ—76–öä–G2’bb"æÖ—76–öä–G2æÆVæwF‚ÃÒ3"bb"æÖ—76–öä–G2æWfW'’†Ö—76–öâ’À¢“°¢&WGW&âF†—2æ6†ævR€¢2À¢‚’Óâ°¢6öç7BRÒF†—2ævWB‚u4TÄT5B¢e$ôÒW6W'2t„U$R–CÓòrÂW6W$ÖF6…³Ò“°¢76W'B‡RÂtäõEôdõTäBrÂCB“°¢76W'B€¢6ö×F–&ÆTGWG•&öÆR†"ç&öÆRóòRç&öÆRÂ"æGWG•&öÆRóòRæGWG•÷&öÆR’À¢tEUE•õ$ôÄUô”ä4ôÕD”$ÄRrÀ¢“°¢76W'B€¢‡Ræ–BÓÓÒ2çW6W%ö–Bbb†"æ7F—fRÓÓÒfÇ6RÇÂ†"ç&öÆRbb"ç&öÆRÓÒvFÖ–âr’’’À¢u4TÄeôÄô4´õUBrÀ¢“°¢F†—2ç'Vâ€¢uUDDRW6W'24UB7F—fSÓòÇ&öÆSÓòÆÖ—76–öç3ÓòÆGWG•÷&öÆSÓòt„U$R–CÓòrÀ¢v7F—fRr–â"ò¶"æ7F—fR¢Ræ7F—fRÀ¢"ç&öÆRóòRç&öÆRÀ¢"æÖ—76–öä–G2ò6æöæ–6Â†"æÖ—76–öä–G2’¢RæÖ—76–öç2À¢"æGWG•&öÆRóòRæGWG•÷&öÆRÀ¢Ræ–BÀ¢“°¢&WGW&â²W6W#¢F†—2çW6W"‡F†—2ævWB‚u4TÄT5B¢e$ôÒW6W'2t„U$R–CÓòrÂRæ–B’’Ó°¢ÒÀ¢uU4U%ôUD„õ$•E•ô4„ätTBrÀ¢“°¢Ð¢6öç7BFWbÒF‚æÖF6‚‚õåÂö•ÂöFÖ–åÂöFWf–6W5Âò…µâõÒ²•Âò†&÷fWÇ&Wfö¶R’Bò“°¢–b†ÖWF†öBÓÓÒuõ5BrbbFWb¢&WGW&âF†—2æ6†ævR€¢2À¢‚’Óâ°¢6öç7BBÒF†—2ævWB‚u4TÄT5B¢e$ôÒFWf–6W2t„U$R–CÓòrÂFWe³Ò“°¢76W'B†BÂtäõEôdõTäBrÂCB“°¢76W'B€¢†FWe³%ÒÓÓÒv&÷fRrbbBç7FGW2ÓÓÒw&Wfö¶VBr’À¢u$Udô´TEô´U•õ$TTå$ôÄÅõ$UT•$TBrÀ¢C’À¢“°¢76W'B‚†FWe³%ÒÓÓÒw&Wfö¶RrbbBæ–BÓÓÒ2æFWf–6Uö–B’Âu4TÄeôÄô4´õUBr“°¢F†—2ç'Vâ€¢uUDDRFWf–6W24UB7FGW3Óòt„U$R–CÓòrÀ¢FWe³%ÒÓÓÒv&÷fRròv&÷fVBr¢w&Wfö¶VBrÀ¢Bæ–BÀ¢“°¢–b†FWe³%ÒÓÓÒw&Wfö¶Rr¢F†—2ç'Vâ‚uUDDR6W76–öç24UB&Wfö¶VCÓt„U$RFWf–6Uö–CÓòrÂBæ–B“°¢&WGW&â²FWf–6S¢F†—2æFWf–6R‡F†—2ævWB‚u4TÄT5B¢e$ôÒFWf–6W2t„U$R–CÓòrÂBæ–B’’Ó°¢ÒÀ¢tDUd”4Uòr²FWe³%ÒçFõWW$66R‚’À¢“°¢6öç7B6W2ÒF‚æÖF6‚‚õåÂö•ÂöFÖ–åÂ÷6W76–öç5Âò…µâõÒ²•Â÷&Wfö¶RBò“°¢–b†ÖWF†öBÓÓÒuõ5Brbb6W2¢&WGW&âF†—2æ6†ævR€¢2À¢‚’Óâ°¢76W'B‡F†—2ævWB‚u4TÄT5B–Be$ôÒ6W76–öç2t„U$R–CÓòrÂ6W5³Ò’ÂtäõEôdõTäBrÂCB“°¢F†—2ç'Vâ‚uUDDR6W76–öç24UB&Wfö¶VCÓt„U$R–CÓòrÂ6W5³Ò“°¢&WGW&â²ö³¢G'VRÓ°¢ÒÀ¢u4U54”ôåõ$Udô´TBrÀ¢“°¢–b†ÖWF†öBÓÓÒuUBrbbF‚ÓÓÒrö’öFÖ–â÷öÆ–6–W2r’°¢76W'B‡G—Vöb"æÆÆ÷rÓÓÒv&ööÆVârbbÖ—76–öâ†"æÖ—76–öä–B’“°¢76W'B€¢F†—2ævWB‚u4TÄT5B–Be$ôÒVæ—G2t„U$R–CÓòrÂ"æg&öÕVæ—B’b`¢F†—2ævWB‚u4TÄT5B–Be$ôÒVæ—G2t„U$R–CÓòrÂ"çFõVæ—B’À¢“°¢&WGW&âF†—2æ6†ævR€¢2À¢‚’Óâ°¢F†—2ç'Vâ€¢t”å4U%B”åDòöÆ–6–W2dÅTU2ƒòÃòÃòÃò’ôâ4ôädÄ”5B†g&öÕ÷Væ—BÇFõ÷Væ—BÆÖ—76–öåö–B’DòUDDR4UBÆÆ÷sÖW†6ÇVFVBæÆÆ÷rrÀ¢"æg&öÕVæ—BÀ¢"çFõVæ—BÀ¢"æÖ—76–öä–BÀ¢¶"æÆÆ÷rÀ¢“°¢&WGW&â°¢öÆ–7“¢°¢g&öÕVæ—C¢"æg&öÕVæ—BÀ¢FõVæ—C¢"çFõVæ—BÀ¢Ö—76–öä–C¢"æÖ—76–öä–BÀ¢ÆÆ÷s¢"æÆÆ÷rÀ¢ÒÀ¢Ó°¢ÒÀ¢uôÄ”5•ô4„ätTBrÀ¢“°¢Ð¢–b†ÖWF†öBÓÓÒuõ5BrbbF‚ÓÓÒrö’ö–çFVw&F–öâ÷fÆ–FFRr’°¢76W'B€¢"ç66†VÖfW'6–öâÓÓÒb`¢7G"†"æW‡FW&æÄ–BÂƒ’b`¢WV–B†"æö&¦V7D–B’b`¢WV–B†"æFW7F–æF–öåVæ—D–B’b`¢Ö—76–öâ†"æÖ—76–öä–B’À¢“°¢&WGW&âF†—2çG‚‚‚’Óâ‡°¢&V6V—C¢F†—2æWfVçB‚t”åDTu$D”ôåõ44„TÔõdÄ”DDTBrÂ2çW6W%ö–BÂ°¢ö&¦V7D–C¢"æö&¦V7D–BÀ¢FV6—6–öã¢u44„TÔôôäÅ’rÀ¢FWF–Ç3¢°¢W‡FW&æÄ–C¢"æW‡FW&æÄ–BÀ¢FW7F–æF–öåVæ—D–C¢"æFW7F–æF–öåVæ—D–BÀ¢Ö—76–öä–C¢"æÖ—76–öä–BÀ¢6öææV7FVC¢fÇ6RÀ¢ÒÀ¢Ò’À¢6öææV7FVC¢fÇ6RÀ¢Ò’“°¢Ð¢f–ÂƒCBÂtäõEôdõTäBr“°¢Ð§Ð 