-- Versioned synthetic duty-role assignments for DISC-14 annexure role mapping.
ALTER TABLE users ADD COLUMN duty_role TEXT DEFAULT NULL CHECK (
  duty_role IS NULL OR duty_role IN (
    'UNIT_COMMANDER', 'SIGNALS_OFFICER', 'INTELLIGENCE_ANALYST',
    'FIELD_OPERATOR', 'AUDIT_OFFICER', 'SYSTEM_ADMIN'
  )
);
