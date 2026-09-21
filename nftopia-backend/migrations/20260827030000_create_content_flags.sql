CREATE TABLE IF NOT EXISTS content_flags (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_type VARCHAR(20) NOT NULL,
  entity_id UUID NOT NULL,
  reason TEXT NOT NULL,
  severity VARCHAR(20) NOT NULL,
  confidence REAL NOT NULL,
  raised_by VARCHAR(50) NOT NULL DEFAULT 'ai-agent',
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_at TIMESTAMPTZ,
  reviewed_by UUID
);

CREATE INDEX IF NOT EXISTS idx_content_flags_status_created ON content_flags (status, created_at);
CREATE INDEX IF NOT EXISTS idx_content_flags_entity ON content_flags (entity_type, entity_id);
