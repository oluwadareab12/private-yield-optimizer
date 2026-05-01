import { Router, Request, Response } from 'express';
import { settlementStore } from '../store';
import type { MatchResult } from '../engine/matchingEngine';

const router = Router();

// Returns only the MatchResult entries relevant to the given participant id.
// No other settlement data is revealed.
router.get('/:id', (req: Request, res: Response) => {
  const { id } = req.params;

  const relevant: MatchResult[] = [];
  for (const settlement of settlementStore.values()) {
    for (const match of settlement.matches) {
      if (match.lpId === id || match.protocolId === id) {
        relevant.push(match);
      }
    }
  }

  if (relevant.length === 0) {
    res.status(404).json({ error: 'No results found for participant' });
    return;
  }

  res.json({ participantId: id, matches: relevant });
});

export default router;
