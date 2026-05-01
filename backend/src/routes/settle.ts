import { Router, Request, Response } from 'express';
import { lpStore, protocolStore, settlementStore, getMxePrivateKey, randomUUID } from '../store';
import { matchOffers } from '../engine/matchingEngine';

const router = Router();

router.post('/', async (_req: Request, res: Response) => {
  try {
    const result = await matchOffers(lpStore, protocolStore, getMxePrivateKey());
    const settlementId = randomUUID();
    settlementStore.set(settlementId, result);
    res.json({ settlementId, ...result });
  } catch (err) {
    res.status(500).json({ error: 'Settlement failed', detail: String(err) });
  }
});

export default router;
