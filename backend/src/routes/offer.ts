import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { lpStore, protocolStore } from '../store';

const router = Router();

const LPOfferSchema = z.object({
  id: z.string().min(1),
  encryptedCapital: z.string().min(1),
  encryptedMinYield: z.string().min(1),
  iv: z.string().min(1),
  clientPublicKey: z.string().min(1),
});

const ProtocolOfferSchema = z.object({
  id: z.string().min(1),
  encryptedDemand: z.string().min(1),
  encryptedMaxRate: z.string().min(1),
  iv: z.string().min(1),
  clientPublicKey: z.string().min(1),
});

router.post('/lp', (req: Request, res: Response) => {
  const parsed = LPOfferSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ errors: parsed.error.flatten() });
    return;
  }
  lpStore.push(parsed.data);
  res.status(201).json({ id: parsed.data.id });
});

router.post('/protocol', (req: Request, res: Response) => {
  const parsed = ProtocolOfferSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ errors: parsed.error.flatten() });
    return;
  }
  protocolStore.push(parsed.data);
  res.status(201).json({ id: parsed.data.id });
});

export default router;
