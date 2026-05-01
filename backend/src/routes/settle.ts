import { Router, Request, Response } from 'express';
import { z } from 'zod';

const router = Router();

const SettleSchema = z.object({
  offerId: z.string().uuid(),
  txHash: z.string(),
});

router.post('/', (req: Request, res: Response) => {
  const parsed = SettleSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ errors: parsed.error.flatten() });
    return;
  }
  res.json({ settled: parsed.data });
});

export default router;
