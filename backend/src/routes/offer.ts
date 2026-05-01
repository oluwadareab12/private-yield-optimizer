import { Router, Request, Response } from 'express';
import { z } from 'zod';

const router = Router();

const OfferSchema = z.object({
  asset: z.string(),
  amount: z.number().positive(),
  rate: z.number().nonnegative(),
  duration: z.number().int().positive(),
});

router.post('/', (req: Request, res: Response) => {
  const parsed = OfferSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ errors: parsed.error.flatten() });
    return;
  }
  res.status(201).json({ offer: parsed.data });
});

export default router;
