import { Router, Request, Response } from 'express';

const router = Router();

router.get('/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  res.json({ id, result: null });
});

export default router;
