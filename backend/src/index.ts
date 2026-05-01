import express, { Request, Response } from 'express';
import { initMxeKeyPair, getMxePublicKeyB64 } from './store';
import offerRoutes from './routes/offer';
import settleRoutes from './routes/settle';
import resultRoutes from './routes/result';

const app = express();
const PORT = process.env.PORT ?? 3001;

app.use(express.json());

app.use('/api/offer', offerRoutes);
app.use('/api/settle', settleRoutes);
app.use('/api/result', resultRoutes);

app.get('/api/mxe-pubkey', (_req: Request, res: Response) => {
  res.json({ publicKey: getMxePublicKeyB64() });
});

initMxeKeyPair()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize MXE key pair:', err);
    process.exit(1);
  });

export default app;
