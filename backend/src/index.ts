import express from 'express';
import offerRoutes from './routes/offer';
import settleRoutes from './routes/settle';
import resultRoutes from './routes/result';

const app = express();
const PORT = process.env.PORT ?? 3001;

app.use(express.json());

app.use('/api/offer', offerRoutes);
app.use('/api/settle', settleRoutes);
app.use('/api/result', resultRoutes);

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

export default app;
