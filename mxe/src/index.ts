import { compute } from './compute';

async function main() {
  const result = await compute({ input: 0 });
  console.log('result:', result);
}

main().catch(console.error);
