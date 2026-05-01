export interface Offer {
  id: string;
  asset: string;
  amount: number;
  rate: number;
  duration: number;
}

export interface MatchResult {
  lender: Offer;
  borrower: Offer;
  matchedAmount: number;
  agreedRate: number;
}

export function matchOffers(lenders: Offer[], borrowers: Offer[]): MatchResult[] {
  const results: MatchResult[] = [];

  const sortedLenders = [...lenders].sort((a, b) => a.rate - b.rate);
  const sortedBorrowers = [...borrowers].sort((a, b) => b.rate - a.rate);

  for (const borrower of sortedBorrowers) {
    for (const lender of sortedLenders) {
      if (
        lender.asset === borrower.asset &&
        lender.rate <= borrower.rate &&
        lender.duration <= borrower.duration
      ) {
        results.push({
          lender,
          borrower,
          matchedAmount: Math.min(lender.amount, borrower.amount),
          agreedRate: (lender.rate + borrower.rate) / 2,
        });
      }
    }
  }

  return results;
}
