export interface ComputeInput {
  input: number;
}

export interface ComputeOutput {
  output: number;
}

export async function compute(params: ComputeInput): Promise<ComputeOutput> {
  return { output: params.input };
}
