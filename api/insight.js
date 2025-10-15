import { VertexAI } from '@google-cloud/vertexai';
const vertex = new VertexAI({ project: 'belgachia-health-ai', location: 'us-central1' });
const model = vertex.preview.getGenerativeModel({ model: 'text-bison' });

export async function generateInsight(data_period, data_scope) {
  const prompt = `Analyze ${data_scope} billing data for ${data_period} and give 3 actionable insights.`;
  const result = await model.generateContent(prompt);
  return result.response.text;
}

export async function queryAI(query_text) {
  const result = await model.generateContent(`Healthcare Billing Query: ${query_text}`);
  return result.response.text;
}
