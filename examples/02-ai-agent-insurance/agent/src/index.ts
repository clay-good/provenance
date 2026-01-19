/**
 * AI Agent Runtime
 *
 * Simulated AI agent that processes user questions about insurance claims.
 * The agent uses "tools" (functions) to access the claims service, and
 * each tool call must use PIC to propagate authority.
 *
 * This demonstrates:
 * 1. Agent receives PCA from gateway
 * 2. Agent requests successor PCA for each tool call
 * 3. Trust Plane enforces monotonicity - agent cannot exceed user's authority
 * 4. Claims service validates PCA for final enforcement
 *
 * For this demo, the agent is simulated (no actual LLM) to demonstrate
 * the security properties without requiring API keys.
 */

import express from 'express';
import {
  TrustPlaneClient,
  TrustPlaneApiError,
  PocBuilder,
  generateKeyPair,
  type KeyPair,
} from '@provenance/sdk';

// =============================================================================
// Configuration
// =============================================================================

const PORT = process.env.AGENT_PORT ?? 3001;
const TRUST_PLANE_URL = process.env.TRUST_PLANE_URL ?? 'http://localhost:8080';
const CLAIMS_SERVICE_URL = process.env.CLAIMS_SERVICE_URL ?? 'http://localhost:3002';

// =============================================================================
// Agent State
// =============================================================================

let agentKeyPair: KeyPair;
const trustPlane = new TrustPlaneClient(TRUST_PLANE_URL);

// =============================================================================
// Simulated AI Agent Logic
// =============================================================================

interface AgentContext {
  currentPca: string;
  userId: string;
}

/**
 * Simulated "tool" to get a specific claim
 *
 * In a real LangChain/agent setup, this would be decorated as a tool.
 * The agent would call this when it needs claim information.
 */
async function toolGetClaim(
  claimId: string,
  context: AgentContext
): Promise<{ success: boolean; data?: unknown; error?: string }> {
  console.log(`[Agent] Tool: get_claim("${claimId}")`);

  // Build PoC requesting authority for this specific claim
  const requestedOps = [`read:claims:${claimId}`];
  console.log(`[Agent] Requesting ops: ${requestedOps.join(', ')}`);

  try {
    // Create and sign PoC
    const signedPoc = await new PocBuilder(context.currentPca)
      .withOps(requestedOps)
      .withExecutor({
        service: 'ai-agent',
        tool: 'get_claim',
        claim_id: claimId,
      })
      .sign(agentKeyPair);

    // Request successor PCA from Trust Plane
    const successorResponse = await trustPlane.processPoc(signedPoc);
    console.log(`[Agent] Got successor PCA: hop=${successorResponse.hop}, ops=${successorResponse.ops.join(', ')}`);

    // Call claims service with successor PCA
    const claimsResponse = await fetch(`${CLAIMS_SERVICE_URL}/claims/${claimId}`, {
      headers: {
        'X-PIC-PCA': successorResponse.pca,
      },
    });

    if (!claimsResponse.ok) {
      const errorBody = await claimsResponse.json().catch(() => ({}));
      return {
        success: false,
        error: `Claims service returned ${claimsResponse.status}: ${JSON.stringify(errorBody)}`,
      };
    }

    const claimData = await claimsResponse.json();
    return { success: true, data: claimData };

  } catch (error) {
    if (error instanceof TrustPlaneApiError) {
      console.log(`[Agent] Trust Plane BLOCKED request: ${error.code} - ${error.message}`);
      if (error.code === 'MONOTONICITY_VIOLATION') {
        return {
          success: false,
          error: `BLOCKED: Cannot access claim "${claimId}" - exceeds authorized scope. ` +
                 `User only has access to their own claims.`,
        };
      }
      return { success: false, error: `Trust Plane error: ${error.message}` };
    }
    throw error;
  }
}

/**
 * Simulated "tool" to list claims
 *
 * This tool tries to list claims. If the agent tries to list ALL claims
 * but only has access to specific user's claims, the Trust Plane will
 * enforce monotonicity.
 */
async function toolListClaims(
  scope: 'own' | 'all',
  context: AgentContext
): Promise<{ success: boolean; data?: unknown; error?: string }> {
  console.log(`[Agent] Tool: list_claims(scope="${scope}")`);

  // Determine requested ops based on scope
  let requestedOps: string[];
  if (scope === 'all') {
    // Agent is trying to access ALL claims - this will fail for non-admin users
    requestedOps = ['read:claims:*'];
    console.log(`[Agent] WARNING: Attempting to access ALL claims`);
  } else {
    // Agent is trying to access only user's claims
    requestedOps = [`read:claims:${context.userId}/*`];
  }

  console.log(`[Agent] Requesting ops: ${requestedOps.join(', ')}`);

  try {
    // Create and sign PoC
    const signedPoc = await new PocBuilder(context.currentPca)
      .withOps(requestedOps)
      .withExecutor({
        service: 'ai-agent',
        tool: 'list_claims',
        scope,
      })
      .sign(agentKeyPair);

    // Request successor PCA from Trust Plane
    const successorResponse = await trustPlane.processPoc(signedPoc);
    console.log(`[Agent] Got successor PCA: hop=${successorResponse.hop}, ops=${successorResponse.ops.join(', ')}`);

    // Call claims service with successor PCA
    const claimsResponse = await fetch(`${CLAIMS_SERVICE_URL}/claims`, {
      headers: {
        'X-PIC-PCA': successorResponse.pca,
      },
    });

    if (!claimsResponse.ok) {
      const errorBody = await claimsResponse.json().catch(() => ({}));
      return {
        success: false,
        error: `Claims service returned ${claimsResponse.status}: ${JSON.stringify(errorBody)}`,
      };
    }

    const claimsData = await claimsResponse.json();
    return { success: true, data: claimsData };

  } catch (error) {
    if (error instanceof TrustPlaneApiError) {
      console.log(`[Agent] Trust Plane BLOCKED request: ${error.code} - ${error.message}`);
      if (error.code === 'MONOTONICITY_VIOLATION') {
        return {
          success: false,
          error: `BLOCKED: Cannot list ${scope === 'all' ? 'all' : ''} claims - ` +
                 `monotonicity violation. User only has access to their own claims. ` +
                 `This is a CONFUSED DEPUTY ATTACK - blocked by PIC!`,
        };
      }
      return { success: false, error: `Trust Plane error: ${error.message}` };
    }
    throw error;
  }
}

/**
 * Simulated AI agent processing
 *
 * In a real setup, this would use LangChain/OpenAI to process the question.
 * For this demo, we parse the question and call appropriate tools.
 */
async function processQuestion(
  question: string,
  context: AgentContext
): Promise<string> {
  const lowerQuestion = question.toLowerCase();

  console.log(`[Agent] Processing question: "${question}"`);
  console.log(`[Agent] User context: ${context.userId}`);

  // Pattern matching for demo purposes
  // In real agent, LLM would decide which tools to call

  // Check for "all claims" / "every claim" patterns (confused deputy attempt)
  if (
    lowerQuestion.includes('all claims') ||
    lowerQuestion.includes('every claim') ||
    lowerQuestion.includes('all the claims') ||
    lowerQuestion.includes("everyone's claims") ||
    lowerQuestion.includes('system claims')
  ) {
    console.log(`[Agent] Detected request for ALL claims - attempting confused deputy attack scenario`);
    const result = await toolListClaims('all', context);
    if (!result.success) {
      return `I tried to access all claims in the system, but the request was blocked:\n\n${result.error}\n\n` +
             `This is the PIC system protecting against confused deputy attacks. ` +
             `As ${context.userId}'s agent, I can only access ${context.userId}'s claims.`;
    }
    return `Here are all accessible claims:\n${JSON.stringify(result.data, null, 2)}`;
  }

  // Check for specific claim ID patterns
  const claimIdMatch = lowerQuestion.match(/claim\s+(?:#?\s*)?([a-z]+-\d+)/i) ||
                       lowerQuestion.match(/([a-z]+-\d+)/i);

  if (claimIdMatch) {
    const claimId = claimIdMatch[1].toLowerCase();
    console.log(`[Agent] Detected request for specific claim: ${claimId}`);
    const result = await toolGetClaim(claimId, context);

    if (!result.success) {
      return `I couldn't retrieve claim ${claimId}:\n\n${result.error}`;
    }

    const claim = (result.data as { claim: { status: string; amount: number; description: string } }).claim;
    return `Claim ${claimId} details:\n` +
           `- Status: ${claim.status}\n` +
           `- Amount: $${claim.amount}\n` +
           `- Description: ${claim.description}`;
  }

  // Default: list user's own claims
  if (
    lowerQuestion.includes('my claims') ||
    lowerQuestion.includes('my claim') ||
    lowerQuestion.includes('claims') ||
    lowerQuestion.includes('status')
  ) {
    console.log(`[Agent] Detected request for user's own claims`);
    const result = await toolListClaims('own', context);

    if (!result.success) {
      return `I couldn't retrieve your claims:\n\n${result.error}`;
    }

    const data = result.data as { claims: Array<{ id: string; status: string; amount: number }> };
    if (data.claims.length === 0) {
      return `You don't have any claims on file.`;
    }

    let response = `Here are your claims:\n\n`;
    for (const claim of data.claims) {
      response += `- ${claim.id}: ${claim.status} ($${claim.amount})\n`;
    }
    return response;
  }

  // Fallback
  return `I'm an insurance claims assistant. I can help you with:\n` +
         `- Checking the status of your claims\n` +
         `- Looking up specific claim details\n` +
         `- Listing all your claims\n\n` +
         `What would you like to know?`;
}

// =============================================================================
// Error Response
// =============================================================================

interface ErrorResponse {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

// =============================================================================
// Agent Server
// =============================================================================

const app = express();
app.use(express.json());

/**
 * POST /process
 *
 * Process a user question. Receives PCA from gateway in X-PIC-PCA header.
 */
app.post('/process', async (req, res) => {
  try {
    const { question, user_id } = req.body as { question: string; user_id: string };

    // Extract PCA from header
    const pcaHeader = req.headers['x-pic-pca'] as string | undefined;
    if (!pcaHeader) {
      return res.status(401).json({
        error: 'Missing authority',
        code: 'MISSING_PCA',
      } satisfies ErrorResponse);
    }

    console.log(`[Agent] Received request from user: ${user_id}`);

    // Create context for tool calls
    const context: AgentContext = {
      currentPca: pcaHeader,
      userId: user_id,
    };

    // Process the question
    const answer = await processQuestion(question, context);

    return res.json({
      answer,
      hop: 1, // We're at hop 1 (gateway is hop 0)
      ops: [], // Would include actual ops from processing
    });

  } catch (error) {
    console.error('[Agent] Error processing request:', error);
    return res.status(500).json({
      error: 'Agent processing failed',
      code: 'INTERNAL_ERROR',
    } satisfies ErrorResponse);
  }
});

/**
 * GET /health
 */
app.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    service: 'ai-agent-runtime',
    key_id: agentKeyPair?.kid ?? 'not initialized',
  });
});

// =============================================================================
// Initialization
// =============================================================================

async function initialize() {
  console.log('[Agent] Initializing AI Agent Runtime...');

  // Generate key pair for signing PoCs
  agentKeyPair = await generateKeyPair('ai-agent-key');
  console.log(`[Agent] Generated key pair: ${agentKeyPair.kid}`);

  // Register public key with Trust Plane
  console.log(`[Agent] Registering public key with Trust Plane at ${TRUST_PLANE_URL}`);
  try {
    await trustPlane.registerExecutorKey(agentKeyPair.kid, agentKeyPair.publicKey);
    console.log('[Agent] Successfully registered with Trust Plane');
  } catch (error) {
    console.error('[Agent] Failed to register with Trust Plane:', error);
    console.error('[Agent] Make sure the Trust Plane server is running');
    // Continue anyway - registration might already exist
  }

  // Start server
  app.listen(PORT, () => {
    console.log(`[Agent] AI Agent Runtime listening on port ${PORT}`);
    console.log(`[Agent] Trust Plane URL: ${TRUST_PLANE_URL}`);
    console.log(`[Agent] Claims Service URL: ${CLAIMS_SERVICE_URL}`);
  });
}

initialize().catch(console.error);
