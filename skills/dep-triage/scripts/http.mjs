// HTTP helper shared by the OSV.dev and Node.js clients.

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * One request, retried once on a network error, a 429 or a 5xx.
 * @returns the last response (which may still be an error status); throws the last network error
 */
export async function request(url, init, { fetchFn, retryDelayMs, timeoutMs }) {
  for (let attempt = 1; ; attempt++) {
    let response;
    let networkError;
    try {
      response = await fetchFn(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    } catch (error) {
      networkError = error;
    }
    const retryable = networkError !== undefined || response.status === 429 || response.status >= 500;
    if (!retryable || attempt === 2) {
      if (networkError !== undefined) throw networkError;
      return response;
    }
    await sleep(retryDelayMs);
  }
}
