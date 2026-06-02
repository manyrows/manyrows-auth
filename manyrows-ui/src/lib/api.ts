import axios from "axios";

import { extractApiError } from "./apiError.ts";

// apiJson is the shared admin-API client: a thin wrapper over axios that
// sends the session cookie, never throws on HTTP status by itself (we inspect
// res.status), maps 204/205 to null, and on any failure throws an Error whose
// message comes from the shared extractApiError. Previously this was
// copy-pasted into Webhooks/ConfigKeys/Features/AppDiff.
export async function apiJson<T>(
  path: string,
  init?: {
    method?: string;
    data?: unknown;
    params?: Record<string, unknown>;
    headers?: Record<string, string>;
  },
): Promise<T> {
  try {
    const res = await axios.request({
      url: path,
      method: init?.method || "GET",
      data: init?.data,
      params: init?.params,
      headers: init?.headers,
      withCredentials: true,
      validateStatus: () => true,
    });

    if (res.status < 200 || res.status >= 300) {
      // Synthesize an AxiosError-shaped object so extractApiError can pick
      // out the body's message/error/issues fields uniformly.
      throw Object.assign(new Error(res.statusText || "Request failed"), {
        isAxiosError: true,
        response: res,
      });
    }

    if (res.status === 204 || res.status === 205) {
      return null as unknown as T;
    }

    return (res.data ?? null) as T;
  } catch (e) {
    throw new Error(extractApiError(e));
  }
}
