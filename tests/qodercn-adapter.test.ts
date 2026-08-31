import { describe, expect, test } from "bun:test";
import {
  createQoderCnAdapter,
  validateQoderGatewayUrl,
  QoderDestinationSecurityError,
  ALLOWED_QODER_GATEWAY_ORIGIN,
  messagesToQoderFormat,
  normalizeToolArguments,
} from "../src/adapters/qodercn";
import type { OcxParsedRequest, OcxProviderConfig } from "../src/types";

const provider: OcxProviderConfig = {
  adapter: "qodercn",
  baseUrl: ALLOWED_QODER_GATEWAY_ORIGIN,
  apiKey: "test_qoder_token",
  accountId: "test-account-123",
  machineId: "test-machine-456",
  modelMap: {
    "GLM-5.3-Flash": "gfmodel",
  },
};

const parsed: OcxParsedRequest = {
  modelId: "GLM-5.3-Flash",
  context: {
    systemPrompt: ["You are a test assistant."],
    messages: [
      { role: "user", content: "Hello Qoder" },
      {
        role: "assistant",
        content: [
          { type: "text", text: "I can help with tools." },
          { type: "toolCall", id: "call_123", name: "calculator", arguments: { a: 1 } },
        ],
      },
      { role: "tool", toolCallId: "call_123", content: "Result: 2" } as any,
    ],
  },
  stream: false,
  options: {},
};

describe("Qoder CN Adapter Trust Boundaries & Protocol", () => {
  test("factory produces valid adapter structure", () => {
    const adapter = createQoderCnAdapter(provider);
    expect(adapter.name).toBe("qodercn");
    expect(typeof adapter.runTurn).toBe("function");
    expect(typeof adapter.buildRequest).toBe("function");
    expect(typeof adapter.parseStream).toBe("function");
  });

  test("security: gateway origin allowlist permits official domain", () => {
    const url = "https://gateway.qoder.com.cn/algo/api/v2/service/pro/sse/agent_chat_generation?foo=bar";
    expect(validateQoderGatewayUrl(url)).toBe(url);
  });

  test("security: gateway origin rejects untrusted destinations", () => {
    expect(() => validateQoderGatewayUrl("https://malicious.com/api")).toThrow(QoderDestinationSecurityError);
    expect(() => validateQoderGatewayUrl("http://gateway.qoder.com.cn/api")).toThrow(QoderDestinationSecurityError);
    expect(() => validateQoderGatewayUrl("https://fake.gateway.qoder.com.cn.attacker.org")).toThrow(QoderDestinationSecurityError);
  });

  test("security: missing credential fails closed", async () => {
    const keylessProvider: OcxProviderConfig = {
      adapter: "qodercn",
      baseUrl: ALLOWED_QODER_GATEWAY_ORIGIN,
    };
    const adapter = createQoderCnAdapter(keylessProvider);
    const events: any[] = [];

    if (adapter.runTurn) {
      await adapter.runTurn(parsed, { headers: new Headers() } as any, (e: any) => { events.push(e); });
    }

    expect(events.length).toBe(1);
    expect(events[0].type).toBe("error");
    expect(events[0].message).toContain("credential missing");
  });

  test("message serializer maps system, user, assistant tool_calls, and tool results", () => {
    const formatted = messagesToQoderFormat(parsed);
    expect(formatted.length).toBe(4);
    expect(formatted[0]).toEqual({ role: "system", content: "You are a test assistant." });
    expect(formatted[1]).toEqual({ role: "user", content: "Hello Qoder" });
    expect(formatted[2]).toMatchObject({
      role: "assistant",
      content: "I can help with tools.",
      tool_calls: [{ id: "call_123", type: "function", function: { name: "calculator", arguments: JSON.stringify({ a: 1 }) } }],
    });
    expect(formatted[3]).toMatchObject({
      role: "tool",
      tool_call_id: "call_123",
      content: "Result: 2",
    });
  });

  test("pre-aborted runTurn emits error", async () => {
    const adapter = createQoderCnAdapter(provider);
    const events: any[] = [];
    const abortCtrl = new AbortController();
    abortCtrl.abort();

    if (adapter.runTurn) {
      await adapter.runTurn(parsed, { headers: new Headers(), abortSignal: abortCtrl.signal } as any, (e: any) => { events.push(e); });
    }

    expect(events.length).toBe(1);
    expect(events[0].type).toBe("error");
    expect(events[0].message).toContain("aborted");
  });

  test("normalizeToolArguments unwraps envelope objects and coerces booleans", () => {
    const input1 = JSON.stringify({ parameters: { title: "Test Title", question: "Is this working?" } });
    const res1 = JSON.parse(normalizeToolArguments(input1));
    expect(res1).toEqual({ title: "Test Title", question: "Is this working?" });

    const input2 = JSON.stringify({ show_details: "true", nested: { flag: "false" } });
    const res2 = JSON.parse(normalizeToolArguments(input2));
    expect(res2).toEqual({ show_details: true, nested: { flag: false } });

    const input3 = JSON.stringify({ code: "print(1)", description: "Test run" });
    const res3 = JSON.parse(normalizeToolArguments(input3, "executeCode"));
    expect(res3).toEqual({ code: "print(1)", description: "Test run", intent: "Test run", capturePlot: false });
  });
});
