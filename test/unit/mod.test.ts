import { assertEquals, assertStringIncludes } from 'https://deno.land/std@0.208.0/assert/mod.ts';
import { tools } from '../../mod.ts';
import type { PluginContext, ToolContext } from '../../types.ts';

// Mock PluginContext
const mockContext: PluginContext & ToolContext = {
  pluginId: 'cortex-plugin-secret-rotation',
  pluginDir: '/tmp/plugins/cortex-plugin-secret-rotation',
  state: {
    get: async () => null,
    set: async () => {},
    delete: async () => {},
    list: async () => ({}),
  },
  config: {
    get: async () => null,
    set: async () => {},
    getAll: async () => ({}),
  },
  logger: {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
  },
  host: {
    registerTool: () => {},
    unregisterTool: () => {},
  },
  sessionId: 'test-session',
  workingDir: '/tmp',
  agentId: 'test-agent',
  workspaceDir: '/tmp',
};

function findTool(name: string) {
  const tool = tools.find((t) => t.definition.name === name);
  if (!tool) throw new Error(`Tool "${name}" not found`);
  return tool;
}

Deno.test('tools array — exports all tools', () => {
  assertEquals(tools.length, 5);
  assertEquals(tools[0].definition.name, 'secrets_scan');
  assertEquals(tools[1].definition.name, 'secrets_rotate');
  assertEquals(tools[2].definition.name, 'secrets_audit_trail');
  assertEquals(tools[3].definition.name, 'secrets_update_vault');
  assertEquals(tools[4].definition.name, 'secrets_generate');
});

Deno.test('secrets_scan — rejects empty target_path', async () => {
  const tool = findTool('secrets_scan');
  const result = await tool.execute({ 'target_path': '' }, mockContext);
  assertEquals(result.success, false);
  assertStringIncludes(result.error ?? '', 'non-empty string');
});

Deno.test('secrets_rotate — rejects empty secret_type', async () => {
  const tool = findTool('secrets_rotate');
  const result = await tool.execute({ 'secret_type': '' }, mockContext);
  assertEquals(result.success, false);
  assertStringIncludes(result.error ?? '', 'non-empty string');
});

Deno.test('secrets_audit_trail — tool is defined with name and description', () => {
  const tool = findTool('secrets_audit_trail');
  assertEquals(typeof tool.definition.description, 'string');
  assertEquals(tool.definition.description.length > 0, true);
});

Deno.test('secrets_update_vault — rejects empty key', async () => {
  const tool = findTool('secrets_update_vault');
  const result = await tool.execute({ 'key': '' }, mockContext);
  assertEquals(result.success, false);
  assertStringIncludes(result.error ?? '', 'non-empty string');
});

Deno.test('secrets_generate — tool is defined with name and description', () => {
  const tool = findTool('secrets_generate');
  assertEquals(typeof tool.definition.description, 'string');
  assertEquals(tool.definition.description.length > 0, true);
});

Deno.test('all tools return durationMs', async () => {
  for (const tool of tools) {
    const args: Record<string, unknown> = {};
    const result = await tool.execute(args, mockContext);
    assertEquals(typeof result.durationMs, 'number');
    assertEquals(result.durationMs >= 0, true);
  }
});
