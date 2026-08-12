// 00 Components / error-notice / default
// design node 0:840 — exported by scripts/export-design-jsx.ts, do not hand-edit
<Component name="00 Components / error-notice / default" x={2000} y={700} flex="row" w={362} h={56} gap={10} items="center" py={10} px={12} bg="#474747">
  <Rectangle name="error-notice-accent" w={3} h={36} bg="#FF9B98" />
  <Text name="error-icon" w={16} lineHeight={17} color="#FF9B98">⚠</Text>
  <Frame name="error-text-col" flex="col" w={260} grow={1} gap={3}>
    <Text name="error-title" w={260} size={12} weight="bold" lineHeight={15} color="#BBBBBB">Could not reach the target</Text>
    <Text name="error-detail" w={260} size={11} lineHeight={14} color="#B2B2B2">connection refused (127.0.0.1:8443)</Text>
  </Frame>
  <Text name="error-retry" w={29} size={11} weight="bold" lineHeight={14} color="#FF7A4D">Retry</Text>
</Component>
