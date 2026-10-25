import { zodResolver } from "@hookform/resolvers/zod";
import { type DefaultValues, type FieldValues, type UseFormReturn, useForm } from "react-hook-form";
import type { z } from "zod";

/**
 * A react-hook-form whose fields are text and whose submit value is the schema's output
 * (lib/form-schemas.ts). Validates as the operator types, so a button can say what is missing.
 */
export function useZodForm<Input extends FieldValues, Output>(
  schema: z.ZodType<Output, Input>,
  defaultValues: DefaultValues<Input>,
  /** Server-saved values: fields reset to them when they change, except ones the operator edited. */
  values?: Input,
): UseFormReturn<Input, unknown, Output> {
  return useForm<Input, unknown, Output>({
    // zod 4's input/output generics are wider than the resolver's; the schema is what is checked.
    resolver: zodResolver(schema as never) as never,
    defaultValues,
    values,
    resetOptions: { keepDirtyValues: true },
    mode: "onChange",
  });
}
