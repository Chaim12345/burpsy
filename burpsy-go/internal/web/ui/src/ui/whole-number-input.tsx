/**
 * A numeric setting field (burpsy-react-ui-vlrh.1). The Network section patched its draft with
 * Number(event.target.value), so clearing a field to retype it saved 0 — a zero timeout. This keeps
 * what is typed as text and tells the caller only about whole numbers at or above `min`; a blank or
 * half-typed field is flagged invalid and the last good value stays in the draft.
 */
import { type ComponentProps, useEffect, useState } from "react";
import { wholeNumber } from "../lib/form-schemas";
import { Input } from "./primitives";

type InputProps = ComponentProps<typeof Input>;
type Props = (InputProps extends infer P ? (P extends unknown ? Omit<P, "value" | "onChange" | "type" | "min"> : never) : never) & {
 value: number;
 min: number;
 onCommit: (value: number) => void;
};

export function WholeNumberInput({ value, min, onCommit, ...rest }: Props): JSX.Element {
 const [text, setText] = useState(String(value));
 const [committed, setCommitted] = useState(value);
 // The value moved without us (Revert, a refetch): show it, replacing whatever was half typed.
 useEffect(() => {
  if (value !== committed) {
   setText(String(value));
   setCommitted(value);
  }
 }, [value, committed]);

 const parsed = wholeNumber("whole number").safeParse(text);
 const valid = parsed.success && parsed.data >= min;

 return (
  <Input
   {...(rest as InputProps)}
   type="number"
   min={min}
   value={text}
   aria-invalid={valid ? undefined : true}
   onChange={(event) => {
    const next = event.target.value;
    setText(next);
    const check = wholeNumber("whole number").safeParse(next);
    if (check.success && check.data >= min) {
     setCommitted(check.data);
     onCommit(check.data);
    }
   }}
  />
 );
}
