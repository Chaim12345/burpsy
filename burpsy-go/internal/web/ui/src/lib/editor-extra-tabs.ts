// Which of the message editor's operator-added tabs a message gets (burpsy-react-ui-11r8).
//
// Burp's rule has two halves, and burpsy used to implement only the first:
//
//   - In a read-only context the editor shows only the views the message can fill. A history
//     row with no cookies has no Cookies tab; a tab that is empty on every message but a few
//     teaches an operator to ignore the strip.
//   - "In editable contexts, such as in Burp Repeater, the message editor displays all views.
//     This gives you the option to add items even if none were included"
//     (desktop/settings/ui/message-editor.html). A Repeater request with no Cookie header is
//     exactly the request an operator wants to give one, and hiding the Cookies tab until a
//     cookie exists made the tab unreachable at the one moment it was needed.
//
// The request-only views (Query params, Body params, Cookies on a request) are the ones that
// change. A response is never offered them on the strength of being editable: Intercept can
// edit a held response, and a response has no query string to add a parameter to.
import {
 addBodyParam,
 addHeader,
 bodyParamSpans,
 cookieSpans,
 cookiesOf,
 headerValue,
 isResponse,
 parseMessage,
 querySpans,
} from "./message";
import type { OptionalEditorTab } from "./store";

/** The extra tabs a message gets, in their default strip order. */
export function extraEditorTabs(value: string, editable: boolean): OptionalEditorTab[] {
 const tabs: OptionalEditorTab[] = ["headers", "attributes"];
 const response = isResponse(value);
 // Every view, so an item can be added where none exists yet — on a request only.
 const offerAll = editable && !response;
 if (offerAll || querySpans(value).length > 0) tabs.push("queryparams");
 if (offerAll || bodyParamSpans(value).length > 0) tabs.push("bodyparams");
 const cookies = response ? cookiesOf(parseMessage(value).headers, true).length : cookieSpans(value).length;
 if (offerAll || cookies > 0) tabs.push("cookies");
 return tabs;
}

/**
 * Add a body parameter to a request, giving a body that has no type yet the form type first.
 * A GET with no body has no Content-Type, and addBodyParam alone would write `a=1` into a body
 * nothing declares — a server reads that as opaque bytes. Burp's body-parameter add on such a
 * request makes it a urlencoded form, which is what this does; a body that already declares a
 * type keeps it (and an unwritable one never reaches here — see BodyParamsTab).
 */
export function addBodyParamToRequest(raw: string, name: string, value: string): string {
 const declared = headerValue(parseMessage(raw).headers, "content-type");
 const typed = declared === undefined ? addHeader(raw, "Content-Type", "application/x-www-form-urlencoded") : raw;
 return addBodyParam(typed, name, value);
}
