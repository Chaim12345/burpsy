package vulnapp

// The LLM prompt injection family (burpsy-react-ui-0vzb.18). There is no model here: each "LLM" is a
// deterministic function standing in for one, so the defect is the real mechanism — the vulnerable
// endpoints paste the user's text into a prompt and the stand-in follows the instructions it finds in
// that prompt, as a model does; the safe twins never treat the user's text as instructions.
//
// The stand-in model (fakeModel) follows two kinds of instruction anywhere in its prompt: "the sum of
// A and B ... followed (immediately) by the word W" (it writes A+B then W) and "the word W spelled
// backwards" (it writes W reversed), each at the start of its reply, and then answers the shop
// question it was asked. One stand-in cannot reverse words, as real models often cannot.
//
// Vulnerable:
//
//   - GET /llm/chat?prompt=... answers {"reply": "..."} from a model that follows both instructions;
//   - POST /llm/v1/chat/completions takes an OpenAI-style {"messages":[...]} body and streams the
//     answer as server-sent events, four characters per chunk, each chunk carrying id/model members
//     as real APIs do; this model follows the sum but cannot reverse a word, so only two of three
//     attempts hold;
//   - GET /helpdesk/reply?text=... answers an HTML page; neither the path nor the parameter name
//     says "model", only a natural-language question answered in prose.
//
// Safe twins and negative controls:
//
//   - /llm/safe/summary only summarises: it quotes the whole message (instruction, numbers and word
//     included) and counts its words, following nothing;
//   - /llm/safe/echo answers the message verbatim; /llm/safe/fixed answers the same text whatever it
//     is sent;
//   - /llm/safe/textutil is a text-utility bot that, for EVERY message, writes the sum of the numbers
//     in it followed by its last word, then the message reversed: it produces the evidence for the
//     probe and for its instruction-free control alike, so only the control comparison stops it;
//   - POST /llm/safe/v1/chat/completions streams the user's message back, chunked like the vulnerable
//     stream, so a reassembled stream must not read as an answer;
//   - GET /helpdesk/safe/reply quotes the question in a prose page and answers from a fixed text;
//   - POST /llm/safe/support/contact is the following model behind a POST whose path says it sends a
//     message to staff: the check must send it nothing.

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

const rowLLMPromptInjection = "LLM prompt injection"

// llmContact counts requests to the contact-form twin.
var llmContact atomic.Int64

// LLMContactRequests is how many requests the LLM contact-form twin has received.
func LLMContactRequests() int64 { return llmContact.Load() }

func llmEndpoints() []Endpoint {
	chatBody := `{"model":"shop-assistant","stream":true,"messages":[{"role":"system","content":"You are the shop's assistant."},` +
		`{"role":"user","content":"What can you help me with today?"}]}`
	return []Endpoint{
		{Path: "/llm/chat?prompt=What+are+your+opening+hours", Row: rowLLMPromptInjection,
			Note: "pastes prompt into a model's prompt; the stand-in model follows the sum and reverse instructions it finds"},
		{Path: "/llm/v1/chat/completions", Method: http.MethodPost, Row: rowLLMPromptInjection, Body: chatBody,
			ContentType: "application/json",
			Note:        "OpenAI-style chat streamed as server-sent events in 4-character chunks; follows the sum, cannot reverse"},
		{Path: "/helpdesk/reply?text=How+do+I+return+a+damaged+item", Row: rowLLMPromptInjection,
			Note: "a model answers the text parameter in an HTML page; only the natural-language exchange marks it"},

		{Path: "/llm/safe/summary?prompt=What+are+your+opening+hours", Row: rowLLMPromptInjection, Safe: true,
			Note: "summarises the message, quoting all of it, and follows no instruction in it"},
		{Path: "/llm/safe/echo?prompt=What+are+your+opening+hours", Row: rowLLMPromptInjection, Safe: true,
			Note: "answers the message verbatim"},
		{Path: "/llm/safe/fixed?prompt=What+are+your+opening+hours", Row: rowLLMPromptInjection, Safe: true,
			Note: "answers the same text whatever it is sent"},
		{Path: "/llm/safe/textutil?prompt=What+are+your+opening+hours", Row: rowLLMPromptInjection, Safe: true,
			Note: "writes the sum of the message's numbers and its last word, then the message reversed, for every message: " +
				"the instruction-free control produces the same text"},
		{Path: "/llm/safe/v1/chat/completions", Method: http.MethodPost, Row: rowLLMPromptInjection, Safe: true,
			Body: chatBody, ContentType: "application/json",
			Note: "streams the user's message back in 4-character server-sent-event chunks"},
		{Path: "/helpdesk/safe/reply?text=How+do+I+return+a+damaged+item", Row: rowLLMPromptInjection, Safe: true,
			Note: "quotes the question in a prose page and answers from a fixed text"},
		{Path: "/llm/safe/support/contact", Method: http.MethodPost, Row: rowLLMPromptInjection, Safe: true,
			Body: "question=Where+is+my+parcel", ContentType: "application/x-www-form-urlencoded",
			Note: "the following model behind a POST that messages staff: the check must send it nothing"},
	}
}

var (
	llmSumInstr  = regexp.MustCompile(`(?i)sum of (\d+) and (\d+)`)
	llmWordAfter = regexp.MustCompile(`(?i)followed (?:immediately )?by the word ([A-Za-z]+)`)
	llmRevInstr  = regexp.MustCompile(`(?i)the word ([A-Za-z]+) spelled backwards`)
	llmNumber    = regexp.MustCompile(`\d+`)
	llmWords     = regexp.MustCompile(`[A-Za-z]+`)
)

// fakeModel stands in for a model given prompt: it follows the instructions it recognises, then
// answers the question.
func fakeModel(prompt string, canReverse bool) string {
	var lead strings.Builder
	if m := llmSumInstr.FindStringSubmatch(prompt); m != nil {
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		lead.WriteString(strconv.Itoa(a + b))
		if w := llmWordAfter.FindStringSubmatch(prompt); w != nil {
			lead.WriteString(w[1])
		}
		lead.WriteString(" ")
	}
	if m := llmRevInstr.FindStringSubmatch(prompt); m != nil && canReverse {
		lead.WriteString(llmReverse(m[1]) + " ")
	}
	return lead.String() + "Thanks for asking! Our shop is open from nine to five on weekdays, and our " +
		"assistant can help you track an order, arrange a return or choose a product."
}

func llmReverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// llmPrompt is what a vulnerable endpoint hands its model: its own instructions with the user's text
// pasted in.
func llmPrompt(user string) string {
	return "You are the shop's helpful assistant. Answer the customer's question politely.\n\nCustomer: " + user
}

// llmLastUser is the last user message of an OpenAI-style chat body.
func llmLastUser(r *http.Request) string {
	var body struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body) != nil {
		return ""
	}
	last := ""
	for _, m := range body.Messages {
		if m.Role == "user" {
			last = m.Content
		}
	}
	return last
}

// llmSSE streams text as OpenAI-style chat-completion chunks of four characters.
func llmSSE(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	chunk := func(delta map[string]string) {
		b, _ := json.Marshal(map[string]any{
			"id": "chatcmpl-7", "object": "chat.completion.chunk", "model": "shop-assistant",
			"choices": []map[string]any{{"index": 0, "delta": delta}},
		})
		fmt.Fprintf(w, "data: %s\n\n", b)
	}
	chunk(map[string]string{"role": "assistant"})
	r := []rune(text)
	for i := 0; i < len(r); i += 4 {
		chunk(map[string]string{"content": string(r[i:min(i+4, len(r))])})
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
}

func llmJSON(w http.ResponseWriter, reply string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"reply": reply})
}

func llmHelpdeskPage(w http.ResponseWriter, question, answer string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><head><title>Helpdesk</title></head><body><h1>Helpdesk</h1>"+
		"<p class=\"q\">You asked: %s</p><p class=\"a\">%s</p></body></html>",
		html.EscapeString(question), html.EscapeString(answer))
}

func registerLLM(mux *http.ServeMux) {
	mux.HandleFunc("/llm/chat", func(w http.ResponseWriter, r *http.Request) {
		llmJSON(w, fakeModel(llmPrompt(r.FormValue("prompt")), true))
	})
	mux.HandleFunc("/llm/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST a chat body", http.StatusMethodNotAllowed)
			return
		}
		llmSSE(w, fakeModel(llmPrompt(llmLastUser(r)), false))
	})
	mux.HandleFunc("/helpdesk/reply", func(w http.ResponseWriter, r *http.Request) {
		q := r.FormValue("text")
		llmHelpdeskPage(w, q, fakeModel(llmPrompt(q), true))
	})

	mux.HandleFunc("/llm/safe/summary", func(w http.ResponseWriter, r *http.Request) {
		q := r.FormValue("prompt")
		ws := llmWords.FindAllString(q, -1)
		longest := ""
		for _, x := range ws {
			if len(x) > len(longest) {
				longest = x
			}
		}
		llmJSON(w, fmt.Sprintf("Summary: the customer wrote %d words, mostly about %q. Their message was: %q. "+
			"A member of staff will read it and reply by the end of the day.", len(ws), longest, q))
	})
	mux.HandleFunc("/llm/safe/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, r.FormValue("prompt"))
	})
	mux.HandleFunc("/llm/safe/fixed", func(w http.ResponseWriter, r *http.Request) {
		llmJSON(w, "Thanks for asking! Our shop is open from nine to five on weekdays, and our assistant "+
			"can help you track an order, arrange a return or choose a product.")
	})
	mux.HandleFunc("/llm/safe/textutil", func(w http.ResponseWriter, r *http.Request) {
		q := r.FormValue("prompt")
		sum := 0
		for _, n := range llmNumber.FindAllString(q, -1) {
			v, _ := strconv.Atoi(n)
			sum += v
		}
		ws := llmWords.FindAllString(q, -1)
		last := ""
		if len(ws) > 0 {
			last = ws[len(ws)-1]
		}
		llmJSON(w, fmt.Sprintf("Numbers total: %d%s. Your text backwards reads: %s", sum, last, llmReverse(q)))
	})
	mux.HandleFunc("/llm/safe/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST a chat body", http.StatusMethodNotAllowed)
			return
		}
		llmSSE(w, "You said: "+llmLastUser(r))
	})
	mux.HandleFunc("/helpdesk/safe/reply", func(w http.ResponseWriter, r *http.Request) {
		llmHelpdeskPage(w, r.FormValue("text"), "Thanks for getting in touch. Returns are free within thirty "+
			"days: print the label from your account page and drop the parcel at any post office.")
	})
	mux.HandleFunc("/llm/safe/support/contact", func(w http.ResponseWriter, r *http.Request) {
		llmContact.Add(1)
		llmJSON(w, fakeModel(llmPrompt(r.FormValue("question")), true))
	})
}
