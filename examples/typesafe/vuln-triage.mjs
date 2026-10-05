// Example: use TypeSafe's Jev model to triage a code snippet during a coding/review task.
// Setup:
//   cd examples/typesafe && npm install
//   npm start   (reads TYPESAFE_API_KEY from ../../.env via node --env-file)

import { choice, noul, TypeSafeClient } from "@typesafe-ai/sdk";

const client = new TypeSafeClient();

const snippet = `
func handleSearch(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	query := "SELECT * FROM findings WHERE title LIKE '%" + term + "%'"
	rows, err := db.Query(query)
	...
}
`;

const { answers } = await client.systemOne({
  state: { code: snippet, language: "go" },
  questions: {
    sqlInjection: noul("Does this code build a SQL query by concatenating unsanitized user input?"),
    category: choice("What is the primary vulnerability category here, if any?", {
      sql_injection: null,
      command_injection: null,
      none: null,
    }),
  },
});

console.log("SQL injection suspected:", answers.sqlInjection.noul);
console.log("Category:", answers.category.choice);
