import _ from "lodash";

const GREETING = "Hello <%= data.name %>!";

// The `variable` option comes straight from the request: this is the exposed call.
export function renderGreeting(req) {
  return _.template(GREETING, { variable: req.query.variable })({ name: req.query.name });
}
