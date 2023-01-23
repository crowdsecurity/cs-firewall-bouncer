//Package go-cs-bouncer implements a wrapper for the CrowdSec bouncer API.
//
//It can be used to create 2 types of bouncer:
//
// - A stream bouncer: in this mode, decisions are fetched in bulk at regular intervals. A `Stream` chan is exposed by the struct to allow you to read the decisions.
//
// - A live bouncer: in this mode, you must call the Get() method to check if an IP has a decision associated with it.
package csbouncer
