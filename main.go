package main

import (
	"fmt"
	"sync"
)

// Policy represents an ACL policy.
type Policy struct {
	ID          string
	Name        string
	Rules       string
	ModifyIndex uint64
}

// Token represents an ACL token.
type Token struct {
	AccessorID  string
	SecretID    string
	Policies    []string // Policy IDs
	ModifyIndex uint64
}

// Resolution represents the compiled rules/permissions for a token.
type Resolution struct {
	TokenID     string
	Rules       string
	ModifyIndex uint64
}

// ACLStore simulates the state store (like Consul's Raft state store).
type ACLStore struct {
	mu       sync.RWMutex
	policies map[string]*Policy // ID -> Policy
	tokens   map[string]*Token  // SecretID -> Token
	index    uint64
}

func NewACLStore() *ACLStore {
	return &ACLStore{
		policies: make(map[string]*Policy),
		tokens:   make(map[string]*Token),
	}
}

func (s *ACLStore) CreatePolicy(p *Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.index++
	p.ModifyIndex = s.index
	s.policies[p.ID] = p
}

func (s *ACLStore) UpdatePolicy(p *Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.index++
	p.ModifyIndex = s.index
	s.policies[p.ID] = p
}

func (s *ACLStore) DeletePolicy(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, id)
}

func (s *ACLStore) CreateToken(t *Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.index++
	t.ModifyIndex = s.index
	s.tokens[t.SecretID] = t
}

func (s *ACLStore) GetToken(secretID string) (*Token, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[secretID]
	return t, ok
}

func (s *ACLStore) GetPolicy(id string) (*Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	return p, ok
}

// TokenCache caches token resolutions and tracks policy dependencies.
type TokenCache struct {
	mu           sync.RWMutex
	store        *ACLStore
	cache        map[string]*Resolution // SecretID -> Resolution
	dependencies map[string]map[string]bool // PolicyID -> Set of SecretIDs
}

func NewTokenCache(store *ACLStore) *TokenCache {
	return &TokenCache{
		store:        store,
		cache:        make(map[string]*Resolution),
		dependencies: make(map[string]map[string]bool),
	}
}

// Resolve resolves a token, using the cache if available.
func (c *TokenCache) Resolve(secretID string) (*Resolution, error) {
	c.mu.RLock()
	if res, ok := c.cache[secretID]; ok {
		c.mu.RUnlock()
		return res, nil
	}
	c.mu.RUnlock()

	// Cache miss, resolve from store
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-checked locking
	if res, ok := c.cache[secretID]; ok {
		return res, nil
	}

	token, ok := c.store.GetToken(secretID)
	if !ok {
		return nil, fmt.Errorf("token not found")
	}

	// Compile rules from policies
	var compiledRules string
	for _, policyID := range token.Policies {
		policy, ok := c.store.GetPolicy(policyID)
		if ok {
			if compiledRules != "" {
				compiledRules += ";"
			}
			compiledRules += policy.Rules

			// Track dependency: this token depends on this policy
			if _, exists := c.dependencies[policyID]; !exists {
				c.dependencies[policyID] = make(map[string]bool)
			}
			c.dependencies[policyID][secretID] = true
		}
	}

	res := &Resolution{
		TokenID:     token.AccessorID,
		Rules:       compiledRules,
		ModifyIndex: token.ModifyIndex,
	}

	c.cache[secretID] = res
	return res, nil
}

// InvalidatePolicy invalidates all cached tokens that depend on the given policy ID.
func (c *TokenCache) InvalidatePolicy(policyID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	tokensToInvalidate, exists := c.dependencies[policyID]
	if !exists {
		return
	}

	for secretID := range tokensToInvalidate {
		delete(c.cache, secretID)
	}

	// Clear the dependency list for this policy
	delete(c.dependencies, policyID)
}

// UpdatePolicy updates a policy in the store and invalidates the cache.
func (c *TokenCache) UpdatePolicy(p *Policy) {
	c.store.UpdatePolicy(p)
	c.InvalidatePolicy(p.ID)
}

// DeletePolicy deletes a policy from the store and invalidates the cache.
func (c *TokenCache) DeletePolicy(policyID string) {
	c.store.DeletePolicy(policyID)
	c.InvalidatePolicy(policyID)
}

func main() {
	// Initialize store and cache
	store := NewACLStore()
	cache := NewTokenCache(store)

	// 1. Create a policy 'policy-a' allowing read access to 'key/foo'
	policyA := &Policy{
		ID:    "policy-a",
		Name:  "policy-a",
		Rules: "key:foo:read",
	}
	store.CreatePolicy(policyA)

	// 2. Create a token 'token-a' associated with 'policy-a'
	tokenA := &Token{
		AccessorID: "accessor-a",
		SecretID:   "secret-a",
		Policies:   []string{"policy-a"},
	}
	store.CreateToken(tokenA)

	// 3. Perform an API request using 'token-a' to read 'key/foo' (populating the cache)
	res, err := cache.Resolve("secret-a")
	if err != nil {
		panic(fmt.Sprintf("Error resolving token: %v", err))
	}
	fmt.Printf("Initial resolution rules: %s\n", res.Rules)
	if res.Rules != "key:foo:read" {
		panic(fmt.Sprintf("Expected rules to be 'key:foo:read', got '%s'", res.Rules))
	}

	// 4. Update 'policy-a' to deny read access to 'key/foo'
	policyA.Rules = "key:foo:deny"
	cache.UpdatePolicy(policyA)

	// 5. Immediately perform the same API request using 'token-a'. Assert that the request is denied.
	res, err = cache.Resolve("secret-a")
	if err != nil {
		panic(fmt.Sprintf("Error resolving token: %v", err))
	}
	fmt.Printf("Updated resolution rules: %s\n", res.Rules)
	if res.Rules != "key:foo:deny" {
		panic(fmt.Sprintf("Expected rules to be 'key:foo:deny', got '%s'", res.Rules))
	}

	// 6. Delete 'policy-a'
	cache.DeletePolicy("policy-a")

	// 7. Assert that the token's permissions are immediately downgraded/revoked.
	res, err = cache.Resolve("secret-a")
	if err != nil {
		panic(fmt.Sprintf("Error resolving token: %v", err))
	}
	fmt.Printf("After policy deletion resolution rules: %s\n", res.Rules)
	if res.Rules != "" {
		panic(fmt.Sprintf("Expected rules to be empty, got '%s'", res.Rules))
	}

	fmt.Println("All tests passed successfully!")
}