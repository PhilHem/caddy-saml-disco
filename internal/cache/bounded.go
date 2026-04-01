// Package cache provides generic bounded cache implementations.
package cache

import (
	"container/list"
	"sync"
)

// BoundedCache is a thread-safe LRU cache with a fixed capacity.
// Unbounded growth is unrepresentable: a positive capacity must be
// supplied at construction time via NewBoundedCache.
type BoundedCache[K comparable, V any] struct {
	capacity int
	items    map[K]*list.Element
	order    *list.List // front = most-recently-used, back = least-recently-used
	mu       sync.RWMutex
}

// entry is the value stored inside each list element.
type entry[K comparable, V any] struct {
	key   K
	value V
}

// NewBoundedCache returns a new BoundedCache with the given capacity.
// It panics if capacity is <= 0.
func NewBoundedCache[K comparable, V any](capacity int) *BoundedCache[K, V] {
	if capacity <= 0 {
		panic("cache: capacity must be > 0")
	}
	return &BoundedCache[K, V]{
		capacity: capacity,
		items:    make(map[K]*list.Element, capacity),
		order:    list.New(),
	}
}

// Get returns the value for key and true if found, or the zero value and
// false if not. A successful lookup promotes the entry to most-recently-used.
func (c *BoundedCache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}

	c.order.MoveToFront(el)
	return el.Value.(*entry[K, V]).value, true
}

// Set adds or updates the entry for key. If the cache is at capacity and key
// is not already present, the least-recently-used entry is evicted first.
func (c *BoundedCache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		// Update existing entry and promote to MRU.
		el.Value.(*entry[K, V]).value = value
		c.order.MoveToFront(el)
		return
	}

	// Evict LRU if at capacity.
	if len(c.items) >= c.capacity {
		lru := c.order.Back()
		if lru != nil {
			c.order.Remove(lru)
			delete(c.items, lru.Value.(*entry[K, V]).key)
		}
	}

	el := c.order.PushFront(&entry[K, V]{key: key, value: value})
	c.items[key] = el
}

// Delete removes the entry for key. It is a no-op if key is not present.
func (c *BoundedCache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}

// Len returns the number of entries currently in the cache.
func (c *BoundedCache[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}
