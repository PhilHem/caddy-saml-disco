//go:build unit

package cache

import (
	"sync"
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

func TestNewBoundedCache_PanicsOnZeroCapacity(t *testing.T) {
	tra.RequireLegacy(t)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for capacity 0")
		}
	}()
	NewBoundedCache[string, int](0)
}

func TestNewBoundedCache_PanicsOnNegativeCapacity(t *testing.T) {
	tra.RequireLegacy(t)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for capacity -1")
		}
	}()
	NewBoundedCache[string, int](-1)
}

func TestBoundedCache_GetSet_Roundtrip(t *testing.T) {
	tra.RequireLegacy(t)

	c := NewBoundedCache[string, int](10)
	c.Set("a", 1)

	v, ok := c.Get("a")
	if !ok {
		t.Fatal("expected key 'a' to be present")
	}
	if v != 1 {
		t.Fatalf("expected 1, got %d", v)
	}
}

func TestBoundedCache_Get_MissingKey(t *testing.T) {
	tra.RequireLegacy(t)

	c := NewBoundedCache[string, int](10)
	_, ok := c.Get("missing")
	if ok {
		t.Fatal("expected false for missing key")
	}
}

func TestBoundedCache_LRUEviction(t *testing.T) {
	tra.RequireLegacy(t)

	c := NewBoundedCache[int, int](3)
	c.Set(1, 10)
	c.Set(2, 20)
	c.Set(3, 30)

	// Insert capacity+1; key 1 is LRU and should be evicted.
	c.Set(4, 40)

	if c.Len() != 3 {
		t.Fatalf("expected len 3, got %d", c.Len())
	}

	if _, ok := c.Get(1); ok {
		t.Fatal("key 1 should have been evicted")
	}
	for _, k := range []int{2, 3, 4} {
		if _, ok := c.Get(k); !ok {
			t.Fatalf("key %d should still be present", k)
		}
	}
}

func TestBoundedCache_Get_PromotesPreventsEviction(t *testing.T) {
	tra.RequireLegacy(t)

	c := NewBoundedCache[int, int](3)
	c.Set(1, 10)
	c.Set(2, 20)
	c.Set(3, 30)

	// Access key 1 to promote it to MRU; now key 2 is LRU.
	c.Get(1)

	c.Set(4, 40) // should evict key 2

	if _, ok := c.Get(2); ok {
		t.Fatal("key 2 should have been evicted (was LRU after promotion of key 1)")
	}
	if _, ok := c.Get(1); !ok {
		t.Fatal("key 1 should still be present (was promoted)")
	}
}

func TestBoundedCache_Set_UpdateExistingNoEviction(t *testing.T) {
	tra.RequireLegacy(t)

	c := NewBoundedCache[string, int](3)
	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)

	// Update existing key — must not evict anything.
	c.Set("a", 99)

	if c.Len() != 3 {
		t.Fatalf("expected len 3 after update, got %d", c.Len())
	}

	v, ok := c.Get("a")
	if !ok || v != 99 {
		t.Fatalf("expected updated value 99, got %d (ok=%v)", v, ok)
	}
}

func TestBoundedCache_Delete(t *testing.T) {
	tra.RequireLegacy(t)

	c := NewBoundedCache[string, string](5)
	c.Set("x", "hello")
	c.Delete("x")

	if _, ok := c.Get("x"); ok {
		t.Fatal("key 'x' should have been deleted")
	}
	if c.Len() != 0 {
		t.Fatalf("expected len 0 after delete, got %d", c.Len())
	}
}

func TestBoundedCache_Delete_NoOp(t *testing.T) {
	tra.RequireLegacy(t)

	c := NewBoundedCache[string, string](5)
	// Should not panic on missing key.
	c.Delete("nonexistent")
}

func TestBoundedCache_Len(t *testing.T) {
	tra.RequireLegacy(t)

	c := NewBoundedCache[int, int](5)
	if c.Len() != 0 {
		t.Fatalf("expected len 0 initially, got %d", c.Len())
	}

	c.Set(1, 1)
	c.Set(2, 2)
	if c.Len() != 2 {
		t.Fatalf("expected len 2, got %d", c.Len())
	}

	c.Delete(1)
	if c.Len() != 1 {
		t.Fatalf("expected len 1 after delete, got %d", c.Len())
	}
}

func TestBoundedCache_ThreadSafety(t *testing.T) {
	tra.RequireLegacy(t)

	const (
		goroutines = 20
		iterations = 500
		capacity   = 10
	)

	c := NewBoundedCache[int, int](capacity)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := (g*iterations + i) % (capacity * 3)
				c.Set(key, key*2)
				c.Get(key)
				if i%10 == 0 {
					c.Delete(key)
				}
				c.Len()
			}
		}()
	}
	wg.Wait()

	if c.Len() > capacity {
		t.Fatalf("cache exceeded capacity: len=%d capacity=%d", c.Len(), capacity)
	}
}
