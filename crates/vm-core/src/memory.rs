// CVM Core — Heap Memory Manager

use crate::error::{VmError, VmResult};
use std::collections::HashMap;

const DEFAULT_MEMORY_QUOTA: usize = 16 * 1024 * 1024; // 16 MB

/// Arena-based heap memory manager with allocation tracking.
pub struct Memory {
    /// Allocated blocks: address → data
    blocks: HashMap<u32, Vec<u8>>,
    /// Next allocation address
    next_addr: u32,
    /// Total bytes currently allocated
    used: usize,
    /// Maximum allowed allocation
    quota: usize,
}

impl Memory {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            next_addr: 0x1000, // Start at 4KB to avoid null-ish addresses
            used: 0,
            quota: DEFAULT_MEMORY_QUOTA,
        }
    }

    pub fn with_quota(quota: usize) -> Self {
        Self { quota, ..Self::new() }
    }

    /// Allocate `size` bytes, returns the base address.
    pub fn alloc(&mut self, size: usize) -> VmResult<u32> {
        if size == 0 {
            return Err(VmError::OutOfBounds { address: 0, size: 0 });
        }
        if self.used + size > self.quota {
            return Err(VmError::MemoryQuotaExceeded {
                requested: size, used: self.used, quota: self.quota,
            });
        }
        let addr = self.next_addr;
        self.next_addr = self.next_addr.checked_add(size as u32 + 16)
            .ok_or(VmError::OutOfBounds { address: self.next_addr, size })?;
        self.blocks.insert(addr, vec![0u8; size]);
        self.used += size;
        Ok(addr)
    }

    /// Free a previously allocated block.
    pub fn free(&mut self, addr: u32) -> VmResult<()> {
        match self.blocks.remove(&addr) {
            Some(block) => { self.used -= block.len(); Ok(()) }
            None => Err(VmError::OutOfBounds { address: addr, size: 0 }),
        }
    }

    /// Load `len` bytes starting at `addr`.
    pub fn load(&self, addr: u32, len: usize) -> VmResult<Vec<u8>> {
        let block = self.blocks.get(&addr)
            .ok_or(VmError::OutOfBounds { address: addr, size: len })?;
        if len > block.len() {
            return Err(VmError::OutOfBounds { address: addr, size: len });
        }
        Ok(block[..len].to_vec())
    }

    /// Store `data` at `addr`.
    pub fn store(&mut self, addr: u32, data: &[u8]) -> VmResult<()> {
        let block = self.blocks.get_mut(&addr)
            .ok_or(VmError::OutOfBounds { address: addr, size: data.len() })?;
        if data.len() > block.len() {
            return Err(VmError::OutOfBounds { address: addr, size: data.len() });
        }
        block[..data.len()].copy_from_slice(data);
        Ok(())
    }

    pub fn used(&self) -> usize { self.used }
    pub fn quota(&self) -> usize { self.quota }
    pub fn block_count(&self) -> usize { self.blocks.len() }

    pub fn clear(&mut self) {
        self.blocks.clear();
        self.used = 0;
        self.next_addr = 0x1000;
    }
}

impl Default for Memory {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_store_load() {
        let mut mem = Memory::new();
        let addr = mem.alloc(10).unwrap();
        mem.store(addr, &[1, 2, 3, 4, 5]).unwrap();
        let data = mem.load(addr, 5).unwrap();
        assert_eq!(data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_free() {
        let mut mem = Memory::new();
        let addr = mem.alloc(100).unwrap();
        assert_eq!(mem.used(), 100);
        mem.free(addr).unwrap();
        assert_eq!(mem.used(), 0);
        assert!(mem.free(addr).is_err()); // Double free
    }

    #[test]
    fn test_quota() {
        let mut mem = Memory::with_quota(100);
        mem.alloc(50).unwrap();
        mem.alloc(50).unwrap();
        assert!(mem.alloc(1).is_err());
    }
}
